/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
import "C"

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

type tunnelHandle struct {
	*device.Device
	*device.Logger
}

// tunnelHandles is reachable from every exported entry point, and those are called from Swift on
// whatever queue the caller happens to be on. WireGuardAdapter serialises its own calls on a
// per-adapter workQueue, which is enough only while a process holds ONE adapter — true for an app
// extension, whose process dies on every disconnect, and false for a macOS SYSTEM extension, whose
// process is a resident daemon that can hold several. deinit also calls wgTurnOff off-queue.
//
// An unsynchronised concurrent map write is not a race that corrupts a value: the Go runtime detects
// it and aborts the process with "fatal error: concurrent map writes", taking the whole network
// extension down with it.
var (
	tunnelHandlesMu sync.Mutex
	tunnelHandles   = make(map[int32]tunnelHandle)
)

func init() {
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	// OWNERSHIP OF dupTunFd PASSES HERE. os.NewFile takes the descriptor, and from this point the
	// raw number must never be closed directly: the File owns it, then the Device owns the File. A
	// direct unix.Close is a DOUBLE CLOSE, and in a long-lived process the second one lands on
	// whatever unrelated object has since been handed that descriptor number.
	//
	// Closing the *os.File instead of the number is safe even where CreateTUNFromFile has already
	// closed it — os.File records that it is closed and returns ErrClosed rather than closing twice.
	tunFile := os.NewFile(uintptr(dupTunFd), "/dev/tun")
	tunDev, err := tun.CreateTUNFromFile(tunFile, 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		tunFile.Close()
		return -1
	}
	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tunDev, conn.NewStdNetBind(), logger)

	err = dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		// dev.Close() and not a bare descriptor close: NewDevice has already started the device's
		// goroutines, so closing the fd alone left a running Device with a dead tun behind it — a
		// leak on top of the double close.
		dev.Close()
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started")

	tunnelHandlesMu.Lock()
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	exhausted := i == math.MaxInt32
	if !exhausted {
		tunnelHandles[i] = tunnelHandle{dev, logger}
	}
	tunnelHandlesMu.Unlock()

	if exhausted {
		// Closed outside the lock, same reasoning as wgTurnOff: Device.Close() waits on the
		// device's goroutines, and no unrelated tunnel should queue behind that.
		dev.Close()
		return -1
	}
	return i
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	tunnelHandlesMu.Lock()
	dev, ok := tunnelHandles[tunnelHandle]
	if ok {
		delete(tunnelHandles, tunnelHandle)
	}
	tunnelHandlesMu.Unlock()
	if !ok {
		return
	}
	// Closed OUTSIDE the lock: Device.Close() waits for the device's goroutines to wind down, and
	// holding a process-wide mutex across that would serialise an unrelated tunnel's start behind
	// this one's teardown.
	dev.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	tunnelHandlesMu.Lock()
	dev, ok := tunnelHandles[tunnelHandle]
	tunnelHandlesMu.Unlock()
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	tunnelHandlesMu.Lock()
	device, ok := tunnelHandles[tunnelHandle]
	tunnelHandlesMu.Unlock()
	if !ok {
		return nil
	}
	settings, err := device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	tunnelHandlesMu.Lock()
	dev, ok := tunnelHandles[tunnelHandle]
	tunnelHandlesMu.Unlock()
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	tunnelHandlesMu.Lock()
	dev, ok := tunnelHandles[tunnelHandle]
	tunnelHandlesMu.Unlock()
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

func main() {}
