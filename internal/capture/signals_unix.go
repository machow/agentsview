//go:build !windows

package capture

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func forwardSignals(process *os.Process) func() {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-ch:
				_ = process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

func processSignal(state *os.ProcessState) (string, int) {
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return "", 0
	}
	sig := status.Signal()
	name := fmt.Sprintf("SIG%d", sig)
	switch sig {
	case syscall.SIGINT:
		name = "SIGINT"
	case syscall.SIGTERM:
		name = "SIGTERM"
	}
	return name, 128 + int(sig)
}
