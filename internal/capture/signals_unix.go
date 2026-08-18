//go:build !windows

package capture

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func configureChildProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func forwardSignals(process *os.Process) func() {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-ch:
				if unixSignal, ok := sig.(syscall.Signal); ok {
					_ = syscall.Kill(-process.Pid, unixSignal)
				}
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
