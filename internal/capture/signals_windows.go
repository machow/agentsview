//go:build windows

package capture

import (
	"os"
	"os/exec"
	"os/signal"
)

func configureChildProcess(*exec.Cmd) {}

func registerChildSignals() chan os.Signal {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt)
	return ch
}

func unregisterChildSignals(ch chan os.Signal) {
	signal.Stop(ch)
}

func forwardSignals(
	process *os.Process, ch chan os.Signal,
) func() (string, int) {
	done := make(chan struct{})
	go relayWindowsSignals(ch, done, func(sig os.Signal) {
		_ = process.Signal(sig)
	})
	return func() (string, int) {
		unregisterChildSignals(ch)
		close(done)
		return "", 0
	}
}

func relayWindowsSignals(
	signals <-chan os.Signal,
	done <-chan struct{},
	forward func(os.Signal),
) {
	for {
		select {
		case sig := <-signals:
			forward(sig)
		case <-done:
			return
		}
	}
}

func processSignal(*os.ProcessState) (string, int) { return "", 0 }
