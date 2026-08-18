//go:build windows

package capture

import (
	"os"
	"os/exec"
	"os/signal"
)

func configureChildProcess(*exec.Cmd) {}

func forwardSignals(process *os.Process) func() {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt)
	done := make(chan struct{})
	go relayWindowsSignals(ch, done, func(sig os.Signal) {
		_ = process.Signal(sig)
	})
	return func() {
		signal.Stop(ch)
		close(done)
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
