//go:build windows

package capture

import (
	"os"
	"os/exec"
	"os/signal"
	"sync"
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
	var wg sync.WaitGroup
	var first os.Signal
	wg.Go(func() {
		first = relayWindowsSignals(ch, done, func(sig os.Signal) {
			_ = process.Signal(sig)
		})
	})
	return func() (string, int) {
		unregisterChildSignals(ch)
		close(done)
		wg.Wait()
		if first == os.Interrupt {
			return "SIGINT", 130
		}
		return "", 0
	}
}

func relayWindowsSignals(
	signals <-chan os.Signal,
	done <-chan struct{},
	forward func(os.Signal),
) os.Signal {
	var first os.Signal
	handle := func(sig os.Signal) {
		if first == nil {
			first = sig
		}
		forward(sig)
	}
	for {
		select {
		case sig := <-signals:
			handle(sig)
		case <-done:
			for {
				select {
				case sig := <-signals:
					handle(sig)
				default:
					return first
				}
			}
		}
	}
}

func processSignal(*os.ProcessState) (string, int) { return "", 0 }
