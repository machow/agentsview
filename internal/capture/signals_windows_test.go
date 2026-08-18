//go:build windows

package capture

import (
	"os"
	"os/signal"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureHelperProcessGroupID() int { return 0 }

func captureHelperWaitForSignal(mode, marker string) {
	var ch chan os.Signal
	if mode == "claude-trap-signal" {
		ch = make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt)
	}
	if mode == "claude-ignore-signal" {
		signal.Ignore(os.Interrupt)
	}
	_ = os.WriteFile(marker, []byte("0"), 0o600)
	if ch != nil {
		<-ch
		_ = os.WriteFile(
			os.Getenv("AGENTSVIEW_CAPTURE_TEST_SIGNAL_HANDLED_MARKER"),
			[]byte("handled"), 0o600,
		)
		os.Exit(0)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestRelayWindowsSignalsForwardsRepeatedInterrupts(t *testing.T) {
	signals := make(chan os.Signal, 2)
	done := make(chan struct{})
	forwarded := make(chan os.Signal, 2)
	exited := make(chan struct{})
	go func() {
		relayWindowsSignals(signals, done, func(sig os.Signal) {
			forwarded <- sig
		})
		close(exited)
	}()

	signals <- os.Interrupt
	signals <- os.Interrupt
	for range 2 {
		select {
		case got := <-forwarded:
			assert.Equal(t, os.Interrupt, got)
		case <-time.After(time.Second):
			require.FailNow(t, "interrupt was not forwarded")
		}
	}
	close(done)
	select {
	case <-exited:
	case <-time.After(time.Second):
		require.FailNow(t, "signal relay did not stop")
	}
}
