//go:build windows

package capture

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
