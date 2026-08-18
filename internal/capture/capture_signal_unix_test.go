//go:build !windows

package capture

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterruptedChildStillSealsRecoverableUsage(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(t.TempDir(), "child-started")
	captureDir := filepath.Join(t.TempDir(), "capture")
	resultPath := filepath.Join(t.TempDir(), "result.json")
	workDir := t.TempDir()
	producer := copyCaptureHelper(t, "claude")
	env := append(
		helperEnvironment(root, "claude-wait-signal", 0),
		"AGENTSVIEW_CAPTURE_TEST_SIGNAL_MARKER="+marker,
	)
	type response struct {
		outcome RunOutcome
		err     error
	}
	done := make(chan response, 1)
	limits := testLimits()
	limits.FinalizationWait = 3 * time.Second
	go func() {
		outcome, err := Run(context.Background(), RunOptions{
			Provider: ProviderClaude, OccurrenceID: "interrupted",
			CaptureDir: captureDir, ResultPath: resultPath,
			ProviderRoot: root, WorkDir: workDir,
			Command: []string{producer, "-p", "prompt"}, Environment: env,
			Streams: Streams{Stdout: io.Discard, Stderr: io.Discard},
			Limits:  limits, CustomPricing: testPricing(),
		})
		done <- response{outcome: outcome, err: err}
	}()
	markerDeadline := time.After(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case early := <-done:
			t.Fatalf("capture exited before signal marker: outcome=%+v err=%v", early.outcome, early.err)
		case <-markerDeadline:
			t.Fatal("child did not write signal marker")
		case <-time.After(10 * time.Millisecond):
		}
	}
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	var got response
	select {
	case got = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("capture did not finish after forwarding SIGTERM")
	}
	require.NoError(t, got.err)
	assert.Equal(t, 128+int(syscall.SIGTERM), got.outcome.ExitCode)
	data, err := os.ReadFile(resultPath)
	require.NoError(t, err)
	result, err := DecodeResult(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, "SIGTERM", result.Execution.Signal)
	require.NotNil(t, result.Usage)

	var replay bytes.Buffer
	_, err = Report(context.Background(), ReportOptions{
		CaptureDir: captureDir, ResultPath: "-", Stdout: &replay,
		CustomPricing: testPricing(),
	})
	require.NoError(t, err)
	assert.Equal(t, data, replay.Bytes())
}
