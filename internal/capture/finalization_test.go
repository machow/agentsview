package capture

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/agentsview/internal/db"
)

func TestCompletedAttemptBecomesRecoverableTimeoutAtSealDeadline(t *testing.T) {
	state := &captureState{
		dir: t.TempDir(),
		manifest: manifest{
			OccurrenceID: "seal-timeout", Limits: DefaultLimits(),
		},
		finalizationDeadline: time.Now().Add(-time.Second),
	}

	result, data, err := encodeAndStoreResult(state, Result{
		Schema:       Schema{Name: ResultSchemaName, Version: ResultSchemaVersion},
		OccurrenceID: "seal-timeout",
		Reporting: ReportingOutcome{
			Outcome: ReportingComplete,
		},
		Producer: ProducerMetadata{AgentsViewVersion: "test"},
	}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, ReportingFailed, result.Reporting.Outcome)
	assert.Equal(t, ReasonFinalizationTimeout, result.Reporting.Reason)
	assert.Empty(t, state.manifest.SealedDigest)
	stored, readErr := os.ReadFile(state.sealedPath())
	require.NoError(t, readErr)
	assert.Equal(t, data, stored)
}

func TestCompletedRetryKeepsPriorFailureWhenSealingExpires(t *testing.T) {
	state := &captureState{
		dir: t.TempDir(),
		manifest: manifest{
			OccurrenceID: "retry-seal-timeout", Provider: string(ProviderClaude),
			Limits: DefaultLimits(),
		},
	}
	first := failureResult(state.manifest, ReasonNoSession, "test")
	firstData, err := encodeResult(first, state.manifest.Limits.MaxResultBytes)
	require.NoError(t, err)
	require.NoError(t, state.storeAttempt(firstData, false))
	state.finalizationDeadline = time.Now().Add(-time.Second)

	result, data, err := encodeAndStoreResult(state, Result{
		Schema:       Schema{Name: ResultSchemaName, Version: ResultSchemaVersion},
		OccurrenceID: state.manifest.OccurrenceID,
		Provider:     ProviderIdentity{Name: string(ProviderClaude)},
		Reporting:    ReportingOutcome{Outcome: ReportingComplete},
		Producer:     ProducerMetadata{AgentsViewVersion: "test"},
	}, nil)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, ReasonNoSession, result.Reporting.Reason)
	assert.Equal(t, firstData, data)
	stored, readErr := os.ReadFile(state.sealedPath())
	require.NoError(t, readErr)
	assert.Equal(t, firstData, stored)
	assert.Empty(t, state.manifest.SealedDigest)
}

func TestFinishIngestedResultClassifiesArchiveCloseFailure(t *testing.T) {
	database, err := db.OpenIsolated(filepath.Join(t.TempDir(), "capture.db"))
	require.NoError(t, err)
	rows, err := database.Reader().Query("SELECT 1")
	require.NoError(t, err)
	require.True(t, rows.Next())
	restoreTimeout := db.SetCloseDrainTimeoutForTest(10 * time.Millisecond)
	t.Cleanup(restoreTimeout)
	t.Cleanup(func() {
		require.NoError(t, rows.Close())
		require.NoError(t, database.Close())
	})

	state := &captureState{manifest: manifest{
		OccurrenceID:      "close-failure",
		Provider:          string(ProviderClaude),
		ProviderSessionID: "11111111-1111-4111-8111-111111111111",
	}}
	result, err := finishIngestedResult(
		context.Background(),
		state,
		&ingestedCapture{
			Database: database,
			Root: &db.Session{
				ID: "11111111-1111-4111-8111-111111111111",
			},
			Usage: &db.SessionUsage{},
		},
		"test",
	)

	require.Error(t, err)
	assert.Equal(t, ReportingFailed, result.Reporting.Outcome)
	assert.Equal(t, ReasonIngestFailed, result.Reporting.Reason)
}

func TestOpenCaptureEngineStopsBeforeInitializationAfterDeadline(t *testing.T) {
	state := &captureState{dir: t.TempDir(), manifest: manifest{
		Provider: string(ProviderClaude),
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	database, engine, err := openCaptureEngine(ctx, state, nil)

	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, database)
	assert.Nil(t, engine)
	assert.NoFileExists(t, state.archivePath())
}

func TestFinishIngestedResultBoundsArchiveCloseByFinalizationDeadline(
	t *testing.T,
) {
	database, err := db.OpenIsolated(filepath.Join(t.TempDir(), "capture.db"))
	require.NoError(t, err)
	rows, err := database.Reader().Query("SELECT 1")
	require.NoError(t, err)
	require.True(t, rows.Next())
	restoreTimeout := db.SetCloseDrainTimeoutForTest(2 * time.Second)
	t.Cleanup(restoreTimeout)
	t.Cleanup(func() {
		require.NoError(t, rows.Close())
		require.NoError(t, database.Close())
	})

	state := &captureState{manifest: manifest{
		OccurrenceID:      "bounded-close",
		Provider:          string(ProviderClaude),
		ProviderSessionID: "11111111-1111-4111-8111-111111111111",
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := finishIngestedResult(
		ctx,
		state,
		&ingestedCapture{
			Database: database,
			Root: &db.Session{
				ID: "11111111-1111-4111-8111-111111111111",
			},
			Usage: &db.SessionUsage{},
		},
		"test",
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), 500*time.Millisecond)
	assert.Equal(t, ReportingFailed, result.Reporting.Outcome)
	assert.Equal(t, ReasonFinalizationTimeout, result.Reporting.Reason)
}
