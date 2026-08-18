package db

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cancelAfterChecksContext struct {
	remaining atomic.Int64
	done      chan struct{}
	once      sync.Once
}

func newCancelAfterChecksContext(checks int64) *cancelAfterChecksContext {
	ctx := &cancelAfterChecksContext{done: make(chan struct{})}
	ctx.remaining.Store(checks)
	return ctx
}

func (ctx *cancelAfterChecksContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (ctx *cancelAfterChecksContext) Done() <-chan struct{} { return ctx.done }

func (ctx *cancelAfterChecksContext) Err() error {
	if ctx.remaining.Add(-1) >= 0 {
		return nil
	}
	ctx.once.Do(func() { close(ctx.done) })
	return context.Canceled
}

func (ctx *cancelAfterChecksContext) Value(any) any { return nil }

func TestWriteSessionBatchContextStopsDuringMessagePreparation(t *testing.T) {
	database := testDB(t)
	messages := make([]Message, 100)
	for i := range messages {
		messages[i] = userMsg("message-cancel", i, "prompt")
	}

	result, err := database.WriteSessionBatchContext(
		newCancelAfterChecksContext(10), []SessionBatchWrite{{
			Session: Session{ID: "message-cancel", Project: "project-a",
				Machine: defaultMachine, Agent: defaultAgent},
			Messages: messages, DataVersion: CurrentDataVersion(),
		}},
	)

	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, result.WrittenSessions)
	session, readErr := database.GetSessionFull(t.Context(), "message-cancel")
	require.NoError(t, readErr)
	assert.Nil(t, session)
}

func TestWriteSessionBatchContextStopsDuringUsagePreparation(t *testing.T) {
	database := testDB(t)
	events := make([]UsageEvent, 100)
	for i := range events {
		events[i] = UsageEvent{SessionID: "usage-cancel", Source: "message",
			OutputTokens: 1}
	}

	result, err := database.WriteSessionBatchContext(
		newCancelAfterChecksContext(10), []SessionBatchWrite{{
			Session: Session{ID: "usage-cancel", Project: "project-a",
				Machine: defaultMachine, Agent: defaultAgent},
			UsageEvents: events, DataVersion: CurrentDataVersion(),
		}},
	)

	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, result.WrittenSessions)
	session, readErr := database.GetSessionFull(t.Context(), "usage-cancel")
	require.NoError(t, readErr)
	assert.Nil(t, session)
}
