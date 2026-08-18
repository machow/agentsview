package parser

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cancelOnErrCheckContext struct {
	context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	remaining int
}

func newCancelOnErrCheckContext(
	t *testing.T, checks int,
) context.Context {
	t.Helper()
	base, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &cancelOnErrCheckContext{
		Context: base, cancel: cancel, remaining: checks,
	}
}

func (ctx *cancelOnErrCheckContext) Err() error {
	ctx.mu.Lock()
	if ctx.remaining > 0 {
		ctx.remaining--
		if ctx.remaining == 0 {
			ctx.cancel()
		}
	}
	ctx.mu.Unlock()
	return ctx.Context.Err()
}

func TestJSONLProviderFingerprintStopsAfterContextCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	require.NoError(t, os.WriteFile(
		path, []byte(strings.Repeat("x", 256*1024)), 0o600,
	))
	for _, agent := range []AgentType{AgentClaude, AgentCodex} {
		t.Run(string(agent), func(t *testing.T) {
			provider, ok := NewProvider(agent, ProviderConfig{})
			require.True(t, ok)
			ctx := newCancelOnErrCheckContext(t, 4)

			_, err := provider.Fingerprint(ctx, SourceRef{
				Provider: agent,
				Opaque:   MaterializedFileSource{Path: path},
			})

			require.ErrorIs(t, err, context.Canceled)
		})
	}
}

func TestClaudeCanceledHeadSniffIsNotCached(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fork.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(
		`{"type":"user","uuid":"root","parentUuid":null,"sessionKind":"bg"}`+"\n",
	), 0o600))

	_, err := claudeSniffHead(newCancelOnErrCheckContext(t, 3), path)
	require.ErrorIs(t, err, context.Canceled)

	sniff, err := claudeSniffHead(t.Context(), path)
	require.NoError(t, err)
	assert.True(t, sniff.ok)
	assert.True(t, sniff.rootIsBG)
	assert.Equal(t, "root", sniff.rootUUID)
}
