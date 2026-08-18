package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodexMetaMatchesLineLargerThanReaderBuffer(t *testing.T) {
	const sessionID = "11111111-1111-4111-8111-111111111111"
	line := fmt.Sprintf(
		`{"type":"session_meta","payload":{"id":%q,"padding":%q}}`+"\n",
		sessionID,
		strings.Repeat("x", 96<<10),
	)
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(line), 0o600))

	matched, err := codexMetaMatches(path, sessionID, 128<<10)

	require.NoError(t, err)
	assert.True(t, matched)
}
