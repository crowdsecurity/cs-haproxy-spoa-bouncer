package cfg

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBouncerConfigValidateRequiresListener(t *testing.T) {
	cfg := &BouncerConfig{}

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one listener")
}

func TestBouncerConfigValidateTcpOnly(t *testing.T) {
	cfg := &BouncerConfig{
		ListenTCP: "0.0.0.0:1234",
	}

	require.NoError(t, cfg.Validate())
}

func TestBouncerConfigValidateUnixOnly(t *testing.T) {
	cfg := &BouncerConfig{
		ListenUnix: "/tmp/spoa.sock",
	}

	require.NoError(t, cfg.Validate())
}

func TestNewConfigValidation(t *testing.T) {
	const configYAML = `
logging:
  log_mode: stdout
`

	_, err := NewConfig(strings.NewReader(configYAML))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one listener")
}
