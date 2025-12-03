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

func TestPprofConfigUnmarshal(t *testing.T) {
	const configYAML = `
log_mode: stdout
listen_tcp: 0.0.0.0:9000
pprof:
  enabled: true
  listen_addr: 127.0.0.1
  listen_port: "6060"
`

	cfg, err := NewConfig(strings.NewReader(configYAML))

	require.NoError(t, err)
	assert.True(t, cfg.PprofConfig.Enabled)
	assert.Equal(t, "127.0.0.1", cfg.PprofConfig.ListenAddress)
	assert.Equal(t, "6060", cfg.PprofConfig.ListenPort)
}

func TestPprofConfigDefaults(t *testing.T) {
	const configYAML = `
log_mode: stdout
listen_tcp: 0.0.0.0:9000
`

	cfg, err := NewConfig(strings.NewReader(configYAML))

	require.NoError(t, err)
	assert.False(t, cfg.PprofConfig.Enabled, "pprof should be disabled by default")
	assert.Empty(t, cfg.PprofConfig.ListenAddress)
	assert.Empty(t, cfg.PprofConfig.ListenPort)
}
