package cslogging

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"
)

var DEFAULT_LOG_FILE = ""

type LoggingConfig struct {
	LogLevel     *log.Level `yaml:"log_level"`
	LogMode      string     `yaml:"log_mode"`
	LogDir       string     `yaml:"log_dir"`
	LogMaxSize   int        `yaml:"log_max_size,omitempty"`
	LogMaxFiles  int        `yaml:"log_max_files,omitempty"`
	LogMaxAge    int        `yaml:"log_max_age,omitempty"`
	CompressLogs *bool      `yaml:"compress_logs,omitempty"`
}

func (c *LoggingConfig) LoggerForFile(fileName string) (io.Writer, error) {
	if c.LogMode == "stdout" {
		return os.Stderr, nil
	}

	// default permissions will be 0600 from lumberjack
	// and are preserved if the file already exists

	l := &lumberjack.Logger{
		Filename:   filepath.Join(c.LogDir, fileName),
		MaxSize:    c.LogMaxSize,
		MaxBackups: c.LogMaxFiles,
		MaxAge:     c.LogMaxAge,
		Compress:   *c.CompressLogs,
	}

	return l, nil
}

func (c *LoggingConfig) setDefaults() {
	if c.LogMode == "" {
		c.LogMode = "stdout"
	}

	if c.LogDir == "" {
		c.LogDir = "/var/log/"
	}

	if c.LogLevel == nil {
		c.LogLevel = ptr.Of(log.InfoLevel)
	}

	if c.LogMaxSize == 0 {
		c.LogMaxSize = 500
	}

	if c.LogMaxFiles == 0 {
		c.LogMaxFiles = 3
	}

	if c.LogMaxAge == 0 {
		c.LogMaxAge = 30
	}

	if c.CompressLogs == nil {
		c.CompressLogs = ptr.Of(true)
	}
}

func (c *LoggingConfig) validate() error {
	if c.LogMode != "stdout" && c.LogMode != "file" {
		return errors.New("log_mode should be either 'stdout' or 'file'")
	}

	return nil
}

func (c *LoggingConfig) ConfigureLogger(clog *log.Logger) error {
	log.SetLevel(*c.LogLevel)

	if c.LogMode == "stdout" {
		return nil
	}

	log.SetFormatter(&log.TextFormatter{TimestampFormat: time.RFC3339, FullTimestamp: true})

	logger, err := c.LoggerForFile(DEFAULT_LOG_FILE)
	if err != nil {
		return err
	}

	log.SetOutput(logger)

	// keep stderr for panic/fatal, otherwise process failures
	// won't be visible enough
	log.AddHook(&writer.Hook{
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	return nil
}

func (c *LoggingConfig) Setup(fileName string) error {
	// Not great but we need to set the default log file for the logger
	DEFAULT_LOG_FILE = fileName

	c.setDefaults()

	if err := c.validate(); err != nil {
		return err
	}

	if err := c.ConfigureLogger(log.StandardLogger()); err != nil {
		return err
	}

	return nil
}
