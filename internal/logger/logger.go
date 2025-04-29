package logger

import (
	"os"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

// ContextHook is a logrus hook that adds file and line information to log entries
type ContextHook struct{}

// Levels defines which log levels this hook will be applied to
func (hook *ContextHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire is called when a log event is fired
func (hook *ContextHook) Fire(entry *logrus.Entry) error {
	pc := make([]uintptr, 3)
	cnt := runtime.Callers(6, pc)

	for i := 0; i < cnt; i++ {
		fu := runtime.FuncForPC(pc[i])
		name := fu.Name()
		if !strings.Contains(name, "github.com/sirupsen/logrus") {
			file, line := fu.FileLine(pc[i])
			// Extract just the filename from the path
			parts := strings.Split(file, "/")
			file = parts[len(parts)-1]

			entry.Data["file"] = file
			entry.Data["line"] = line
			entry.Data["func"] = name
			break
		}
	}
	return nil
}

// New creates a new logrus Logger with predefined settings
func New() *logrus.Logger {
	log := logrus.New()

	// Set default level to Info
	log.SetLevel(logrus.InfoLevel)

	// Set formatter
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	// Set output to stdout
	log.SetOutput(os.Stdout)

	// Add hook for file and line numbers
	log.AddHook(&ContextHook{})

	return log
}

// WithField returns a new entry with the specified field
func WithField(logger *logrus.Logger, key string, value interface{}) *logrus.Entry {
	return logger.WithField(key, value)
}

// WithFields returns a new entry with the specified fields
func WithFields(logger *logrus.Logger, fields map[string]interface{}) *logrus.Entry {
	return logger.WithFields(fields)
}
