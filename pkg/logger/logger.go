package logger

import (
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/log"
)

type InAppLogger struct {
	*log.Logger
}

func NewInAppLogger(prefix string) *InAppLogger {
	return &InAppLogger{
		log.NewWithOptions(os.Stderr, log.Options{
			ReportTimestamp: true,
			TimeFormat:      time.Kitchen,
			Prefix:          prefix,
		}),
	}
}

func (l *InAppLogger) NewInAppLoggerExtendPrefix(prefix string) *InAppLogger {
	return &InAppLogger{
		log.NewWithOptions(os.Stderr, log.Options{
			ReportTimestamp: true,
			TimeFormat:      time.Kitchen,
			Prefix:          fmt.Sprintf("%s|%s", l.GetPrefix(), prefix),
		}),
	}
}