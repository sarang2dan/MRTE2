package logutil

import (
	"bytes"
	"fmt"
	logr "github.com/sirupsen/logrus"
	"sort"
)

const (
	defaultLogTimeFormat = "2006/01/02 15:04:05.000"
)

// textFormatter is for compatibility with ngaut/logr
type textFormatter struct {
	DisableTimestamp bool
	EnableColors     bool
	EnableEntryOrder bool
}

var logLevelStr = [...]string{
	"panic",
	"fatal",
	"error",
	"warn",
	"info",
	"debug",
	"trace",
}

func init() {
	logFmt := &textFormatter{
		DisableTimestamp: false,
		EnableColors:     true,
	}

	logr.SetFormatter(logFmt)
	logr.SetLevel(logr.DebugLevel)
}

func SetColoring(isColoring bool) {
	logFmt := &textFormatter{
		DisableTimestamp: false,
		EnableColors:     isColoring,
	}
	logr.SetFormatter(logFmt)
}

func SetLevel(level string) error {
	lvl, err := logr.ParseLevel(level)
	if err != nil {
		lvl = logr.WarnLevel
	}

	logr.SetLevel(lvl)
	return err
}

func getLogLevel(level logr.Level) string {
	return logLevelStr[level]
}

// Format implements logrus.Formatter
func (f *textFormatter) Format(entry *logr.Entry) ([]byte, error) {
	var buf *bytes.Buffer

	if entry.Buffer != nil {
		buf = entry.Buffer
	} else {
		buf = &bytes.Buffer{}
	}

	if !f.DisableTimestamp {
		fmt.Fprintf(buf, "%s ", entry.Time.Format(defaultLogTimeFormat))
	}

	if file, ok := entry.Data["file"]; ok {
		fmt.Fprintf(buf, "%s:%v:", file, entry.Data["line"])
	}

	var colorStart string = ""
	var colorEnd string = ""

	if f.EnableColors == true {
		colorStr := logTypeToColor(entry.Level)
		colorStart = fmt.Sprintf("\033%sm", colorStr)
		colorEnd = "\033[0m"
	}

	//fmt.Fprintf(buf, "[%s%-7s%s] %s", colorStart, entry.Level.String(), colorEnd, entry.Message)
	fmt.Fprintf(buf, "[%s%s%s] %s", colorStart, getLogLevel(entry.Level), colorEnd, entry.Message)

	if f.EnableEntryOrder {
		keys := make([]string, 0, len(entry.Data))
		for k := range entry.Data {
			if k != "file" && k != "line" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(buf, " %v=%v", k, entry.Data[k])
		}
	} else {
		for k, v := range entry.Data {
			if k != "file" && k != "line" {
				fmt.Fprintf(buf, " %v=%v", k, v)
			}
		}
	}

	buf.WriteByte('\n')

	return buf.Bytes(), nil
}

// logTypeToColor converts the Level to a color string.
func logTypeToColor(level logr.Level) string {
	switch level {
	case logr.DebugLevel:
		return "[0;37"
	case logr.InfoLevel:
		return "[0;36"
	case logr.WarnLevel:
		return "[0;33"
	case logr.ErrorLevel:
		return "[0;31"
	case logr.FatalLevel:
		return "[0;31"
	case logr.PanicLevel:
		return "[0;31"
	}

	return "[0;37"
}
