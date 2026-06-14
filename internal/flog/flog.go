package flog

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

type Level int

const None Level = -1
const (
	Debug Level = iota
	Info
	Warn
	Error
	Fatal
)

var (
	// minLevel is accessed atomically: SetLevel may be called concurrently
	// with logging in principle, and the race detector flags non-atomic
	// reads from the per-log-call gate as a data race. Int32 is the
	// smallest type sync/atomic supports for our Level (=int) enum.
	minLevel atomic.Int32
	logCh    = make(chan string, 1024)
)

func init() {
	minLevel.Store(int32(Info))
}

func SetLevel(l int) {
	minLevel.Store(int32(l))
	if l != -1 {
		go func() {
			for msg := range logCh {
				fmt.Fprint(os.Stdout, msg)
			}
		}()
	}
}

// Enabled reports whether a log call at the given level will emit. Use it
// at call sites where the format arguments are expensive to evaluate:
//
//	if flog.Enabled(flog.Debug) {
//	    flog.Debugf("...", expensiveCall(), ...)
//	}
//
// For cheap-argument calls there's no need to gate; logf already returns
// fast when the level is below threshold.
func Enabled(level Level) bool {
	m := Level(minLevel.Load())
	return m != None && level >= m
}

// DebugEnabled is a shortcut for Enabled(Debug). Cheaper to call than
// constructing the Level value at every gate site.
func DebugEnabled() bool { return Enabled(Debug) }

func logf(level Level, format string, args ...any) {
	m := Level(minLevel.Load())
	if level < m || m == None {
		return
	}

	for _, arg := range args {
		if err, ok := arg.(error); ok {
			err = WErr(err)
			if err == nil {
				return
			}
		}
	}

	now := time.Now().Format("2006-01-02 15:04:05.000")
	line := fmt.Sprintf("%s [%s] %s\n", now, level.String(), fmt.Sprintf(format, args...))

	select {
	case logCh <- line:
	default:
	}
}

func (l Level) String() string {
	switch l {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	case Fatal:
		return "FATAL"
	case None:
		return "None"
	default:
		return "UNKNOWN"
	}
}

func Debugf(format string, args ...any) { logf(Debug, format, args...) }
func Infof(format string, args ...any)  { logf(Info, format, args...) }
func Warnf(format string, args ...any)  { logf(Warn, format, args...) }
func Errorf(format string, args ...any) { logf(Error, format, args...) }
func Fatalf(format string, args ...any) {
	logf(Fatal, format, args...)
	// flush logs (optional: small sleep to let goroutine write)
	time.Sleep(10 * time.Millisecond)
	os.Exit(1)
}

func Close() { close(logCh) }
