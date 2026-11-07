package store

import (
	"errors"
	"fmt"
	"os"
)

// Kind classifies state errors so the CLI can return stable exit codes.
type Kind int

const (
	KindNotFound Kind = iota
	KindCorrupt
	KindSchemaHigh
	KindUnsupported
	KindPermission
	KindDrift
)

// Error wraps a Kind plus a user-facing message.
type Error struct {
	Kind Kind
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// New builds a classified error.
func New(k Kind, msg string, err error) *Error { return &Error{Kind: k, Msg: msg, Err: err} }

// ExitCode maps classified errors to the Phase 01 CLI contract.
func ExitCode(err error) int {
	var se *Error
	if !errors.As(err, &se) {
		return 1
	}
	switch se.Kind {
	case KindNotFound:
		return 3
	case KindCorrupt:
		return 4
	case KindSchemaHigh:
		return 5
	case KindPermission:
		return 6
	case KindDrift:
		return 7
	case KindUnsupported:
		return 12
	default:
		return 1
	}
}

// ClassifyOS turns file system failures into stable kinds.
func ClassifyOS(msg string, err error) error {
	if os.IsNotExist(err) {
		return New(KindNotFound, msg, err)
	}
	if os.IsPermission(err) {
		return New(KindPermission, msg, err)
	}
	return New(KindCorrupt, msg, err)
}

func corruptf(format string, args ...any) error {
	return New(KindCorrupt, fmt.Sprintf(format, args...), nil)
}
