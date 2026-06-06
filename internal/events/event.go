package events

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type Type string

const (
	TypeExecve          Type = "execve"
	TypeConnect         Type = "connect"
	TypeFileWrite       Type = "file_write"
	TypeChmod           Type = "chmod"
	TypeSensitiveRead   Type = "sensitive_read"
	TypeFileLifecycle   Type = "file_lifecycle"
	TypePrivilegeChange Type = "privilege_change"
	TypeNamespaceChange Type = "namespace_change"
	TypeProcessAccess   Type = "process_access"
	TypeNetworkServer   Type = "network_server"
	TypeKernelTamper    Type = "kernel_tamper"
)

// Event is the stable userspace representation emitted by every collector.
type Event struct {
	EventID           string         `json:"event_id"`
	Timestamp         time.Time      `json:"timestamp"`
	Host              string         `json:"host"`
	ContainerID       string         `json:"container_id"`
	ContainerName     string         `json:"container_name"`
	PID               int            `json:"pid"`
	PPID              int            `json:"ppid"`
	UID               int            `json:"uid"`
	ProcessName       string         `json:"process_name"`
	ParentProcessName string         `json:"parent_process_name"`
	EventType         Type           `json:"event_type"`
	ExecutablePath    string         `json:"executable_path"`
	CommandLine       []string       `json:"command_line"`
	CWD               string         `json:"cwd"`
	FilePath          string         `json:"file_path"`
	RemoteAddr        string         `json:"remote_addr"`
	RemotePort        int            `json:"remote_port"`
	Metadata          map[string]any `json:"metadata"`
}

func LoadJSON(reader io.Reader) ([]Event, error) {
	var loaded []Event
	if err := json.NewDecoder(reader).Decode(&loaded); err != nil {
		return nil, fmt.Errorf("decode normalized events: %w", err)
	}
	for index, event := range loaded {
		if err := event.Validate(); err != nil {
			return nil, fmt.Errorf("event %d: %w", index, err)
		}
	}
	return loaded, nil
}

func (event Event) Validate() error {
	if event.EventID == "" {
		return fmt.Errorf("event_id is required")
	}
	if event.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	if event.Host == "" {
		return fmt.Errorf("host is required")
	}
	if event.EventType == "" {
		return fmt.Errorf("event_type is required")
	}
	if event.ProcessName == "" {
		return fmt.Errorf("process_name is required")
	}
	return nil
}
