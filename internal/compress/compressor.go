package compress

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"tracejutsu/internal/detect"
	"tracejutsu/internal/events"
)

type RootProcess struct {
	PID            int    `json:"pid"`
	ProcessName    string `json:"process_name"`
	ExecutablePath string `json:"executable_path"`
}

type Incident struct {
	IncidentID    string      `json:"incident_id"`
	StartTime     time.Time   `json:"start_time"`
	EndTime       time.Time   `json:"end_time"`
	RootProcess   RootProcess `json:"root_process"`
	ProcessTree   []string    `json:"process_tree"`
	RiskScore     int         `json:"risk_score"`
	Signals       []string    `json:"signals"`
	Timeline      []string    `json:"timeline"`
	Summary       string      `json:"summary"`
	LLMStatus     string      `json:"llm_status"`
	DroppedEvents int         `json:"dropped_events,omitempty"`
}

type Compressor interface {
	Compress(normalizedEvents []events.Event, detection detect.Result) (Incident, error)
}

type Basic struct{}

func NewBasic() Basic {
	return Basic{}
}

func (Basic) Compress(normalizedEvents []events.Event, detection detect.Result) (Incident, error) {
	if len(normalizedEvents) == 0 {
		return Incident{}, errors.New("cannot compress an empty event set")
	}

	ordered := append([]events.Event(nil), normalizedEvents...)
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].Timestamp.Before(ordered[right].Timestamp)
	})

	incident := Incident{
		IncidentID:  "inc-" + ordered[0].EventID,
		StartTime:   ordered[0].Timestamp,
		EndTime:     ordered[len(ordered)-1].Timestamp,
		RootProcess: inferRoot(ordered[0]),
		RiskScore:   detection.RiskScore,
		LLMStatus:   "pending",
	}

	incident.ProcessTree = processTree(incident.RootProcess, ordered)
	incident.Timeline = timeline(ordered)
	for _, matched := range detection.Signals {
		incident.Signals = append(incident.Signals, matched.RuleID)
	}
	incident.Summary = summarize(incident)

	return incident, nil
}

func inferRoot(first events.Event) RootProcess {
	if first.ParentProcessName != "" && first.PPID != 0 {
		return RootProcess{PID: first.PPID, ProcessName: first.ParentProcessName}
	}
	return RootProcess{
		PID:            first.PID,
		ProcessName:    first.ProcessName,
		ExecutablePath: first.ExecutablePath,
	}
}

func processTree(root RootProcess, normalizedEvents []events.Event) []string {
	tree := []string{fmt.Sprintf("%s(%d)", root.ProcessName, root.PID)}
	for _, event := range normalizedEvents {
		if event.EventType != events.TypeExecve || event.PPID == 0 {
			continue
		}
		tree = append(tree, fmt.Sprintf("%s(%d) -> %s(%d)",
			event.ParentProcessName, event.PPID, event.ProcessName, event.PID))
	}
	return tree
}

func timeline(normalizedEvents []events.Event) []string {
	var entries []string
	writeCounts := make(map[fileWriteKey]int)
	emittedWrites := make(map[fileWriteKey]bool)
	for _, event := range normalizedEvents {
		if event.EventType == events.TypeFileWrite && fileWriteChanged(event) {
			writeCounts[fileWriteKey{PID: event.PID, Path: event.FilePath}]++
		}
	}

	for _, event := range normalizedEvents {
		switch event.EventType {
		case events.TypeExecve:
			switch {
			case isShell(event.ProcessName):
				entries = append(entries, fmt.Sprintf("%s spawned shell %s", event.ParentProcessName, event.ProcessName))
			case isDownloadTool(event.ProcessName):
				entries = append(entries, fmt.Sprintf("%s ran %s to download %s",
					event.ParentProcessName, event.ProcessName, downloadOutput(event.CommandLine)))
			default:
				entries = append(entries, fmt.Sprintf("%s executed", displayExecutable(event)))
			}
		case events.TypeChmod:
			if !mutationSucceeded(event) {
				entries = append(entries, fmt.Sprintf("%s failed to make %s executable", event.ProcessName, event.FilePath))
				continue
			}
			entries = append(entries, fmt.Sprintf("%s made %s executable", event.ProcessName, event.FilePath))
		case events.TypeFileWrite:
			if !mutationSucceeded(event) {
				entries = append(entries, fmt.Sprintf("%s failed to write %s", event.ProcessName, event.FilePath))
				continue
			}
			if !fileWriteChanged(event) {
				entries = append(entries, fmt.Sprintf("%s completed zero-byte write to %s", event.ProcessName, event.FilePath))
				continue
			}
			key := fileWriteKey{PID: event.PID, Path: event.FilePath}
			if emittedWrites[key] {
				continue
			}
			emittedWrites[key] = true
			if writeCounts[key] == 1 {
				entries = append(entries, fmt.Sprintf("%s wrote %s", event.ProcessName, event.FilePath))
				continue
			}
			entries = append(entries, fmt.Sprintf("%s wrote %s %d times",
				event.ProcessName, event.FilePath, writeCounts[key]))
		case events.TypeConnect:
			switch event.Metadata["outcome"] {
			case "failed":
				entries = append(entries, fmt.Sprintf("%s failed to connect to %s",
					displayExecutable(event), remoteEndpoint(event)))
				continue
			case "in_progress":
				entries = append(entries, fmt.Sprintf("%s started connecting to %s",
					displayExecutable(event), remoteEndpoint(event)))
				continue
			}
			entries = append(entries, fmt.Sprintf("%s connected to %s",
				displayExecutable(event), remoteEndpoint(event)))
		case events.TypeSensitiveRead:
			if !mutationSucceeded(event) {
				entries = append(entries, fmt.Sprintf("%s failed to read sensitive file %s", event.ProcessName, event.FilePath))
				continue
			}
			entries = append(entries, fmt.Sprintf("%s read sensitive file %s", event.ProcessName, event.FilePath))
		case events.TypeFileLifecycle:
			action := metadataString(event, "action")
			if !mutationSucceeded(event) {
				entries = append(entries, fmt.Sprintf("%s failed to %s %s", event.ProcessName, lifecycleVerb(action), event.FilePath))
				continue
			}
			entries = append(entries, fmt.Sprintf("%s %s %s", event.ProcessName, lifecyclePastTense(action), event.FilePath))
		case events.TypePrivilegeChange:
			entries = append(entries, fmt.Sprintf("%s called privilege syscall %s", event.ProcessName, metadataString(event, "syscall")))
		case events.TypeNamespaceChange:
			entries = append(entries, fmt.Sprintf("%s called namespace syscall %s", event.ProcessName, metadataString(event, "syscall")))
		case events.TypeProcessAccess:
			if target := metadataUint64(event, "target_pid"); target != 0 {
				entries = append(entries, fmt.Sprintf("%s accessed process %d with %s", event.ProcessName, target, metadataString(event, "syscall")))
				continue
			}
			entries = append(entries, fmt.Sprintf("%s accessed another process with %s", event.ProcessName, metadataString(event, "syscall")))
		case events.TypeNetworkServer:
			switch metadataString(event, "syscall") {
			case "bind":
				entries = append(entries, fmt.Sprintf("%s bound listener address %s", event.ProcessName, remoteEndpoint(event)))
			case "listen":
				entries = append(entries, fmt.Sprintf("%s started listening on fd %v", event.ProcessName, event.Metadata["fd"]))
			default:
				entries = append(entries, fmt.Sprintf("%s opened network server syscall %s", event.ProcessName, metadataString(event, "syscall")))
			}
		case events.TypeKernelTamper:
			entries = append(entries, fmt.Sprintf("%s called kernel tamper syscall %s", event.ProcessName, metadataString(event, "syscall")))
		}
	}
	return entries
}

type fileWriteKey struct {
	PID  int
	Path string
}

func summarize(incident Incident) string {
	required := []string{
		"web_process_spawned_shell",
		"shell_downloaded_file",
		"tmp_file_made_executable",
		"recently_downloaded_binary_executed",
		"downloaded_binary_connected_outbound",
	}
	if hasAll(incident.Signals, required) {
		return fmt.Sprintf("%s spawned a shell, downloaded a file into /tmp, made it executable, executed it, then opened an outbound connection.",
			incident.RootProcess.ProcessName)
	}
	return fmt.Sprintf("Observed %d related runtime events with %d deterministic signals.",
		len(incident.Timeline), len(incident.Signals))
}

func hasAll(actual, required []string) bool {
	found := make(map[string]bool, len(actual))
	for _, item := range actual {
		found[item] = true
	}
	for _, item := range required {
		if !found[item] {
			return false
		}
	}
	return true
}

func displayExecutable(event events.Event) string {
	if event.ExecutablePath != "" {
		return event.ExecutablePath
	}
	return event.ProcessName
}

func isShell(name string) bool {
	switch filepath.Base(name) {
	case "sh", "bash", "dash", "zsh":
		return true
	default:
		return false
	}
}

func isDownloadTool(name string) bool {
	switch filepath.Base(name) {
	case "curl", "wget":
		return true
	default:
		return false
	}
}

func downloadOutput(commandLine []string) string {
	for index, argument := range commandLine {
		if (argument == "-o" || argument == "-O") && index+1 < len(commandLine) {
			return commandLine[index+1]
		}
	}
	return "a file"
}

func mutationSucceeded(event events.Event) bool {
	outcome, _ := event.Metadata["outcome"].(string)
	return outcome != "failed"
}

func fileWriteChanged(event events.Event) bool {
	if !mutationSucceeded(event) {
		return false
	}
	value, found := event.Metadata["written_bytes"]
	if !found {
		return true
	}
	switch count := value.(type) {
	case int:
		return count > 0
	case int64:
		return count > 0
	case float64:
		return count > 0
	default:
		return false
	}
}

func metadataString(event events.Event, key string) string {
	value, _ := event.Metadata[key].(string)
	return value
}

func metadataUint64(event events.Event, key string) uint64 {
	switch value := event.Metadata[key].(type) {
	case uint64:
		return value
	case uint:
		return uint64(value)
	case int:
		if value < 0 {
			return 0
		}
		return uint64(value)
	case int64:
		if value < 0 {
			return 0
		}
		return uint64(value)
	case float64:
		if value < 0 {
			return 0
		}
		return uint64(value)
	default:
		return 0
	}
}

func lifecycleVerb(action string) string {
	switch action {
	case "mkdir":
		return "create"
	case "unlink":
		return "delete"
	case "rename":
		return "rename"
	case "symlink":
		return "create symlink at"
	case "link":
		return "create hard link at"
	case "truncate":
		return "truncate"
	default:
		return "modify"
	}
}

func lifecyclePastTense(action string) string {
	switch action {
	case "mkdir":
		return "created"
	case "unlink":
		return "deleted"
	case "rename":
		return "renamed"
	case "symlink":
		return "created symlink at"
	case "link":
		return "created hard link at"
	case "truncate":
		return "truncated"
	default:
		return "modified"
	}
}

func remoteEndpoint(event events.Event) string {
	return net.JoinHostPort(event.RemoteAddr, strconv.Itoa(event.RemotePort))
}
