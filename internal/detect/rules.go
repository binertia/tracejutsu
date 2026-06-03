package detect

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"runtime-guard/internal/events"
)

type Basic struct{}

func NewBasic() Basic {
	return Basic{}
}

func RuleIDs() []string {
	return []string{
		"web_process_spawned_shell",
		"shell_downloaded_file",
		"tmp_file_made_executable",
		"recently_downloaded_binary_executed",
		"downloaded_binary_connected_outbound",
		"suspicious_reverse_shell_pattern",
		"package_manager_spawned_shell",
		"sensitive_file_access",
		"crypto_miner_process_name",
		"unexpected_network_tool_execution",
	}
}

// Analyze applies a small deterministic rule set to a related process tree.
func (Basic) Analyze(normalizedEvents []events.Event) Result {
	ordered := append([]events.Event(nil), normalizedEvents...)
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].Timestamp.Before(ordered[right].Timestamp)
	})

	var result Result
	downloadProcesses := make(map[int]events.Event)
	downloadedFiles := make(map[string][]events.Event)
	downloadedProcessPIDs := make(map[int]downloadedArtifact)
	shellProcesses := make(map[int]events.Event)
	sensitiveFiles := make(map[string]bool)
	reverseShellConnections := make(map[string]bool)

	for _, event := range ordered {
		switch event.EventType {
		case events.TypeExecve:
			if isShell(event.ProcessName) {
				shellProcesses[event.PID] = event
				if isWebProcess(event.ParentProcessName) {
					result.add(signal("web_process_spawned_shell", 30, []events.Event{event},
						fmt.Sprintf("%s spawned shell %s", event.ParentProcessName, event.ProcessName)))
				}
				if isPackageManager(event.ParentProcessName) {
					result.add(signal("package_manager_spawned_shell", 5, []events.Event{event},
						fmt.Sprintf("%s spawned shell %s", event.ParentProcessName, event.ProcessName)))
				}
			}

			if isDownloadTool(event.ProcessName) && isShell(event.ParentProcessName) {
				downloadedPath := downloadOutput(event.CommandLine)
				result.add(signal("shell_downloaded_file", 20, []events.Event{event},
					fmt.Sprintf("%s ran %s to download %s", event.ParentProcessName, event.ProcessName, displayDownloadOutput(downloadedPath))))
				downloadProcesses[event.PID] = event
				if downloadedPath != "" {
					downloadedFiles[downloadedPath] = []events.Event{event}
				}
			}

			if downloadEvents, found := downloadedFiles[event.ExecutablePath]; found {
				downloadedProcessPIDs[event.PID] = downloadedArtifact{
					downloadEvents: downloadEvents,
					executionEvent: event,
				}
				result.add(signal("recently_downloaded_binary_executed", 30, appendEvents(downloadEvents, event),
					fmt.Sprintf("recently downloaded file %s executed", event.ExecutablePath)))
			}

			if isCryptoMinerExecution(event) {
				result.add(signal("crypto_miner_process_name", 35, []events.Event{event},
					fmt.Sprintf("process %s matched a known crypto miner name", event.ProcessName)))
			}

			if isUnexpectedNetworkToolExecution(event) {
				result.add(signal("unexpected_network_tool_execution", 20, []events.Event{event},
					fmt.Sprintf("%s executed network utility %s", event.ParentProcessName, event.ProcessName)))
			}
		case events.TypeFileWrite:
			if !fileWriteChanged(event) {
				continue
			}
			if downloadEvent, found := downloadProcesses[event.PID]; found && event.FilePath != "" {
				downloadedFiles[event.FilePath] = []events.Event{downloadEvent, event}
			}
			if isSensitiveFile(event.FilePath) && !sensitiveFiles[event.FilePath] {
				result.add(signal("sensitive_file_access", 35, []events.Event{event},
					fmt.Sprintf("%s wrote sensitive file %s", event.ProcessName, event.FilePath)))
				sensitiveFiles[event.FilePath] = true
			}
		case events.TypeChmod:
			if mutationSucceeded(event) && isTempPath(event.FilePath) && metadataBool(event, "added_execute_bit") {
				result.add(signal("tmp_file_made_executable", 20, []events.Event{event},
					fmt.Sprintf("%s made %s executable", event.ProcessName, event.FilePath)))
			}
		case events.TypeConnect:
			if !mutationSucceeded(event) {
				continue
			}
			if artifact, found := downloadedProcessPIDs[event.PID]; found {
				result.add(signal("downloaded_binary_connected_outbound", 35,
					appendEvents(artifact.downloadEvents, artifact.executionEvent, event),
					fmt.Sprintf("%s %s %s", event.ProcessName, connectVerb(event), remoteEndpoint(event))))
			}
			connectionKey := fmt.Sprintf("%d:%s:%d", event.PID, event.RemoteAddr, event.RemotePort)
			if isShellConnection(event) && isUnusualOutboundPort(event.RemotePort) && !reverseShellConnections[connectionKey] {
				supportingEvents := []events.Event{event}
				if shellEvent, found := shellProcesses[event.PID]; found {
					supportingEvents = []events.Event{shellEvent, event}
				}
				result.add(signal("suspicious_reverse_shell_pattern", 50, supportingEvents,
					fmt.Sprintf("shell %s %s unusual outbound endpoint %s",
						event.ProcessName, connectVerb(event), remoteEndpoint(event))))
				reverseShellConnections[connectionKey] = true
			}
		}
	}

	return result
}

func (result *Result) add(matched Signal) {
	result.Signals = append(result.Signals, matched)
	result.RiskScore += matched.ScoreImpact
	if result.RiskScore > 100 {
		result.RiskScore = 100
	}
}

type downloadedArtifact struct {
	downloadEvents []events.Event
	executionEvent events.Event
}

func appendEvents(initial []events.Event, additional ...events.Event) []events.Event {
	combined := make([]events.Event, 0, len(initial)+len(additional))
	combined = append(combined, initial...)
	return append(combined, additional...)
}

func signal(ruleID string, scoreImpact int, supportingEvents []events.Event, evidence string) Signal {
	eventIDs := make([]string, 0, len(supportingEvents))
	for _, event := range supportingEvents {
		eventIDs = append(eventIDs, event.EventID)
	}
	return Signal{
		RuleID:      ruleID,
		Description: evidence,
		ScoreImpact: scoreImpact,
		EventIDs:    eventIDs,
		Evidence:    evidence,
	}
}

func isWebProcess(name string) bool {
	switch strings.ToLower(name) {
	case "nginx", "apache", "apache2", "httpd":
		return true
	default:
		return false
	}
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

func isPackageManager(name string) bool {
	switch filepath.Base(name) {
	case "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pacman", "apk", "brew":
		return true
	default:
		return false
	}
}

func isSensitiveFile(path string) bool {
	cleaned := filepath.Clean(path)
	switch cleaned {
	case "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
		"/etc/profile", "/etc/bash.bashrc", "/root/.ssh/authorized_keys":
		return true
	}
	return strings.HasPrefix(cleaned, "/etc/sudoers.d/") ||
		strings.HasPrefix(cleaned, "/etc/ssh/") ||
		strings.HasPrefix(cleaned, "/etc/systemd/system/") ||
		strings.HasPrefix(cleaned, "/usr/lib/systemd/system/") ||
		strings.HasPrefix(cleaned, "/root/.ssh/") ||
		strings.HasSuffix(cleaned, "/.ssh/authorized_keys") ||
		strings.HasSuffix(cleaned, "/.bashrc") ||
		strings.HasSuffix(cleaned, "/.profile") ||
		strings.HasSuffix(cleaned, "/.zshrc")
}

func isCryptoMinerExecution(event events.Event) bool {
	if isCryptoMinerName(event.ProcessName) || isCryptoMinerName(event.ExecutablePath) {
		return true
	}
	for _, argument := range event.CommandLine {
		if isCryptoMinerName(argument) {
			return true
		}
	}
	return false
}

func isCryptoMinerName(name string) bool {
	switch strings.ToLower(filepath.Base(name)) {
	case "xmrig", "minerd", "cpuminer", "cgminer", "bfgminer", "ethminer",
		"nbminer", "t-rex", "teamredminer":
		return true
	default:
		return false
	}
}

func isUnexpectedNetworkToolExecution(event events.Event) bool {
	switch filepath.Base(event.ProcessName) {
	case "nc", "ncat", "netcat", "socat", "telnet":
		return true
	case "curl", "wget":
		return isWebProcess(event.ParentProcessName)
	default:
		return false
	}
}

func isShellConnection(event events.Event) bool {
	return isShell(event.ProcessName) || isShell(event.ExecutablePath)
}

func isUnusualOutboundPort(port int) bool {
	switch port {
	case 0, 53, 80, 443:
		return false
	default:
		return true
	}
}

func downloadOutput(commandLine []string) string {
	for index, argument := range commandLine {
		if (argument == "-o" || argument == "-O") && index+1 < len(commandLine) {
			return commandLine[index+1]
		}
	}
	return ""
}

func displayDownloadOutput(path string) string {
	if path == "" {
		return "a file"
	}
	return path
}

func isTempPath(path string) bool {
	return strings.HasPrefix(path, "/tmp/") ||
		strings.HasPrefix(path, "/var/tmp/") ||
		strings.HasPrefix(path, "/dev/shm/")
}

func metadataBool(event events.Event, key string) bool {
	value, ok := event.Metadata[key].(bool)
	return ok && value
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

func remoteEndpoint(event events.Event) string {
	return net.JoinHostPort(event.RemoteAddr, strconv.Itoa(event.RemotePort))
}

func connectVerb(event events.Event) string {
	if outcome, _ := event.Metadata["outcome"].(string); outcome == "in_progress" {
		return "started connecting to"
	}
	return "connected to"
}
