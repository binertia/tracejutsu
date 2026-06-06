package detect

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"tracejutsu/internal/events"
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
		"sensitive_file_read",
		"persistence_path_modified",
		"log_tampering",
		"privilege_change_after_suspicious_activity",
		"namespace_escape_attempt",
		"process_memory_access",
		"unexpected_network_listener",
		"kernel_tamper_syscall",
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
	suspiciousProcessPIDs := make(map[int]bool)
	sensitiveFiles := make(map[string]bool)
	reverseShellConnections := make(map[string]bool)
	sensitiveReads := make(map[string]bool)
	persistenceChanges := make(map[string]bool)
	logTampering := make(map[string]bool)
	privilegeChanges := make(map[int]bool)
	namespaceChanges := make(map[int]bool)
	processAccesses := make(map[string]bool)
	networkListeners := make(map[string]bool)
	kernelTamper := make(map[string]bool)

	for _, event := range ordered {
		switch event.EventType {
		case events.TypeExecve:
			if isShell(event.ProcessName) {
				shellProcesses[event.PID] = event
				suspiciousProcessPIDs[event.PID] = true
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
				suspiciousProcessPIDs[event.PID] = true
				if downloadedPath != "" {
					downloadedFiles[downloadedPath] = []events.Event{event}
				}
			}

			if downloadEvents, found := downloadedFiles[event.ExecutablePath]; found {
				downloadedProcessPIDs[event.PID] = downloadedArtifact{
					downloadEvents: downloadEvents,
					executionEvent: event,
				}
				suspiciousProcessPIDs[event.PID] = true
				result.add(signal("recently_downloaded_binary_executed", 30, appendEvents(downloadEvents, event),
					fmt.Sprintf("recently downloaded file %s executed", event.ExecutablePath)))
			}

			if isCryptoMinerExecution(event) {
				suspiciousProcessPIDs[event.PID] = true
				result.add(signal("crypto_miner_process_name", 35, []events.Event{event},
					fmt.Sprintf("process %s matched a known crypto miner name", event.ProcessName)))
			}

			if isUnexpectedNetworkToolExecution(event) {
				suspiciousProcessPIDs[event.PID] = true
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
		case events.TypeSensitiveRead:
			key := fmt.Sprintf("%d:%s", event.PID, event.FilePath)
			if isSensitiveReadPath(event.FilePath) && !sensitiveReads[key] {
				result.add(signal("sensitive_file_read", 25, []events.Event{event},
					fmt.Sprintf("%s read sensitive file %s", event.ProcessName, event.FilePath)))
				sensitiveReads[key] = true
			}
		case events.TypeFileLifecycle:
			if !mutationSucceeded(event) {
				continue
			}
			action := metadataString(event, "action")
			if isPersistencePath(event.FilePath) {
				key := action + ":" + event.FilePath
				if !persistenceChanges[key] {
					result.add(signal("persistence_path_modified", 35, []events.Event{event},
						fmt.Sprintf("%s %s persistence path %s", event.ProcessName, lifecycleVerb(action), event.FilePath)))
					persistenceChanges[key] = true
				}
			}
			if isLogPath(event.FilePath) && isLogTamperAction(action) {
				key := action + ":" + event.FilePath
				if !logTampering[key] {
					result.add(signal("log_tampering", 40, []events.Event{event},
						fmt.Sprintf("%s %s log path %s", event.ProcessName, lifecycleVerb(action), event.FilePath)))
					logTampering[key] = true
				}
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
		case events.TypePrivilegeChange:
			if mutationSucceeded(event) && !privilegeChanges[event.PID] && isSuspiciousPrivilegeContext(event, suspiciousProcessPIDs) {
				result.add(signal("privilege_change_after_suspicious_activity", 35, []events.Event{event},
					fmt.Sprintf("%s called %s after suspicious activity", event.ProcessName, metadataString(event, "syscall"))))
				privilegeChanges[event.PID] = true
			}
		case events.TypeNamespaceChange:
			if mutationSucceeded(event) && !namespaceChanges[event.PID] {
				result.add(signal("namespace_escape_attempt", 40, []events.Event{event},
					fmt.Sprintf("%s called namespace syscall %s", event.ProcessName, metadataString(event, "syscall"))))
				namespaceChanges[event.PID] = true
			}
		case events.TypeProcessAccess:
			if mutationSucceeded(event) {
				key := fmt.Sprintf("%d:%s:%d", event.PID, metadataString(event, "syscall"), metadataUint64(event, "target_pid"))
				if !processAccesses[key] {
					result.add(signal("process_memory_access", 35, []events.Event{event},
						fmt.Sprintf("%s accessed another process with %s", event.ProcessName, metadataString(event, "syscall"))))
					processAccesses[key] = true
				}
			}
		case events.TypeNetworkServer:
			if mutationSucceeded(event) && isUnexpectedNetworkListener(event) {
				key := fmt.Sprintf("%d:%s:%d", event.PID, event.RemoteAddr, event.RemotePort)
				if !networkListeners[key] {
					result.add(signal("unexpected_network_listener", 30, []events.Event{event},
						fmt.Sprintf("%s opened listener %s", event.ProcessName, listenEndpoint(event))))
					networkListeners[key] = true
				}
			}
		case events.TypeKernelTamper:
			key := fmt.Sprintf("%d:%s", event.PID, metadataString(event, "syscall"))
			if !kernelTamper[key] {
				result.add(signal("kernel_tamper_syscall", 50, []events.Event{event},
					fmt.Sprintf("%s called kernel tamper syscall %s", event.ProcessName, metadataString(event, "syscall"))))
				kernelTamper[key] = true
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

func isSensitiveReadPath(path string) bool {
	cleaned := filepath.Clean(path)
	if isSensitiveFile(cleaned) {
		return true
	}
	switch cleaned {
	case "/root/.aws/credentials", "/root/.docker/config.json":
		return true
	default:
		return strings.HasPrefix(cleaned, "/root/.gnupg/") ||
			strings.HasSuffix(cleaned, "/.ssh/id_rsa") ||
			strings.HasSuffix(cleaned, "/.ssh/id_ed25519") ||
			strings.HasSuffix(cleaned, "/.aws/credentials") ||
			strings.HasSuffix(cleaned, "/.docker/config.json") ||
			strings.HasSuffix(cleaned, "/.kube/config") ||
			strings.Contains(cleaned, "/secrets/")
	}
}

func isPersistencePath(path string) bool {
	cleaned := filepath.Clean(path)
	return strings.HasPrefix(cleaned, "/etc/systemd/system/") ||
		strings.HasPrefix(cleaned, "/usr/lib/systemd/system/") ||
		strings.HasPrefix(cleaned, "/etc/cron.") ||
		strings.HasPrefix(cleaned, "/var/spool/cron/") ||
		strings.HasPrefix(cleaned, "/etc/init.d/") ||
		strings.HasPrefix(cleaned, "/root/.ssh/") ||
		strings.HasSuffix(cleaned, "/.ssh/authorized_keys") ||
		strings.HasSuffix(cleaned, "/.bashrc") ||
		strings.HasSuffix(cleaned, "/.profile") ||
		strings.HasSuffix(cleaned, "/.zshrc")
}

func isLogPath(path string) bool {
	cleaned := filepath.Clean(path)
	return cleaned == "/var/log" || strings.HasPrefix(cleaned, "/var/log/")
}

func isLogTamperAction(action string) bool {
	switch action {
	case "unlink", "rename", "truncate":
		return true
	default:
		return false
	}
}

func lifecycleVerb(action string) string {
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

func isSuspiciousPrivilegeContext(event events.Event, suspiciousProcessPIDs map[int]bool) bool {
	return suspiciousProcessPIDs[event.PID] ||
		isShell(event.ProcessName) ||
		isShell(event.ParentProcessName) ||
		isUnexpectedNetworkToolName(event.ProcessName)
}

func isUnexpectedNetworkToolName(name string) bool {
	switch filepath.Base(name) {
	case "nc", "ncat", "netcat", "socat", "telnet":
		return true
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

func isUnexpectedNetworkListener(event events.Event) bool {
	syscall := metadataString(event, "syscall")
	if syscall == "listen" {
		return isShell(event.ProcessName) || isUnexpectedNetworkToolName(event.ProcessName)
	}
	if event.RemotePort == 0 {
		return false
	}
	return isShell(event.ProcessName) ||
		isUnexpectedNetworkToolName(event.ProcessName) ||
		isUnusualListenerPort(event.RemotePort)
}

func isUnusualListenerPort(port int) bool {
	switch port {
	case 53, 80, 443, 8080, 8443:
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

func listenEndpoint(event events.Event) string {
	if event.RemoteAddr == "" || event.RemotePort == 0 {
		return metadataString(event, "syscall")
	}
	return net.JoinHostPort(event.RemoteAddr, strconv.Itoa(event.RemotePort))
}

func connectVerb(event events.Event) string {
	if outcome, _ := event.Metadata["outcome"].(string); outcome == "in_progress" {
		return "started connecting to"
	}
	return "connected to"
}
