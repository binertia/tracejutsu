package detect

type RuleDefinition struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	ScoreImpact int      `json:"score_impact"`
	Collectors  []string `json:"collectors"`
}

func RuleDefinitions() []RuleDefinition {
	return []RuleDefinition{
		{
			RuleID:      "web_process_spawned_shell",
			Description: "A web-facing parent process spawned a shell.",
			ScoreImpact: 30,
			Collectors:  []string{"execve"},
		},
		{
			RuleID:      "shell_downloaded_file",
			Description: "A shell launched a download utility and selected an output path.",
			ScoreImpact: 20,
			Collectors:  []string{"execve"},
		},
		{
			RuleID:      "tmp_file_made_executable",
			Description: "A process added execute permission to a file under a temporary path.",
			ScoreImpact: 20,
			Collectors:  []string{"chmod"},
		},
		{
			RuleID:      "recently_downloaded_binary_executed",
			Description: "A process executed a file that was recently downloaded in the same process tree.",
			ScoreImpact: 30,
			Collectors:  []string{"execve", "file_write"},
		},
		{
			RuleID:      "downloaded_binary_connected_outbound",
			Description: "A recently downloaded executable opened an outbound connection.",
			ScoreImpact: 35,
			Collectors:  []string{"execve", "file_write", "connect"},
		},
		{
			RuleID:      "suspicious_reverse_shell_pattern",
			Description: "A shell connected to an unusual outbound endpoint.",
			ScoreImpact: 50,
			Collectors:  []string{"execve", "connect"},
		},
		{
			RuleID:      "package_manager_spawned_shell",
			Description: "A package manager spawned an interactive shell.",
			ScoreImpact: 5,
			Collectors:  []string{"execve"},
		},
		{
			RuleID:      "sensitive_file_access",
			Description: "A process wrote a sensitive file path.",
			ScoreImpact: 35,
			Collectors:  []string{"file_write"},
		},
		{
			RuleID:      "crypto_miner_process_name",
			Description: "A process name matched a known crypto-miner pattern.",
			ScoreImpact: 35,
			Collectors:  []string{"execve"},
		},
		{
			RuleID:      "unexpected_network_tool_execution",
			Description: "A suspicious parent process executed a common network utility.",
			ScoreImpact: 20,
			Collectors:  []string{"execve"},
		},
		{
			RuleID:      "sensitive_file_read",
			Description: "A process read a sensitive credential or system file.",
			ScoreImpact: 25,
			Collectors:  []string{"sensitive_read"},
		},
		{
			RuleID:      "persistence_path_modified",
			Description: "A process changed a common persistence path.",
			ScoreImpact: 35,
			Collectors:  []string{"file_lifecycle"},
		},
		{
			RuleID:      "log_tampering",
			Description: "A process removed or renamed a log path.",
			ScoreImpact: 40,
			Collectors:  []string{"file_lifecycle"},
		},
		{
			RuleID:      "privilege_change_after_suspicious_activity",
			Description: "A suspicious process attempted a privilege-changing syscall.",
			ScoreImpact: 35,
			Collectors:  []string{"privilege_change"},
		},
		{
			RuleID:      "namespace_escape_attempt",
			Description: "A process attempted namespace creation or reassociation.",
			ScoreImpact: 40,
			Collectors:  []string{"namespace_change"},
		},
		{
			RuleID:      "process_memory_access",
			Description: "A process accessed another process with a memory or tracing syscall.",
			ScoreImpact: 35,
			Collectors:  []string{"process_access"},
		},
		{
			RuleID:      "unexpected_network_listener",
			Description: "A process opened an unexpected listening socket.",
			ScoreImpact: 30,
			Collectors:  []string{"network_server"},
		},
		{
			RuleID:      "kernel_tamper_syscall",
			Description: "A process called a syscall commonly used for kernel tampering.",
			ScoreImpact: 50,
			Collectors:  []string{"kernel_tamper"},
		},
	}
}

func RuleIDs() []string {
	definitions := RuleDefinitions()
	ids := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		ids = append(ids, definition.RuleID)
	}
	return ids
}
