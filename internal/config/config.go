package config

type Config struct {
	LocalOnly bool      `json:"local_only"`
	LLM       LLMConfig `json:"llm"`
}

type LLMConfig struct {
	Endpoint            string `json:"endpoint"`
	Model               string `json:"model"`
	Timeout             string `json:"timeout"`
	RemoteEndpointOptIn bool   `json:"remote_endpoint_opt_in"`
	PreserveRawResponse bool   `json:"preserve_raw_response"`
}

func Default() Config {
	return Config{
		LocalOnly: true,
		LLM: LLMConfig{
			Endpoint:            "http://127.0.0.1:8080",
			Model:               "local-model",
			Timeout:             "5m",
			RemoteEndpointOptIn: false,
			PreserveRawResponse: false,
		},
	}
}
