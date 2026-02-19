package main

//?=================================================================================+
//?  This file is responsible for defining and loading the system configuration.    |
//?=================================================================================+

type Config struct {
	Agent AgentConfig
	//	Dll DllConfig
	//	Etw EtwConfig
}

type AgentConfig struct {
	UseDriver          bool   `yaml:"use_driver"`
	WorkerPoolSize     int    `yaml:"worker_pool_size"`
	MalwareBazaarKey   string `yaml:"malware_bazaar_key"`
	YaraInstallPath    string `yaml:"yara_install_path"`
	OpenSslInstallPath string `yaml:"open_ssl_install_path"`

	//TODO: agent path?
	//TODO: dll path?

	LogLevel      int    `yaml:"log_level"`
	AlertLogPath  string `yaml:"alert_log_path"`
	EventLogPath  string `yaml:"event_log_path"`
	DetectLogPath string `yaml:"detection_log_path"`

	PatternDir string `yaml:"patterns_dir"`
	YaraDir    string `yaml:"yara_dir"`
	MalapiDir  string `yaml:"malapi_dir"`
	MalapiPath string `yaml:"malapi_path"`

	TotalScoreAlert  int `yaml:"total_score_alert_threshold"`
	TotalScoreFinal  int `yaml:"total_score_alert_threshold"`
	StaticScoreAlert int `yaml:"static_score_alert_threshold"`
	StaticScoreFinal int `yaml:"static_score_final_threshold"`
	RansomScoreAlert int `yaml:"ransom_score_alert_threshold"`
	RansomScoreFinal int `yaml:"ransom_score_final_threshold"`

	MemoryScanInterval  int `yaml:"memory_scan_interval"`
	ThreadScanInterval  int `yaml:"thread_scan_interval"`
	HandleScanInterval  int `yaml:"handle_scan_interval"`
	NetworkScanInterval int `yaml:"network_scan_interval"`
	HeartbeatInterval   int `yaml:"heartbeat_interval"`
	HeartbeatMaxDelay   int `yaml:"max_heartbeat_delay"`
}

func LoadConfig() Config {
	var config Config
	//TODO: find agent config
	//TODO: read agent config
	//TODO: find dll config
	//TODO: read dll config
	//TODO: find etw config
	//TODO: read etw config
	return config
}

//TODO: LoadEnums()
