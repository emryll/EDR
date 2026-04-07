package main

import (
	"fmt"
	"os"

	yaml "gopkg.in/yaml.v3"
)

//?=================================================================================+
//?  This file is responsible for defining and loading the system configuration.    |
//?=================================================================================+

type Config struct {
	Agent AgentConfig
	Dll   DllConfig
	Etw   EtwConfig
}

type BehaviorRules struct {
	Whitelist BehaviorWhitelist
	Blacklist BehaviorBlacklist
}

// used for yaml parsing straight into map
type AllowDenyRule map[string]bool

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
	TotalScoreFinal  int `yaml:"total_score_final_threshold"`
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

type EtwConfig struct {
	LightweightMode   bool `yaml:"lightweight_mode"`
	HeartbeatInterval int  `yaml:"heartbeat_interval"`
}

type DllConfig struct {
	HeartbeatInterval int `yaml:"heartbeat_interval"`
}

type BehaviorWhitelist struct {
	NoTracking        AllowDenyRule `yaml:"no_tracking"`
	RwxMemory         AllowDenyRule `yaml:"rwx_memory"`
	DllInjection      AllowDenyRule `yaml:"dll_injection"`
	ParentSpoofing    AllowDenyRule `yaml:"parent_spoofing"`
	RemoteExecution   AllowDenyRule `yaml:"remote_execution"`
	UnbackedExecution AllowDenyRule `yaml:"unbacked_execution"`
}

type BehaviorBlacklist struct {
	InternetDownloads AllowDenyRule `yaml:"internet_download"`
	FileCreation      AllowDenyRule `yaml:"file_creation"`
}

func LoadConfig(path string) (Config, error) {
	var config Config
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	err = yaml.Unmarshal(bytes, &config)
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

//TODO: LoadEnums()

func LoadAllowDenyLists(whitelistPath string, blacklistPath string) (BehaviorRules, error) {
	whitelistBytes, err := os.ReadFile(whitelistPath)
	if err != nil {
		return BehaviorRules{}, fmt.Errorf("failed to read file: %v", err)
	}
	blacklistBytes, err := os.ReadFile(blacklistPath)
	if err != nil {
		return BehaviorRules{}, fmt.Errorf("failed to read file: %v", err)
	}

	var rules BehaviorRules
	err = yaml.Unmarshal(whitelistBytes, &rules.Whitelist)
	if err != nil {
		return BehaviorRules{}, fmt.Errorf("failed to unmarshal whitelist: %v", err)
	}
	err = yaml.Unmarshal(blacklistBytes, &rules.Blacklist)
	if err != nil {
		return BehaviorRules{}, fmt.Errorf("failed to unmarshal blacklist: %v", err)
	}
	return rules, nil
}

func (r *BehaviorRules) IsAllowedUnbackedExecution(pid uint32) bool {
	path, err := GetProcessExecutable(pid)
	if err == nil && r.Whitelist.UnbackedExecution[path] {
		return true
	}
	return false
}

func (r *AllowDenyRule) UnmarshalYAML(value *yaml.Node) error {
	var list []string
	if err := value.Decode(&list); err != nil {
		return err
	}

	m := make(map[string]bool, len(list))
	for _, v := range list {
		m[v] = true
	}

	*r = m
	return nil
}
