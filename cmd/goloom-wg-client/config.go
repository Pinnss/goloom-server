package main

import (
	"fmt"
	"net"
	"os"

	"github.com/Pinnss/goloom-server/internal/connstr"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Meeting     string `yaml:"meeting"`
	DisplayName string `yaml:"display_name"`
	ListenAddr  string `yaml:"listen_addr"`
	LogLevel    string `yaml:"log_level"`
}

func DefaultConfig() *Config {
	return &Config{
		DisplayName: "",
		ListenAddr:  "127.0.0.1:51820",
		LogLevel:    "info",
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Meeting == "" {
		return nil, fmt.Errorf("meeting URL is required")
	}
	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		return nil, fmt.Errorf("listen_addr %q: %w", cfg.ListenAddr, err)
	}
	return cfg, nil
}

func ConfigFromConnStr(s string) (*Config, error) {
	p, err := connstr.Decode(s)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	cfg.Meeting = p.Meeting
	if p.DisplayName != "" {
		cfg.DisplayName = p.DisplayName
	}
	return cfg, nil
}
