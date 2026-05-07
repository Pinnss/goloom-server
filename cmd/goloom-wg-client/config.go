package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Pinnss/goloom-server/pkg/wgclient"
	"gopkg.in/yaml.v3"
)

// errUsage signals "no input provided" — main.go turns it into a
// usage banner via log.Fatalf.
var errUsage = errors.New("usage: goloom-wg-client -connect goloom://... | -config path.yaml [-listen 127.0.0.1:51820]")

// yamlConfig mirrors the on-disk YAML schema. Stays in the cmd
// package so the wgclient library doesn't pull a YAML dependency for
// callers (e.g. the GUI) that build the Config struct programmatically.
type yamlConfig struct {
	Transport          string `yaml:"transport,omitempty"`
	Meeting            string `yaml:"meeting,omitempty"`
	LiveKitRoomURL     string `yaml:"livekit_room_url,omitempty"`
	LiveKitAccessToken string `yaml:"livekit_access_token,omitempty"`
	LiveKitCookies     string `yaml:"livekit_cookies,omitempty"`
	DisplayName        string `yaml:"display_name,omitempty"`
	ListenAddr         string `yaml:"listen_addr,omitempty"`
	LogLevel           string `yaml:"log_level,omitempty"` // accepted for back-compat, currently unused
}

func loadYAMLConfig(path string) (wgclient.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return wgclient.Config{}, fmt.Errorf("read config: %w", err)
	}
	var y yamlConfig
	if err := yaml.Unmarshal(data, &y); err != nil {
		return wgclient.Config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg := wgclient.Config{
		Transport:          y.Transport,
		Meeting:            y.Meeting,
		LiveKitRoomURL:     y.LiveKitRoomURL,
		LiveKitAccessToken: y.LiveKitAccessToken,
		LiveKitCookies:     y.LiveKitCookies,
		DisplayName:        y.DisplayName,
		ListenAddr:         y.ListenAddr,
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:51820"
	}
	if err := cfg.Validate(); err != nil {
		return wgclient.Config{}, err
	}
	return cfg, nil
}

// isAdmin returns true when the process can perform privileged
// operations (route table edits). The check is heuristic — we try to
// open a path that requires Administrator on Windows. Linux/macOS get
// a permissive true since the route manager is currently a no-op
// there anyway.
func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}
