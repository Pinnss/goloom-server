package main

import (
	"fmt"
	"net"
	"os"

	"github.com/Pinnss/goloom-server/internal/connstr"
	"gopkg.in/yaml.v3"
)

// Config is the unified client config — now transport-agnostic.
//
// For Telemost-based inbounds, only Meeting + the common fields matter;
// LiveKit fields stay empty. For WB Stream / LiveKit inbounds, set
// Transport="livekit-wb-stream" plus the corresponding LiveKit*
// credentials. Empty Transport falls back to Telemost.
type Config struct {
	// Transport selects the SFU implementation. Empty defaults to
	// telemost. See [sfu.Kind] for valid values.
	Transport string `yaml:"transport,omitempty"`

	// Meeting is the Telemost meeting URL. Required when Transport ==
	// "telemost" (or empty); ignored otherwise.
	Meeting string `yaml:"meeting,omitempty"`

	// LiveKit credentials for Transport == "livekit-wb-stream".
	// LiveKitRoomURL is the public room link
	// (https://stream.wb.ru/room/<id>); LiveKitAccessToken /
	// LiveKitCookies come from the admin webview-auth bundle.
	LiveKitRoomURL     string `yaml:"livekit_room_url,omitempty"`
	LiveKitAccessToken string `yaml:"livekit_access_token,omitempty"`
	LiveKitCookies     string `yaml:"livekit_cookies,omitempty"`

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
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr %q: %w", c.ListenAddr, err)
	}
	switch c.Transport {
	case "", "telemost":
		if c.Meeting == "" {
			return fmt.Errorf("meeting URL is required for transport=telemost")
		}
	case "livekit-wb-stream":
		if c.LiveKitRoomURL == "" {
			return fmt.Errorf("livekit_room_url is required for transport=livekit-wb-stream")
		}
		if c.LiveKitAccessToken == "" {
			return fmt.Errorf("livekit_access_token is required (run admin webview-auth flow)")
		}
	default:
		return fmt.Errorf("unknown transport %q", c.Transport)
	}
	return nil
}

func ConfigFromConnStr(s string) (*Config, error) {
	p, err := connstr.Decode(s)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	// connstr currently only carries Telemost-style fields. WB Stream
	// inbounds are set up via the admin panel and their Config is
	// distributed as a YAML file (or an extended connstr spec — TBD).
	cfg.Meeting = p.Meeting
	if p.DisplayName != "" {
		cfg.DisplayName = p.DisplayName
	}
	return cfg, nil
}
