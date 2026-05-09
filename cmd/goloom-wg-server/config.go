package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/Pinnss/goloom-server/internal/inbound"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Admin    AdminConfig     `yaml:"admin"`
	Network  NetworkConfig   `yaml:"network"`
	Inbounds []inbound.Spec  `yaml:"inbounds"`
	LogLevel string          `yaml:"log_level"`

	path string
	mu   sync.Mutex
}

type AdminConfig struct {
	Listen string `yaml:"listen"`

	// PublicURL — внешний URL admin-сервера для клиентских ctrl-ws
	// подключений (S2/S3). Используется при генерации connstr'а.
	// Пример: "https://vps.example.com:9443". Если пусто — Listen
	// fallback'ится с https-схемой.
	PublicURL string `yaml:"public_url,omitempty"`

	// CredentialsPath — JSON-файл с username/bcrypt-hash. Если пусто,
	// используется `<dir-of-yaml>/admin.json`. На первом старте файл
	// создаётся с username=admin и случайным паролем — пароль печатается
	// в лог один раз. Меняется через панель; чтобы сбросить, удалить
	// файл и перезапустить сервис.
	CredentialsPath string `yaml:"credentials_path,omitempty"`

	// Token deprecated — для обратной совместимости при миграции.
	// Если в YAML остался — игнорируется с предупреждением в логах.
	Token string `yaml:"token,omitempty"`

	TLS TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Cert            string `yaml:"cert"`
	Key             string `yaml:"key"`
	AutoSelfSigned  bool   `yaml:"auto_self_signed"`
}

type NetworkConfig struct {
	ExternalIface string `yaml:"external_iface"`
	WGSubnetBase  string `yaml:"wg_subnet_base"`
	WGPortBase    int    `yaml:"wg_port_base"`
}

func DefaultConfig() *Config {
	return &Config{
		Admin: AdminConfig{
			Listen: "127.0.0.1:8443",
		},
		Network: NetworkConfig{
			WGSubnetBase: "10.66.0.0/16",
			WGPortBase:   51820,
		},
		LogLevel: "info",
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
	cfg.path = path

	// Авто-провижн bearer'а для VK инбаундов с AcceptClientMeeting=true.
	// Если в yaml оставили пустой ctrl_bearer — генерируем 32-byte hex
	// и сохраняем обратно в файл, чтобы между рестартами он был
	// стабильным.
	bearersGenerated := false
	for i := range cfg.Inbounds {
		vk := cfg.Inbounds[i].VKCalls
		if vk == nil || !vk.AcceptClientMeeting {
			continue
		}
		if vk.CtrlBearer == "" {
			vk.CtrlBearer = randomBearer()
			bearersGenerated = true
		}
	}
	if bearersGenerated {
		if err := cfg.Save(); err != nil {
			return nil, fmt.Errorf("persist generated bearers: %w", err)
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}
	return cfg, nil
}

func randomBearer() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (c *Config) validate() error {
	if c.Admin.Listen != "" {
		if _, _, err := net.SplitHostPort(c.Admin.Listen); err != nil {
			return fmt.Errorf("admin.listen %q: %w", c.Admin.Listen, err)
		}
	}
	if c.Network.WGSubnetBase != "" {
		if _, _, err := net.ParseCIDR(c.Network.WGSubnetBase); err != nil {
			return fmt.Errorf("network.wg_subnet_base %q: %w", c.Network.WGSubnetBase, err)
		}
	}
	for i, in := range c.Inbounds {
		if in.ID == "" {
			return fmt.Errorf("inbounds[%d]: id required", i)
		}
		// Meeting required, кроме VK client-meeting mode где он
		// приходит через ctrl-ws DIAL.
		clientMeeting := in.VKCalls != nil && in.VKCalls.AcceptClientMeeting
		if in.Meeting == "" && !clientMeeting {
			return fmt.Errorf("inbounds[%d] (%s): meeting required", i, in.Tag)
		}
		if in.WGEndpoint == "" {
			return fmt.Errorf("inbounds[%d] (%s): wg_endpoint required", i, in.Tag)
		}
	}
	return nil
}

// Save writes the current config back to disk. Used by the admin panel
// after CRUD operations.
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// SetInbounds replaces the inbound list (called by admin panel on changes).
func (c *Config) SetInbounds(specs []inbound.Spec) {
	c.mu.Lock()
	c.Inbounds = specs
	c.mu.Unlock()
}
