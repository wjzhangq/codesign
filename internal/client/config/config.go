package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config 客户端配置
type Config struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}

// configDir 返回配置目录路径
func configDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, ".codesign"), nil
}

// configPath 返回配置文件路径
func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load 加载客户端配置
func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// MustLoad 加载配置，失败则返回空配置
func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		return &Config{}
	}
	return cfg
}

// Save 保存配置到文件
func Save(cfg *Config) error {
	dir, err := configDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	path, err := configPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// 原子写入
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return os.Rename(tmpPath, path)
}

// ConfigPath 返回配置文件路径（导出）
func ConfigPath() string {
	path, _ := configPath()
	return path
}
