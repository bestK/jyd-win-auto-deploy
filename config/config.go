package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Autoupdater struct {
		Mode   string `yaml:"mode"`
		Server struct {
			Port       string `yaml:"port"`
			Password   string `yaml:"password"`
			UploadPath string `yaml:"upload_path"`
			Ansible    struct {
				HostConfig struct {
					Path         string   `yaml:"path"`
					IncludeGroup []string `yaml:"include_group"`
				} `yaml:"host_config"`
				PlaybookConfig struct {
					Path  string `yaml:"path"`
					Forks int    `yaml:"forks"`
				} `yaml:"playbook_config"`
			} `yaml:"ansible"`
		} `yaml:"server"`
		Watch struct {
			Path       string `yaml:"path"`
			Exclude    string `yaml:"exclude"`
			TimeBefore string `yaml:"time_before"`
			TimeAfter  string `yaml:"time_after"`
		} `yaml:"watch"`
	} `yaml:"autoupdater"`
}

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	return &config, nil
}
