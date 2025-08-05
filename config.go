package main

import (
	"fmt"
	"os"
	"slices"

	"github.com/go-yaml/yaml"
	"github.com/pkg/errors"
)

type Config struct {
	VaultServer      *string  `yaml:"vault_server"`   // Address of the Vault server
	VaultApprole     string   `yaml:"vault_approle"`  // The AppRole being queried
	RoleId           string   `yaml:"role_id"`        // The role ID
	SecretIdName     string   `yaml:"secret_id_name"` // The path to the secret ID inside $CREDENTIALS_DIRECTORY
	SecretFilePath   string   `yaml:"-"`              // The entire constructed path to the secret file inside $CREDENTIALS_DIRECTORY
	ServiceWhitelist []string `yaml:"service_whitelist"`
}

func newConfig(path string) (*Config, error) {
	config := &Config{}
	content, err := os.ReadFile(path) // the file is inside the local directory
	if err != nil {
		return nil, errors.Wrap(err, "opening config file")
	}

	err = yaml.Unmarshal(content, config)
	if err != nil {
		return nil, errors.Wrap(err, "parsing configuration yaml")
	}

	if slices.Contains(config.ServiceWhitelist, "") {
		return nil, errors.New("service_whitelist cannot be empty")
	}

	fmt.Printf("whitelist: %v\n", config.ServiceWhitelist)

	return config, nil
}
