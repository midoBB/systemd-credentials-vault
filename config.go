package main

import (
	"os"

	"github.com/go-yaml/yaml"
	"github.com/pkg/errors"
)

type Config struct {
	VaultServer    *string `yaml:"vault_server"`    // Address of the Vault server
	SocketLocation string  `yaml:"socket_location"` // The base path in which Unix sockets will be created
	VaultApprole   string  `yaml:"vault_approle"`   // The AppRole being queried
	RoleId         string  `yaml:"role_id"`         // The role ID
	SecretId       string  // The path to the secret ID file NOTE: This is gotten at runtime from CREDENTIALS_DIRECTORY
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

	return config, nil
}
