package main

import (
	"os"

	"github.com/go-yaml/yaml"
	"github.com/pkg/errors"
)

type Config struct {
	VaultServer    *string `yaml:"vault_server"`  // Address of the Vault server
	SocketLocation string  `yaml:"socket_root"`   // The base path in which Unix sockets will be created
	VaultMount     string  `yaml:"vault_mount"`   // The Secret Mount within vault to look for secrets
	VaultApprole   string  `yaml:"vault_approle"` // The AppRole being queried

	RoleId       string `yaml:"role_id"`        // The role ID
	SecretIdPath string `yaml:"secret_id_path"` // The secret ID path
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
