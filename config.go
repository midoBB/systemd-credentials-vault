package main

import (
	"io/ioutil"

	"github.com/go-yaml/yaml"
	"github.com/pkg/errors"
)

type Config struct {
	VaultServer *string `yaml:"vault_server"` // Address of the Vault server
	SocketRoot  string  `yaml:"socket_root"`  // The base path in which Unix sockets will be created
	VaultMount  string  `yaml:"vault_mount"`  // The Secret Mount within vault to look for secrets

	Secrets []Secret `yaml:"secrets"`
}

type Secret struct {
	VaultPath  string `yaml:"vault_path"`  // The path in Vault to the secret value
	SocketPath string `yaml:"socket_path"` // The relative path to SocketRoot where the socket will be created
	Field      string `yaml:"field"`       // The field within the Vault secret to be returned (optional)
}

func newConfig(path string) (*Config, error) {
	config := &Config{}
	content, err := ioutil.ReadFile(path) // the file is inside the local directory
	if err != nil {
		return nil, errors.Wrap(err, "opening config file")
	}

	err = yaml.Unmarshal(content, config)
	if err != nil {
		return nil, errors.Wrap(err, "parsing configuration yaml")
	}

	return config, nil

}
