package main

import (
	"fmt"
	"slices"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type Config struct {
	VaultServer      *string  `yaml:"vault_server"      mapstructure:"vault_server"`   // Address of the Vault server
	VaultMount       string   `yaml:"vault_mount"       mapstructure:"vault_mount"`    // Vault mount path
	VaultApprole     string   `yaml:"vault_approle"     mapstructure:"vault_approle"`  // The AppRole being queried
	RoleId           string   `yaml:"role_id"           mapstructure:"role_id"`        // The role ID
	SecretIdName     string   `yaml:"secret_id_name"    mapstructure:"secret_id_name"` // The path to the secret ID inside $CREDENTIALS_DIRECTORY
	SecretFilePath   string   `yaml:"-"                 mapstructure:"-"`              // The entire constructed path to the secret file inside $CREDENTIALS_DIRECTORY
	ServiceWhitelist []string `yaml:"service_whitelist" mapstructure:"service_whitelist"`
}

func newConfig(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("VAULT")
	v.AutomaticEnv()

	// Set up environment variable mapping
	v.BindEnv("vault_server", "VAULT_SERVER")
	v.BindEnv("vault_mount", "VAULT_MOUNT")
	v.BindEnv("vault_approle", "VAULT_APPROLE")
	v.BindEnv("role_id", "VAULT_ROLE_ID")
	v.BindEnv("secret_id_name", "VAULT_SECRET_ID_NAME")
	v.BindEnv("service_whitelist", "VAULT_SERVICE_WHITELIST")

	err := v.ReadInConfig()
	if err != nil {
		return nil, errors.Wrap(err, "reading config file")
	}

	config := &Config{}
	err = v.Unmarshal(config)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling configuration")
	}

	if slices.Contains(config.ServiceWhitelist, "") {
		return nil, errors.New("service_whitelist cannot be empty")
	}

	fmt.Printf("whitelist: %v\n", config.ServiceWhitelist)

	return config, nil
}
