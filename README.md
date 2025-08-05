# Systemd Vault Credential Server

This Go package provides a server for retrieving credentials from HashiCorp Vault, designed specifically to integrate with `systemd`. The server uses systemd socket activation, validates connecting processes, and responds to requests for specific credentials from whitelisted systemd services.

## Features

- Connects to a Vault server to fetch credentials.
- Supports AppRole authentication method.
- Automatically renews Vault tokens before they expire.
- **Security**: Validates that connecting processes are managed by `systemd`.
- **Security**: Restricts access to a whitelist of `systemd` services.
- **Socket Activation**: Uses systemd socket activation for on-demand service startup.
- Supports fetching generic KV secrets from Vault.

## Requirements

- Go 1.22 or higher.
- A Linux system with `systemd`.
- HashiCorp Vault & AppRole policies allowing access to secrets.

## Configuration

The server requires a configuration file in YAML format. The path to this file should be provided using the `-config` flag when running the server.

Example `config.yml`:

```yaml
vault_server: http://localhost:8200
vault_mount: /secrets
vault_approle: approle

role_id: foo
secret_id_name: secret_id

service_whitelist:
  - example.service
```

**Configuration Options:**

- `vault_server`: Address of the Vault server
- `vault_mount`: Vault mount path for secrets
- `vault_approle`: The AppRole mount path in Vault
- `role_id`: The AppRole role ID for authentication
- `secret_id_name`: Name of the secret ID file in `$CREDENTIALS_DIRECTORY`
- `service_whitelist`: A list of systemd service names (e.g., `my-app.service`) that are permitted to request credentials

### Environment Variable Overrides

All configuration values can be overridden using environment variables with the `VAULT_` prefix:

- `VAULT_SERVER` → `vault_server`
- `VAULT_MOUNT` → `vault_mount`
- `VAULT_APPROLE` → `vault_approle`
- `VAULT_ROLE_ID` → `role_id`
- `VAULT_SECRET_ID_NAME` → `secret_id_name`
- `VAULT_SERVICE_WHITELIST` → `service_whitelist` (comma-separated list)

Environment variables take precedence over configuration file values.

## Installation

### Using Make (Recommended)

1. Clone the repository:

   ```sh
   git clone https://github.com/strass/systemd-credentials-vault
   cd systemd-credentials-vault
   ```

2. Build and install:

   ```sh
   make build
   sudo make install
   ```

   This installs the binary to `/usr/local/bin/systemd-credentials-vault` and creates an example config at `/usr/local/etc/config.yml`.

3. Customize the configuration:

   ```sh
   sudo edit /usr/local/etc/config.yml
   ```

### Custom Installation Path

Use the `PREFIX` variable to install to a different location:

```sh
sudo make install PREFIX=/opt
```

### Available Make Commands

- `make build` - Build the statically-linked binary
- `make config` - Create `config.yml` from example
- `make clean` - Remove build artifacts
- `make install` - Install binary and config files
- `make uninstall` - Remove installed binary
- `make test` - Run tests
- `make run` - Build and run with local config

### Manual Installation

If you prefer to build manually:

```sh
go build .
```

Or for a static build:

```sh
CGO_ENABLED=1 CC=x86_64-linux-musl-gcc \
  go build -ldflags="-linkmode external -extldflags '-static' -s -w"
```

## Usage

The server listens on a Unix socket and only accepts connections from whitelisted systemd-managed processes. It processes requests in the following format:

```
<service>.<credential>.<key | role>
```

### Request Format Details

- **Generic Secret**: `<mount>.<secret-name>.<key>`
- **AppRole Role ID**: `<approle-name>.role-id.<any-string>`
- **AppRole Secret ID**: `<approle-name>.secret-id.<any-string>`
- **Dynamic/Static DB Creds**: `<db-mount>.<'creds'|'static-cred'>.<role-name>`

**Note**: For `role-id` and `secret-id` requests, the third part of the request string is required but ignored by the server.

### Example Requests

#### Via Systemd Unit

Use the `LoadCredential=` directive in your service unit file. The credential name must follow the format described above.

```ini
[Service]
# For a generic secret
LoadCredential=secrets.app_secret.password:/run/vault-credentials.socket

# For a dynamic database credential
LoadCredential=database.creds.my-role:/run/vault-credentials.socket
```

The credential will be available in the `CREDENTIALS_DIRECTORY` environment variable within your service.

## Testing

Supply Vault URL and Token using environment variables: `VAULT_ADDR= VAULT_TOKEN= go test`. The test suite connects to Vault, creates an approle, and retrieves a secret via the agent.

## Acknowledgments

- [Damomurf's systemd-credentials-vault](https://github.com/damomurf/systemd-credentials-vault): Provided a template and initial inspiration for extending this Golang application to be more versatile.
- [Medium article by Umglurf](https://medium.com/@umglurf/using-systemd-credentials-to-pass-secrets-from-hashicorp-vault-to-systemd-services-928f0e804518): Offered a Python script that was integrated into the original repository and guided further development.
- [arianvp's systemd creds](https://github.com/arianvp/systemd-creds) has an example of how LoadCredentials sends its Network Addr
