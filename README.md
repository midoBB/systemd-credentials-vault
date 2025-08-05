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

- `service_whitelist`: A list of systemd service names (e.g., `my-app.service`) that are permitted to request credentials.

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/strass/systemd-credentials-vault
   cd systemd-credentials-vault
   ```

2. Build the server:

   ```sh
   go build .
   ```

3. Run the server (must be run from within a systemd service):
   ```sh
   ./systemd-credentials-vault -config /path/to/config.yml
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
