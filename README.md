# Vault Credential Server

This Go package provides a server for retrieving credentials from HashiCorp Vault. The server listens on a Unix socket and responds to requests for specific credentials.

This was the first time I've ever worked with Golang (and sockets) so please let me know where I could improve my code.

## Features

- Connects to a Vault server to fetch credentials.
- Supports AppRole authentication method.
- Automatically renews Vault tokens before they expire.

## Requirements

- Go 1.22 or higher.
- HashiCorp Vault & AppRole policies allowing access to secrets
- A Unix-based system (due to the use of Unix sockets).

## Configuration

The server requires a configuration file in YAML format. The path to this file should be provided using the `-config` flag when running the server.

Example `config.yml`:
```yaml
vault_server: http://localhost:8200
socket_location: /run/vault-credentials.socket
vault_approle: approle

approle_id: 0000-0000-0000-0000
secret_id_path: /etc/vault/secret_id
```

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/strass/systemd-credentials-vault
   cd vault-credential-server
   ```

2. Build the server:
   ```sh
   go build .
   ```

3. Run the server:
   ```sh
   ./systemd-credentials-vault -config /path/to/config.yml
   ```

## Usage

The server listens on a Unix socket specified in the configuration file. It accepts connections and processes requests in the format:

```
<service>/<credential>
```

or for generic secrets:

```
<mount>/<secret-name>/<key>
```

### Example Requests

#### Via CLI

- To get an AppRole Role ID:
  ```
  echo -n "myservice/role-id" | nc -U /run/vault-credentials.socket
  ```

- To get an AppRole Secret ID:
  ```
  echo -n "myservice/secret-id" | nc -U /run/vault-credentials.socket
  ```

- To get a generic secret:
  ```
  echo -n "secrets/app_secret/password" | nc -U /run/vault-credentials.socket
  ```

#### Via Systemd Unit
LoadCredential=services.%N.secret:/run/vault-credentials.socket

## Acknowledgments

- [Damomurf's systemd-credentials-vault](https://github.com/damomurf/systemd-credentials-vault): Provided a template and initial inspiration for extending this Golang application to work with LoadCredentials
- [Medium article by Umglurf](https://medium.com/@umglurf/using-systemd-credentials-to-pass-secrets-from-hashicorp-vault-to-systemd-services-928f0e804518): Offered a Python script that was integrated into the original repository and guided further development.
- [arianvp's systemd creds](https://github.com/arianvp/systemd-creds) has an example of how LoadCredentials sends its Network Addr