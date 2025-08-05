package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type VaultCredentialServer struct {
	socket        net.Listener
	client        *api.Client
	config        *Config
	socketAddress string
}

func NewVaultCredentialServer(config *Config) (*VaultCredentialServer, error) {
	apiConfig := api.DefaultConfig()
	if config.VaultServer != nil {
		apiConfig.Address = *config.VaultServer
	}

	credsDir, ok := os.LookupEnv("CREDENTIALS_DIRECTORY")
	if !ok {
		return nil, errors.New(
			"CREDENTIALS_DIRECTORY not provided, This program is meant to be run inside a systemd service unit context",
		)
	}
	if _, err := os.Stat(credsDir); os.IsNotExist(err) {
		return nil, errors.Errorf("CREDENTIALS_DIRECTORY does not exist: %s", credsDir)
	}

	config.SecretFilePath = filepath.Join(credsDir, config.SecretIdName)

	client, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, errors.Wrap(err, "error creating Vault API client")
	}

	socketAddress := config.SocketLocation
	if socketAddress == "" {
		return nil, errors.New("Socket root not provided")
	}

	listener, err := net.Listen("unix", socketAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %v", err)
	}

	return &VaultCredentialServer{
		config:        config,
		client:        client,
		socket:        listener,
		socketAddress: socketAddress,
	}, nil
}

func (vcs *VaultCredentialServer) Run(ctx context.Context) error {
	// Start the main server loop
	g, ctx := errgroup.WithContext(ctx)

	defer vcs.socket.Close()

	g.Go(func() error {
		return vcs.startServer(ctx)
	})

	// Perform Vault login and token renewal
	g.Go(func() error {
		return vcs.vaultLogin(ctx)
	})

	return g.Wait()
}

func (vcs *VaultCredentialServer) startServer(ctx context.Context) error {
	for {
		conn, err := vcs.socket.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("failed to accept connection: %v", err)
			}
		}
		go vcs.handleConnection(ctx, conn)
	}
}

func (vcs *VaultCredentialServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ucred, ucredErr := getUcred(conn)
	if ucredErr != nil {
		log.Printf("failed to get ucred: %v", ucredErr)
		return
	}

	// get the caller unit name and cross check it with the whitelisted services
	pInfo, pInfoErr := getProcessSystemdInfo(ucred.Pid)
	if pInfoErr != nil {
		log.Printf("failed to get process systemd info: %v", pInfoErr)
		return
	}

	if pInfo.Type == ProcessTypeUnknown {
		log.Printf("SECURITY: Rejected non-systemd process - PID: %d, UID: %d",
			ucred.Pid, ucred.Uid)
		return
	}

	if !slices.Contains(vcs.config.ServiceWhitelist, pInfo.ServiceName) {
		log.Printf("SECURITY: Rejected non-whitelisted service - %s", pInfo.ServiceName)
		return
	}
	unixAddr, ok := conn.RemoteAddr().(*net.UnixAddr)

	if !ok {
		log.Printf("Failed to get peer name")
		return
	}
	log.Print("---")
	log.Printf("Connection from: %s", unixAddr.Name)

	var value string
	if unixAddr.Name == "@" {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("failed to read from connection: %v", err)
			return
		}

		value = string(buf[:n])
	} else {
		_, credential, ok := parsePeerName(unixAddr.Name)
		if !ok {
			log.Printf("Failed to parse peer name: %s", unixAddr.Name)
			return
		}

		value = credential
	}

	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		log.Printf("Invalid credential request: %s", value)
		return
	}
	service, credential, roleNameOrKey := parts[0], parts[1], parts[2]

	log.Printf("Request - %s", value)
	var err error
	switch credential {
	case "role-id":
		value, err = vcs.getVaultAppRoleID(service)
	case "secret-id":
		value, err = vcs.getVaultAppRoleSecretID(service)
	// How do I combine these cases?
	case "creds":
		mount, credType, roleName := service, credential, roleNameOrKey
		value, err = vcs.createVaultDatabaseCreds(mount, credType, roleName)
	case "static-cred":
		mount, credType, roleName := service, credential, roleNameOrKey
		value, err = vcs.createVaultDatabaseCreds(mount, credType, roleName)
	default:
		mount, secretName, key := service, credential, roleNameOrKey
		value, err = vcs.getVaultServerSecret(mount, secretName, key)
	}

	if err != nil {
		log.Printf("failed to retrieve credential: %v", err)
		return
	}

	if _, err := conn.Write([]byte(value)); err != nil {
		log.Printf("failed to write credential to connection: %v", err)
	}
}

// parsePeerName parses the peer name of a unix socket connection as per the
// documentation of LoadCredential=
func parsePeerName(s string) (string, string, bool) {
	// NOTE: Apparently in Go abstract socket names are prefixed with @ instead of 0x00
	matches := regexp.MustCompile("^@.*/unit/(.*)/(.*)$").FindStringSubmatch(s)
	if matches == nil {
		return "", "", false
	}
	unitName := matches[1]
	credID := matches[2]

	return unitName, credID, true
}

func (vcs *VaultCredentialServer) vaultLogin(ctx context.Context) error {
	roleID, secretID := vcs.getVaultCredentials()

	if roleID == "" {
		return errors.New("Role ID not provided")
	}

	appRoleAuth, err := approle.NewAppRoleAuth(roleID, secretID)
	if err != nil {
		return fmt.Errorf("failed to create AppRoleAuth: %v", err)
	}

	secret, err := vcs.client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return fmt.Errorf("failed to log in: %v", err)
	}

	vcs.client.SetToken(secret.Auth.ClientToken)

	leaseDuration := secret.Auth.LeaseDuration
	time.AfterFunc(time.Duration(leaseDuration)*time.Second*7/10, func() {
		if err := vcs.vaultLogin(ctx); err != nil {
			fmt.Printf("Error logging in: %v\n", err)
		}
	})

	return nil
}

func (vcs *VaultCredentialServer) getVaultAppRoleID(service string) (string, error) {
	path := fmt.Sprintf("auth/%s/role/%s/role-id", vcs.config.VaultApprole, service)
	secret, err := vcs.client.Logical().Read(path)
	if err != nil {
		return "", fmt.Errorf("failed to get AppRole ID: %v", err)
	}

	roleID, ok := secret.Data["role_id"].(string)
	if !ok {
		return "", errors.New("role_id not found in response")
	}

	return roleID, nil
}

func (vcs *VaultCredentialServer) getVaultAppRoleSecretID(service string) (string, error) {
	path := fmt.Sprintf("auth/%s/role/%s/secret-id", vcs.config.VaultApprole, service)

	secret, err := vcs.client.Logical().Write(path, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get AppRole Secret ID: %v", err)
	}

	value, ok := secret.Data["secret_id"].(string)
	if !ok {
		return "", fmt.Errorf("AppRole Secret ID for %s not found in secret data", service)
	}

	return value, nil
}

func (vcs *VaultCredentialServer) getVaultServerSecret(
	mount, secretName string,
	key string,
) (string, error) {
	secret, err := vcs.client.KVv2(mount).Get(context.Background(), secretName)
	if err != nil {
		return "", fmt.Errorf("failed to get service secret: %v", err)
	}

	value, ok := secret.Raw.Data["data"].(map[string]any)[key].(string)
	if !ok {
		return "", fmt.Errorf("credential %s not found in secret data", key)
	}
	return value, nil
}

func (vcs *VaultCredentialServer) createVaultDatabaseCreds(
	mount string,
	credType string,
	role string,
) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", mount, credType, role)
	secret, err := vcs.client.Logical().Read(path)
	if err != nil {
		return "", fmt.Errorf("failed to create auth for %v: %v", mount, err)
	}

	if secret == nil {
		return "", fmt.Errorf("failed to retrieve auth for %v", mount)
	}

	value, err := json.Marshal(secret.Data)
	if err != nil {
		return "", fmt.Errorf("could not read secret data: %v", role)
	}
	return string(value), nil
}

func (vcs *VaultCredentialServer) getVaultCredentials() (string, *approle.SecretID) {
	secretID := &approle.SecretID{FromFile: vcs.config.SecretFilePath}

	return string(vcs.config.RoleId), secretID
}

func (vcs *VaultCredentialServer) shutdown() error {
	if err := vcs.socket.Close(); err != nil {
		return fmt.Errorf("failed to close socket: %v", err)
	}
	return nil
}


var configPath = flag.String("config", "config.yml", "YAML Configuration file.")

func main() {
	flag.Parse()
	if !checkSystemd() {
		log.Fatal("This program is meant to be run inside a systemd service unit context")
	}

	config, err := newConfig(*configPath)
	if err != nil {
		log.Fatalf("Error reading configuration: %+v", err)
	}
	server, err := NewVaultCredentialServer(config)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal: %s, shutting down...", sig)
		context.CancelFunc(cancel)()
		if err := server.shutdown(); err != nil {
			log.Printf("error during shutdown: %v", err)
		}
		cancel()
	}()

	if err := server.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("server error: %v", err)
	}

	log.Println("Server shutdown complete")
}
