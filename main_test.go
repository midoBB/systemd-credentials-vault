package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

func setupVaultServer(t *testing.T) (*api.Client, string, string) {
	// Set up a Vault client and create necessary roles and secrets for testing
	config := api.DefaultConfig()
	client, err := api.NewClient(config)

	if err != nil {
		t.Fatalf("failed to create Vault client: %v", err)
	}

	// Enable AppRole auth method
	err = client.Sys().EnableAuthWithOptions("approle-test", &api.EnableAuthOptions{Type: "approle"})
	if err != nil {
		t.Fatalf("failed to enable AppRole auth method: %v", err)
	}

	// Create AppRole
	roleName := "test-role"
	_, err = client.Logical().Write(fmt.Sprintf("auth/approle-test/role/%s", roleName), map[string]interface{}{
		"secret_id_ttl": "1m",
		"token_ttl":     "2m",
		"token_max_ttl": "3m",
	})
	if err != nil {
		t.Fatalf("failed to create AppRole: %v", err)
	}

	// Get Role ID
	secret, err := client.Logical().Read(fmt.Sprintf("auth/approle-test/role/%s/role-id", roleName))
	if err != nil {
		t.Fatalf("failed to read Role ID: %v", err)
	}
	roleID, ok := secret.Data["role_id"].(string)
	if !ok {
		t.Fatalf("role_id not found in response")
	}

	// Create Secret ID
	secret, err = client.Logical().Write(fmt.Sprintf("auth/approle-test/role/%s/secret-id", roleName), nil)
	if err != nil {
		t.Fatalf("failed to create Secret ID: %v", err)
	}
	secretID, ok := secret.Data["secret_id"].(string)
	if !ok {
		t.Fatalf("secret_id not found in response")
	}

	// Create Service Secret
	err = client.Sys().Mount("secrets-test", &api.MountInput{Type: "kv-v2"})
	if err != nil {
		t.Fatalf("failed to create secrets engine: %v", err)
	}
	_, err = client.KVv2("secrets-test").Put(context.Background(), "test-secret", map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatalf("failed to write secret: %v", err)
	}

	return client, roleID, secretID
}

func testRoleId(t *testing.T, conn net.Conn, expected string) error {
	// Send a request for role-id
	_, err := conn.Write([]byte("test-role/role-id"))
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	// Read the response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	response := string(buf[:n])
	if response != expected {
		t.Fatalf("expected role ID %s, got %s", expected, response)
	}

	return nil
}

func testSecretId(t *testing.T, conn net.Conn) error {
	// Send a request for role-id
	_, err := conn.Write([]byte("test-role/secret-id"))
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	// Read the response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	response := string(buf[:n])
	if response == "" {
		t.Fatalf("expected role ID, got %s", response)
	}
	return nil
}

func testKVSecret(t *testing.T, conn net.Conn) error {
	// Send a request for a secret
	_, err := conn.Write([]byte("secrets-test/test-secret/foo"))
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	// Read the response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	response := string(buf[:n])
	if response != "bar" {
		t.Fatalf("expected bar, got %s", response)
	}
	return nil
}

func TestVaultCredentialServer(t *testing.T) {
	// Set up Vault server for testing
	client, roleID, secretID := setupVaultServer(t)
	defer client.Sys().DisableAuth("approle-test")
	defer client.KVv2("secrets-test").Delete(context.Background(), "test-secret")
	defer client.Sys().Unmount("secrets-test")

	// Create temporary Unix socket
	socketPath := "/tmp/test_socket"

	server, err := NewVaultCredentialServer(&Config{
		VaultServer:    &client.CloneConfig().Address,
		VaultApprole:   "approle-test",
		SocketLocation: socketPath,
		RoleId:         roleID,
		SecretIdPath:   secretID,
	})
	if err != nil {
		t.Fatalf("failed to create VaultCredentialServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := server.Run(ctx); err != nil {
			t.Fatalf("server error: %v", err)
		}
		defer server.shutdown()
	}()

	// Give the server some time to start
	time.Sleep(2 * time.Second)

	// Connect to the Unix socket
	defer os.Remove(socketPath)
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to connect to Unix socket: %v", err)
	}
	testRoleId(t, conn, roleID)
	conn.Close()

	conn, err = net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to connect to Unix socket: %v", err)
	}
	testSecretId(t, conn)
	conn.Close()

	conn, err = net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to connect to Unix socket: %v", err)
	}
	testKVSecret(t, conn)
	conn.Close()
}
