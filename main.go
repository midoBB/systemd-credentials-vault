package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

type App struct {
	config *Config
	client *api.Client
}

func socketSecretListen(ctx context.Context, client *api.Client, mount *api.KVv2, socketRoot string, secret Secret) {

	sockPath := socketRoot + secret.SocketPath

	err := os.RemoveAll(sockPath)
	if err != nil {
		log.Fatalf("%+v", err)
		return
	}

	log.Printf("Listening on %s for secret path %s", sockPath, secret.VaultPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Print(err)
		return
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		log.Printf("Serving secret value for %s on socket %s", secret.VaultPath, sockPath)

		obj, err := mount.Get(ctx, secret.VaultPath)
		if err != nil {
			log.Fatal(err)
		}
		if secret.Field != "" {
			value := string(secret.Field)
			if _, err = c.Write([]byte(value)); err != nil {
				log.Print(err)
			}
		} else {
			if _, err = c.Write([]byte(fmt.Sprintf("%+v", obj))); err != nil {
				log.Print(err)
			}
		}
		if err = c.Close(); err != nil {
			log.Print(err)
		}
	}

}

func newApp(config *Config) *App {
	return &App{
		config: config,
	}
}

func setupVault(app *App) error {

	apiConfig := api.DefaultConfig()
	if app.config.VaultServer != nil {
		apiConfig.Address = *app.config.VaultServer
	}

	client, err := api.NewClient(apiConfig)
	if err != nil {
		return errors.Wrap(err, "error creating Vault API client")
	}

	app.client = client
	return nil
}

func main() {

	config, err := newConfig("config.yml")
	if err != nil {
		log.Fatalf("Error reading configuration: %+v", err)
	}

	app := newApp(config)

	if err = setupVault(app); err != nil {
		log.Fatalf("Error configuring Vault client: %+v", err)
	}

	kv := app.client.KVv2(config.VaultMount)

	ctx := context.Background()

	// Start a unix socket listener for each configured secret
	for _, secretCfg := range config.Secrets {
		go func(secret Secret) {
			socketSecretListen(ctx, app.client, kv, app.config.SocketRoot, secret)
		}(secretCfg)
	}

	// Register and handle interrupt signals to make sure we clean up
	// the unix sockets nicely.
	signalChan := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signalChan, os.Interrupt)

	go func() {
		<-signalChan
		log.Print("Received interrupt: cleaning up...")
		for _, secret := range config.Secrets {
			sockPath := app.config.SocketRoot + secret.SocketPath

			err := os.Remove(sockPath)
			if err != nil {
				log.Print(err)
			} else {
				log.Printf("Removed socket %s", sockPath)
			}

		}
		close(done)
	}()
	<-done

}
