# Makefile for systemd-credentials-vault

# Variables
BINARY_NAME = systemd-credentials-vault
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
CONFIG_DIR = $(PREFIX)/etc
CONFIG_FILE = config.yml

# Build flags
CGO_ENABLED = 1
CC = x86_64-linux-musl-gcc
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -ldflags="-linkmode external -extldflags '-static' -s -w -X main.version=$(VERSION)"

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	CGO_ENABLED=$(CGO_ENABLED) CC=$(CC) \
		go build $(LDFLAGS) -o $(BINARY_NAME) .

# Create example config file
.PHONY: config
config: config.yml

config.yml:
	@if [ ! -f config.yml ]; then \
		cp config.yml.example config.yml; \
		echo "Created config.yml from config.yml.example"; \
	else \
		echo "config.yml already exists"; \
	fi

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME)
	go clean

# Install binary and config
.PHONY: install
install: build
	@mkdir -p $(BINDIR)
	@mkdir -p $(CONFIG_DIR)
	install -m 755 $(BINARY_NAME) $(BINDIR)/$(BINARY_NAME)
	@if [ ! -f $(CONFIG_DIR)/$(CONFIG_FILE) ]; then \
		install -m 644 config.yml.example $(CONFIG_DIR)/$(CONFIG_FILE); \
		echo "Installed example config to $(CONFIG_DIR)/$(CONFIG_FILE)"; \
	else \
		echo "Config file $(CONFIG_DIR)/$(CONFIG_FILE) already exists, skipping"; \
	fi
	@echo "Binary installed to $(BINDIR)/$(BINARY_NAME)"

# Uninstall binary and config
.PHONY: uninstall
uninstall:
	rm -f $(BINDIR)/$(BINARY_NAME)
	@if [ -f $(CONFIG_DIR)/$(CONFIG_FILE) ]; then \
		echo "Config file $(CONFIG_DIR)/$(CONFIG_FILE) left in place"; \
		echo "Remove manually if desired: rm $(CONFIG_DIR)/$(CONFIG_FILE)"; \
	fi
	@echo "Binary removed from $(BINDIR)/$(BINARY_NAME)"

# Test
.PHONY: test
test:
	go test -v ./...

# Run with default config
.PHONY: run
run: build config
	./$(BINARY_NAME) -config config.yml

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build     - Build the binary"
	@echo "  config    - Create config.yml from config.yml.example"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install binary to $(BINDIR) and config to $(CONFIG_DIR)"
	@echo "  uninstall - Remove binary from $(BINDIR)"
	@echo "  test      - Run tests"
	@echo "  run       - Build and run with default config"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX    - Installation prefix (default: /usr/local)"
	@echo "  CC        - C compiler (default: x86_64-linux-musl-gcc)"