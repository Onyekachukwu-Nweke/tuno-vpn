.PHONY: build clean test install uninstall genkeys run-server run-client lint

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOVET=$(GOCMD) vet

# Binary names
BINARY_NAME=tuno
SERVER_BINARY_NAME=tunoserver
CLIENT_BINARY_NAME=tunoclient

# Build directory
BUILD_DIR=build

# Source directories
CMD_DIR=cmd
MAIN_PACKAGE=github.com/Onyekachukwu-Nweke/tuno-vpn

# Build flags
LDFLAGS=-ldflags "-s -w"

# Install directory
INSTALL_DIR=/usr/local/bin

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    TUN_GROUP=root
else ifeq ($(UNAME_S),Darwin)
    TUN_GROUP=wheel
else
    TUN_GROUP=root
endif

all: test build

# Build the project
build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)/$(CMD_DIR)/tunocli
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(SERVER_BINARY_NAME) $(MAIN_PACKAGE)/$(CMD_DIR)/tunoserver
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(CLIENT_BINARY_NAME) $(MAIN_PACKAGE)/$(CMD_DIR)/tunoclient

# Clean the project
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Run tests
test:
	$(GOTEST) -v ./...

# Run static analysis
lint:
	golangci-lint run ./...

# Update Go modules
deps:
	$(GOMOD) tidy

# Install the binaries
install: build
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	install -m 755 $(BUILD_DIR)/$(SERVER_BINARY_NAME) $(INSTALL_DIR)/$(SERVER_BINARY_NAME)
	install -m 755 $(BUILD_DIR)/$(CLIENT_BINARY_NAME) $(INSTALL_DIR)/$(CLIENT_BINARY_NAME)
	mkdir -p /etc/tuno
	cp -n configs/server.yaml /etc/tuno/server.yaml || true
	cp -n configs/client.yaml /etc/tuno/client.yaml || true
	@echo "Creating TUN device setup script..."
	@echo "#!/bin/bash" > $(BUILD_DIR)/setup-tun.sh
	@echo "ip tuntap add dev tun0 mode tun" >> $(BUILD_DIR)/setup-tun.sh
	@echo "ip link set tun0 up" >> $(BUILD_DIR)/setup-tun.sh
	@echo "chmod 0660 /dev/net/tun" >> $(BUILD_DIR)/setup-tun.sh
	@echo "chgrp $(TUN_GROUP) /dev/net/tun" >> $(BUILD_DIR)/setup-tun.sh
	install -m 755 $(BUILD_DIR)/setup-tun.sh $(INSTALL_DIR)/tuno-setup-tun

# Uninstall the binaries
uninstall:
	rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	rm -f $(INSTALL_DIR)/$(SERVER_BINARY_NAME)
	rm -f $(INSTALL_DIR)/$(CLIENT_BINARY_NAME)
	rm -f $(INSTALL_DIR)/tuno-setup-tun

# Generate TLS certificates for testing
genkeys:
	mkdir -p ~/.tuno
	openssl req -x509 -newkey rsa:4096 -keyout ~/.tuno/server.key -out ~/.tuno/server.crt -days 365 -nodes -subj "/CN=TunoVPN"
	cp ~/.tuno/server.crt ~/.tuno/ca.crt
	openssl req -newkey rsa:4096 -keyout ~/.tuno/client.key -out ~/.tuno/client.csr -nodes -subj "/CN=TunoVPNClient"
	openssl x509 -req -in ~/.tuno/client.csr -CA ~/.tuno/ca.crt -CAkey ~/.tuno/server.key -out ~/.tuno/client.crt -days 365 -CAcreateserial
	chmod 600 ~/.tuno/*.key

# Run server (as root, required for TUN device)
run-server: build
	sudo $(BUILD_DIR)/$(BINARY_NAME) server

# Run client (as root, required for TUN device)
run-client: build
	sudo $(BUILD_DIR)/$(BINARY_NAME) client