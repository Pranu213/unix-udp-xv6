# Makefile for S.H.A.M. Protocol Implementation
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lcrypto

# Source files
SERVER_SRC = server.c
CLIENT_SRC = client.c
HEADERS = sham.h

# Target executables
SERVER = server
CLIENT = client

.PHONY: all clean help test debug install_deps test_file

# Default target - build both client and server
all: $(SERVER) $(CLIENT)

$(SERVER): $(SERVER_SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRC) $(LDFLAGS)

$(CLIENT): $(CLIENT_SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRC) $(LDFLAGS)

# Create a test file for demonstration
test_file:
	@echo "Creating test file for demonstration..."
	@head -c 10240 /dev/urandom > test_file.bin
	@echo "Created test_file.bin (10KB)"

# Run a quick test (you need two terminals)
test: all test_file
	@echo "Starting test with S.H.A.M. implementation..."
	@echo "Run the following commands in separate terminals:"
	@echo "Terminal 1: ./server 8080"
	@echo "Terminal 2: ./client 127.0.0.1 8080 test_file.bin received.bin"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: all

# Clean build artifacts
clean:
	rm -f $(SERVER) $(CLIENT)
	rm -f *.o
	rm -f test_file.bin received_* output.bin
	rm -f server_log.txt client_log.txt

# Show help
help:
	@echo "S.H.A.M. Protocol Implementation Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all       - Build server and client (default)"
	@echo "  test_file - Create a 10KB random test file"
	@echo "  test      - Show test instructions"
	@echo "  debug     - Build with debug symbols"
	@echo "  clean     - Remove build artifacts and test files"
	@echo "  help      - Show this help message"

# Install dependencies (Ubuntu/Debian)
install_deps:
	@echo "Installing dependencies for Ubuntu/Debian..."
	sudo apt-get update
	sudo apt-get install -y build-essential libssl-dev
