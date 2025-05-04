# compiler and flags
CC = gcc
CFLAGS = -Wall -I./picotls/include
LDFLAGS = -lssl -lcrypto

# PicoTLS sources (relatibe paths)
PICOTLS_SRC = picotls/lib/picotls.c picotls/lib/openssl.c picotls/lib/hpke.c

# source files
CLIENT_SRC = client.c
SERVER_SRC = server.c
CLIENT_TARGET = client
SERVER_TARGET = server

all: $(CLIENT_TARGET) $(SERVER_TARGET)

$(CLIENT_TARGET): $(CLIENT_SRC) $(PICOTLS_SRC)
	$(CC) $(CFLAGS) $(CLIENT_SRC) $(PICOTLS_SRC) -o $(CLIENT_TARGET) $(LDFLAGS)

$(SERVER_TARGET): $(SERVER_SRC) $(PICOTLS_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) $(PICOTLS_SRC) -o $(SERVER_TARGET) $(LDFLAGS)

clean:
	rm -f $(CLIENT_TARGET) $(SERVER_TARGET)

.PHONY: all clean
