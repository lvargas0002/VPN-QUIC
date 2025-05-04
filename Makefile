# compiler and flags
CC = gcc
CFLAGS = -I/usr/local/opt/openssl/include -I./picotls/include
LDFLAGS = -L/usr/local/opt/openssl/lib -L./picotls -lssl -lcrypto -lpicotls-core -lpicotls-openssl

# source files
CLIENT_SRC = client.c
SERVER_SRC = server.c
CLIENT_TARGET = client
SERVER_TARGET = server

#test files
MINIMAL_PICO_TEST = picoTest.c
MINIMAL_PICO_TARGET = picoTest

all: $(CLIENT_TARGET) $(SERVER_TARGET) $(MINIMAL_PICO_TARGET)

$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC) $(CLIENT_SRC) -o $(CLIENT_TARGET) $(CFLAGS) $(LDFLAGS)

$(SERVER_TARGET): $(SERVER_SRC)
	$(CC) $(SERVER_SRC) -o $(SERVER_TARGET) $(CFLAGS) $(LDFLAGS)

$(MINIMAL_PICO_TARGET): $(MINIMAL_PICO_TEST)
	$(CC) $(MINIMAL_PICO_TEST) -o $(MINIMAL_PICO_TARGET) $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(CLIENT_TARGET) $(SERVER_TARGET) $(MINIMAL_PICO_TARGET)

.PHONY: all clean
