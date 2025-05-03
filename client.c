#include <arpa/inet.h>       //Networking functions like inet_pton(), htons()
#include <netinet/in.h>      //Defines Internet address structures.
#include <openssl/ssl.h>     // OpenSSL SSL functions
#include <picotls.h>         // Core PicoTLS definitions
#include <picotls/openssl.h> // OpenSSL backend integration
#include <pthread.h>
#include <signal.h> // <csignal> is part of the C++ standard library, use this instead
#include <stddef.h>
#include <stdio.h>      //Standard I/O functions like printf()
#include <stdlib.h>     //Standard functions like exit()
#include <string.h>     //String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h>     //POSIX OS functions like close()

#define PORT 8080
#define BUFFER_SIZE 1024

uint8_t key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                   0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

// TLS context configuration
ptls_context_t tls_ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges,
                          .cipher_suites = ptls_openssl_cipher_suites};

static int global_stream_id = 0;
pthread_mutex_t stream_id_mutex = PTHREAD_MUTEX_INITIALIZER;

// Keep track of the stream ID for multiplexing
int allocate_client_stream_id() {
  pthread_mutex_lock(&stream_id_mutex);
  int id = ++global_stream_id;
  pthread_mutex_unlock(&stream_id_mutex);
  return id;
}

int main() {
  int sock_fd;
  char server_ip_addr[] = "127.0.0.1";

  struct sockaddr_in server_addr;
  socklen_t addr_len = sizeof(server_addr);

  // Create UDP socket
  sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sock_fd < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  // Set up server address
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(PORT);

  if (inet_pton(AF_INET, server_ip_addr, &server_addr.sin_addr) <= 0) {
    perror("Invalid server IP address");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    perror("Connection failed");
    exit(EXIT_FAILURE);
  }

  // Create TLS object
  ptls_t *tls = ptls_new(&tls_ctx, 1);
  if (tls == NULL) {
    fprintf(stderr, "Failed to create ptls object");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  // Set up AEAD encryption with key
  ptls_cipher_suite_t *suite = tls_ctx.cipher_suites[0];
  if (!suite) {
    fprintf(stderr, "Failed to get cipher suite\n");
    ptls_free(tls);
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  ptls_aead_context_t *aead_encryption =
      ptls_aead_new(suite->aead, suite->hash, 1, key, "key-label");

  if (aead_encryption == NULL) {
    fprintf(stderr, "Failed to create AEAD context");
    ptls_free(tls);
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  int stream_id = allocate_client_stream_id();
  const char *message = "Hello";
  size_t message_len = strlen(message);
  printf("Sending message '%s' on stream %d\n", message, stream_id);

  // Serialize packet: stream_id, length, payload
  uint8_t plain[BUFFER_SIZE];
  memset(plain, 0, BUFFER_SIZE);

  size_t plain_len = 2 * sizeof(int) + message_len;
  memcpy(plain, &stream_id, sizeof(int));
  int payload_len = message_len;
  memcpy(plain + sizeof(int), &payload_len, sizeof(int));
  memcpy(plain + 2 * sizeof(int), message, message_len);

  printf("Plain packet size: %zu bytes\n", plain_len);
  printf("Plain packet structure: stream_id=%d, length=%d, message='%s'\n",
         stream_id, payload_len, message);

  // Encrypt Message
  // uint8_t encrypted[BUFFER_SIZE];
  size_t tag_size = suite->aead->tag_size;
  size_t encrypted_capacity = plain_len + tag_size;

  uint8_t *encrypted = malloc(encrypted_capacity);

  if (encrypted == NULL) {
    perror("Memory allocation failed for encrypted buffer");
    ptls_aead_free(aead_encryption);
    ptls_free(tls);
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  memset(encrypted, 0, encrypted_capacity);

  size_t encrypted_len = ptls_aead_encrypt(aead_encryption, encrypted, plain,
                                           plain_len, 0, NULL, 0);

  if (encrypted_len == 0) {
    fprintf(stderr, "Encryption failed");
    free(encrypted);
    ptls_aead_free(aead_encryption);
    ptls_free(tls);
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  // Send encrypted packet
  ssize_t sent = send(sock_fd, encrypted, encrypted_len, 0);

  if (sent < 0) {
    perror("sendto failed");
    free(encrypted);
    ptls_aead_free(aead_encryption);
    close(sock_fd);
    exit(EXIT_FAILURE);
  }
  printf("Sent %zd bytes to server\n", sent);

  ptls_aead_free(aead_encryption);
  ptls_free(tls);
  close(sock_fd);
  return 0;
}
