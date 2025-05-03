#include <arpa/inet.h> //Networking functions like inet_pton(), htons()

#include <netinet/in.h> //Defines Internet address structures.
#include <signal.h> // <csignal> is part of the C++ standard library, use this instead
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>      //Standard I/O functions like printf()
#include <stdlib.h>     //Standard functions like exit()
#include <string.h>     //String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h>     //POSIX OS functions like close()

#include <openssl/ssl.h>     // OpenSSL SSL functions
#include <picotls.h>         // Core PicoTLS definitions
#include <picotls/openssl.h> // OpenSSL backend integration
// Defines the port number (8080) on which the server will listen for
// connections. #define creates a symbolic constant. We can use PORT wherever we
// would like to specify the port number.

#define PORT 8080
#define BUFFER_SIZE 1024

ptls_context_t tls_ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges,
                          .cipher_suites = ptls_openssl_cipher_suites};
// Define encryption key - MUST match between client and server
uint8_t key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                   0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

struct quic_packet {
  int stream_id;
  int length;
  char payload[BUFFER_SIZE];
};

int main() {
  int server_fd, new_socket;
  struct sockaddr_in address, client_addr;
  char buffer[BUFFER_SIZE];

  socklen_t addrlen = sizeof(client_addr);

  server_fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (server_fd < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&address, 0, sizeof(address));

  // bind
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Bind Failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  printf("Server listening on port %d\n", PORT);

  ptls_cipher_suite_t *suite = ptls_openssl_cipher_suites[0];
  if (!suite) {
    perror("Failed to get cipher suite");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  ptls_aead_context_t *aead_decryption =
      ptls_aead_new(suite->aead, suite->hash, 0, key, "key-label");

  if (!aead_decryption) {
    perror("Failed to create AEAD decryption context");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  uint64_t seq = 0;

  while (1) {
    memset(buffer, 0, BUFFER_SIZE);

    int bytes = recvfrom(server_fd, buffer, BUFFER_SIZE, 0,
                         (struct sockaddr *)&client_addr, &addrlen);

    if (bytes < 0) {
      perror("receive failed");
      continue;
    }

    printf("received %d bytes from client\n", bytes);
    uint8_t *decrypted = malloc(BUFFER_SIZE);

    if (decrypted == NULL) {
      perror("Memory allocation failed for decrypted buffer");
      continue;
    }

    // uint8_t decrypted[BUFFER_SIZE];
    // uint8_t aad[8] = {0};
    // uint64_t seq = 0;
    size_t decrypted_len = ptls_aead_decrypt(
        aead_decryption, decrypted, (uint8_t *)buffer, bytes, seq, NULL, 0);

    if (decrypted_len == SIZE_MAX) {
      fprintf(stderr, "Decryption failed (sequence: %lu)\n", seq);

      //  debug, delete later
      for (int i = 0; i < (bytes > 16 ? 16 : bytes); i++) {
        printf("%02x ", (unsigned char)buffer[i]);
      }
      printf("\n");

      free(decrypted);
      continue;
    }

    printf("\n");
    // Check to see if length of decrypted data is less than expected
    if (decrypted_len < 2 * sizeof(int)) {
      printf("Decrypted length: %zu\n", decrypted_len); // Use %zu for size_t

      printf("\nDecryption failed\n");
      free(decrypted);
      continue;
    }

    int stream_id, length;
    memcpy(&stream_id, decrypted, sizeof(int));
    memcpy(&length, decrypted + sizeof(int), sizeof(int));

    // Check for error or if expected decrypted message is less than expected
    if (length < 0 || decrypted_len < 2 * sizeof(int) + (size_t)length) {
      printf("Invalid payload length\n");
      continue;
    }

    struct quic_packet packet;
    packet.stream_id = stream_id;
    packet.length = length;
    memcpy(packet.payload, decrypted + 2 * sizeof(int), length);

    packet.payload[length] = '\0';
    printf("Received packet - Stream ID: %d, Length: %d, Payload: %s\n",
           packet.stream_id, packet.length, packet.payload);

    free(decrypted);
    seq++;
  }
  ptls_aead_free(aead_decryption);
  close(server_fd);
  return 0;
}
