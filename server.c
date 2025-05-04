#include <arpa/inet.h> //Networking functions like inet_pton(), htons()

#include <cstdio>
#include <cstdlib>
#include <netinet/in.h> //Defines Internet address structures.
#include <signal.h> // <csignal> is part of the C++ standard library, use this instead
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>      //Standard I/O functions like printf()
#include <stdlib.h>     //Standard functions like exit()
#include <string.h>     //String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h>     //POSIX OS functions like close()

#include <fcntl.h>
#include <net/if.h>
#include <openssl/ssl.h>     // OpenSSL SSL functions
#include <picotls.h>         // Core PicoTLS definitions
#include <picotls/openssl.h> // OpenSSL backend integration
#include <stdlib.h>
#include <sys/ioctl.h>
// Defines the port number (8080) on which the server will listen for
// connections. #define creates a symbolic constant. We can use PORT wherever we
// would like to specify the port number.

#define PORT 8080 // Port number
#define BUFFER_SIZE 9999
#define MAX_PACKET_SIZE 4096
#define TUN_MTU 1500

ptls_context_t tls_ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges,
                          .cipher_suites = ptls_openssl_cipher_suites};

struct quic_packet {
  int stream_id;
  int length;
  char payload[];
};

int open_tun_device(char *dev) {
  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("Opening /dev/net/tun");
    return fd;
  }
  memset(&ifr, 0, sizeof(ifr));

  //  tunnel for ip packets, leaves protocol empty
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    perror("ioctl(UNSETIFF)");
    close(fd);
    return err;
  }
  printf("TUN device %s opened\n", ifr.ifr_name);

  strcpy(dev, ifr.ifr_name);

  return fd;
}

int main() {
  // Open TUN
  char tun_device[IFNAMSIZ] = "tun0";
  int tun_fd = open_tun_device(tun_device);
  if (tun_fd < 0) {
    fprintf(stderr, "Failed to open TUN device\n");
    return EXIT_FAILURE;
  }

  printf("TUN Device opened. Congifure with IP:\n");
  printf(" sudo ip address add 10.8.0.1/24 dev %s\n", tun_device);
  printf(" sudo ip link set dev %s up\n", tun_device);

  int server_fd, new_socket;
  struct sockaddr_in address, client_addr;
  char buffer[BUFFER_SIZE];
  uint8_t tun_buffer[MAX_PACKET_SIZE];
  uint8_t encrypted_bufffer[BUFFER_SIZE];

  socklen_t addrlen = sizeof(client_addr);

  server_fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (server_fd < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  int opt = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    perror("setsockopt(SO_REUSEADDR) failed");
    close(tun_fd);
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  // bind
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Bind Failed");
    close(tun_fd);
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  printf("Server listening on port %d\n", PORT);

  // AEAD setup for decryption
  uint8_t key[32] = {0};
  ptls_cipher_suite_t *suite = ptls_openssl_cipher_suites[0];
  ptls_aead_context_t *aead_decryption =
      ptls_aead_new(suite->aead, suite->hash, 0, key, "key-label");

  int have_client = 0;

  while (1) {
    // read from tun
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(tun_fd, &readfds);
    FD_SET(server_fd, &readfds);
    int max_fd = tun_fd > server_fd ? tun_fd : server_fd;

    int ready_to_receive = select(max_fd + 1, &readfds, NULL, NULL, NULL);

    if (ready_to_receive < 0) {
      perror("select");
      break;
    }

    if (FD_ISSET(server_fd, &readfds)) {

      int bytes = recvfrom(server_fd, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr *)&client_addr, &addrlen);

      if (bytes < 0) {
        perror("receive failed");
        continue;
      }

      uint8_t decrypted[BUFFER_SIZE];
      size_t decrypted_len = ptls_aead_decrypt(aead_decryption, decrypted,
                                               buffer, bytes, 0, NULL, 0);
      // Check to see if length of decrypted data is less than expected
      if (decrypted_len == SIZE_MAX || decrypted_len < 2 * sizeof(int)) {
        fprintf(stderr, "Invalid decryption failed, decrypted length: \n",
                decrypted_len);

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

      // Allocate packet memory
      struct quic_packet *packet = malloc(sizeof(struct quic_packet) + length);
      if (!packet) {
        perror("malloc failed");
        continue;
      }
      packet->stream_id = stream_id;
      packet->length = length;
      memcpy(packet->payload, decrypted + 2 * sizeof(int), length);

      uint8_t *payload = decrypted + 2 * sizeof(int);

      //  write to the tun device
      int bytes_written = write(tun_fd, payload, length);
      if (bytes_written < 0) {
        perror("Writing to tun device");
        continue;
      }

      if (bytes_written != length) {
        fprintf(stderr, "Incomplete write to tun device: %d/%d\n",
                bytes_written, length);
      } else {
        printf("Wrote %d bytes to TUN device\n", bytes_written);
      }

      printf("Decrypted packet: Stream ID: %d, Length: %d, Payload: %s\n",
             packet->stream_id, packet->length, packet->payload);
      // Release allocated packet
      free(packet);
    }
  }
  ptls_aead_free(aead_decryption);
  close(server_fd);
  return 0;
}
