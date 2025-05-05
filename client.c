#include <arpa/inet.h>       //Networking functions like inet_pton(), htons()
#include <netinet/in.h>      //Defines Internet address structures.
#include <openssl/ssl.h>     // OpenSSL SSL functions
#include <picotls.h>         // Core PicoTLS definitions
#include <picotls/openssl.h> // OpenSSL backend integration
#include <stdint.h>
#include <stdio.h>      //Standard I/O functions like printf()
#include <stdlib.h>     //Standard functions like exit()
#include <string.h>     //String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h>     //POSIX OS functions like close()

#define PORT 8080
#define BUFFER_SIZE 2048

uint8_t key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                   0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

static int global_stream_id = 0;
pthread_mutex_t stream_id_mutex = PTHREAD_MUTEX_INITIALIZER;

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

// Keep track of the stream ID for multiplexing
int allocate_client_stream_id() {
  pthread_mutex_lock(&stream_id_mutex);
  int id = ++global_stream_id;
  pthread_mutex_unlock(&stream_id_mutex);
  return id;
}

int main() {
  int sock_fd, tun_fd;
  char server_ip_addr[] = "127.0.0.1";
  char tun_device[IFNAMSIZ] = "tun1";

  struct sockaddr_in server_addr;

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

  // tun
  tun_fd = open_tun_device(tun_device);
  if (tun_fd < 0) {
    fprintf(stderr, "failed top open tun");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    perror("Connection failed");
    exit(EXIT_FAILURE);
  }

  // Set up AEAD encryption with key
  ptls_cipher_suite_t *suite = ptls_openssl_cipher_suites[0];
  if (!suite) {
    fprintf(stderr, "Failed to get cipher suite\n");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  ptls_aead_context_t *aead =
      ptls_aead_new(suite->aead, suite->hash, 1, key, "key-label");
  if (aead == NULL) {
    fprintf(stderr, "Failed to create AEAD context");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  printf("Client initialized with key: \n");
  for (int i = 0; i < 32; i++) {
    printf("%02x", key[i]);
  }

  if (FD_ISSET(tun_fd, &readfds)) {
    uint8_t tun_buffer[MAX_PACKET_SIZE];
    int bytes_read = read(tun_fd, tun_buffer, sizeof(tun_buffer));

    if (bytes_read < 0) {
      perror("Reading from tun error");
      continue;
    }

    if (bytes_read > 0) {
      printf("Read %d bytes from TUN\n", bytes_read);

      int stream_id = allocate_client_stream_id();
      const char *message = "Hello";
      size_t message_len = strlen(message);

      // Initialize packer: stream_id, length, payload
      uint8_t plain[BUFFER_SIZE];
      memcpy(plain, &stream_id, sizeof(int));
      memcpy(plain + sizeof(int), &message_len, sizeof(int));
      memcpy(plain + 2 * sizeof(int), message, message_len);
      size_t plain_len = 2 * sizeof(int) + message_len;

      // Encrypt message
      uint8_t encrypted[BUFFER_SIZE];
      size_t encrypted_len =
          ptls_aead_encrypt(aead, encrypted, plain, plain_len, 0, NULL, 0);
      if (encrypted_len == 0) {
        fprintf(stderr, "Failed to encrypt message\n");
        close(sock_fd);
        exit(EXIT_FAILURE);
      }
      // send encrypted packet
      if (send(sock_fd, encrypted, encrypted_len, 0) < 0) {
        perror("send failed");
        ptls_aead_free(aead);
        close(sock_fd);
        exit(EXIT_FAILURE);
      }
      printf("\nClient sent encrypted message (%zu bytes)\n", encrypted_len);
    }
  }

  ptls_aead_free(aead);
  close(sock_fd);
  return 0;
}
