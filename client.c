#include <arpa/inet.h> //Networking functions like inet_pton(), htons()
#include <csignal>
#include <cstdlib>
#include <netinet/in.h> //Defines Internet address structures.
#include <stdio.h>      //Standard I/O functions like printf()
#include <stdlib.h>     //Standard functions like exit()
#include <string.h>     //String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h>     //POSIX OS functions like close()

#define PORT 8080
#define BUFFER_SIZE 1024

struct quic_packet {
  int stream_id;
  int length;
  int payload[];
};

int main() {
  int sock_fd;
  char server_ip_addr[] = "127.0.0.1";

  struct sockaddr_in server_addr;
  socklen_t addr_len = sizeof(server_addr);

  sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sock_fd < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

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
}
