#include <arpa/inet.h> //Networking functions like inet_pton(), htons()
#include <signal.h>   // <csignal> is part of the C++ standard library, use this instead
#include <netinet/in.h> //Defines Internet address structures.
#include <stdio.h>      //Standard I/O functions like printf()
#include <stdlib.h>     //Standard functions like exit()
#include <string.h>     //String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h>     //POSIX OS functions like close()

// Defines the port number (8080) on which the server will listen for
// connections. #define creates a symbolic constant. We can use PORT wherever we
// would like to specify the port number.

#define PORT 8080 // Port number
#define BUFFER_SIZE 1024

struct quic_packet {
  int stream_id;
  int length;
  int payload[];
};

int main() {
  int server_fd, new_socket;
  struct sockaddr_in address, client_addr;
  char buffer[BUFFER_SIZE];

  socklen_t addrlen = sizeof(client_addr);
  struct quic_packet packet;

  server_fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (server_fd < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  // bind
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Bind Failed");
    exit(EXIT_FAILURE);
  }

  printf("Server listening on port %d\n", PORT);

  while (1) {
    int bytes = recvfrom(server_fd, buffer, BUFFER_SIZE, 0,
                         (struct sockaddr *)&client_addr, &addrlen);

    if (bytes > 0) {
      struct quic_packet *packet = (struct quic_packet *)buffer;
      printf("Received packet:\n");
      printf("Stream ID: %d, Length: %d Payload: %.*s\n", packet->stream_id,
             packet->length, packet->payload);
    } else {
      perror("Recvfrom failed");
    }
  }
  close(server_fd);
  return 0;
}