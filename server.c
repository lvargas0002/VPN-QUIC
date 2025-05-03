#include <arpa/inet.h> //Networking functions like inet_pton(), htons()
#include <signal.h> 	// <csignal> is part of the C++ standard library, use this instead
#include <netinet/in.h> //Defines Internet address structures.
#include <stdio.h>  	//Standard I/O functions like printf()
#include <stdlib.h> 	//Standard functions like exit()
#include <string.h> 	//String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h> 	//POSIX OS functions like close()

#include <picotls.h>         	// Core PicoTLS definitions
#include <picotls/openssl.h> 	// OpenSSL backend integration
#include <openssl/ssl.h>     	// OpenSSL SSL functions
// Defines the port number (8080) on which the server will listen for
// connections. #define creates a symbolic constant. We can use PORT wherever we
// would like to specify the port number.

#define PORT 8080 // Port number
#define BUFFER_SIZE 1024

ptls_context_t tls_ctx = {
	.random_bytes = ptls_openssl_random_bytes,
	.get_time = &ptls_get_time,
	.key_exchanges = ptls_openssl_key_exchanges,
	.cipher_suites = ptls_openssl_cipher_suites
};

struct quic_packet {
  int stream_id;
  int length;
  char payload[];
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

  // bind
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
	perror("Bind Failed");
	exit(EXIT_FAILURE);
  }

  printf("Server listening on port %d\n", PORT);
 
  // AEAD setup for decryption
  uint8_t key[32] = {0};
  ptls_cipher_suite_t *suite = ptls_openssl_cipher_suites[0];
  ptls_aead_context_t *aead_decryption = ptls_aead_new(suite->aead, suite->hash, 0, key, "key-label");

  while (1) {
	int bytes = recvfrom(server_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addrlen);
  	 
	if (bytes < 0) {
  	perror("receive failed");
  	continue;
	}
    
	uint8_t decrypted[BUFFER_SIZE];
	size_t decrypted_len = ptls_aead_decrypt(aead_decryption, decrypted, buffer, bytes, 0, NULL, 0);
	// Check to see if length of decrypted data is less than expected
	if (decrypted_len < 2 * sizeof(int)){
    	printf("Decryption failed\n");
    	continue;
	}
    
	int stream_id, length;
	memcpy(&stream_id, decrypted, sizeof(int));
	memcpy(&length, decrypted + sizeof(int), sizeof(int));
	// Check for error or if expected decrypted message is less than expected
	if(length < 0 || decrypted_len < 2 * sizeof(int) + (size_t)length){
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
    
	printf("Decrypted packet: Stream ID: %d, Length: %d, Payload: %s\n", packet->stream_id, packet->length, packet->payload);
	// Release allocated packet
	free(packet);
  }
  ptls_aead_free(aead_decryption);
  close(server_fd);
  return 0;
}
