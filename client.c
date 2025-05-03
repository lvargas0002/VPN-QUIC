#include <arpa/inet.h> //Networking functions like inet_pton(), htons()
#include <signal.h>    	// <csignal> is part of the C++ standard library, use this instead
#include <netinet/in.h> //Defines Internet address structures.
#include <stdio.h>  	//Standard I/O functions like printf()
#include <stdlib.h> 	//Standard functions like exit()
#include <string.h> 	//String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h> 	//POSIX OS functions like close()

#include <picotls.h>         	// Core PicoTLS definitions
#include <picotls/openssl.h> 	// OpenSSL backend integration
#include <openssl/ssl.h>     	// OpenSSL SSL functions

#define PORT 8080
#define BUFFER_SIZE 1024

// TLS context configuration
ptls_context_t tls_ctx = {
	.random_bytes = ptls_openssl_random_bytes,
	.get_time = &ptls_get_time,
	.key_exchanges = ptls_openssl_key_exchanges,
	.cipher_suites = ptls_openssl_cipher_suites
};

// Keep track of the stream ID for multiplexing
int allocate_client_stream_id(){
	static int client_stream_id = 1;
	int id = client_stream_id;
	// Clients use odd number stream IDs
	client_stream_id += 2;
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
  if(tls == NULL){
  	fprintf(stderr, "Failed to create ptls object");
  	close(sock_fd);
  	exit(EXIT_FAILURE);
  }
 
  // Set up AEAD encryption with key
  ptls_cipher_suite_t *suite = tls_ctx.cipher_suites[0];
  uint8_t key[32] = {0};
  ptls_aead_context_t *aead_encryption = ptls_aead_new(suite->aead, suite->hash, 1, key, "key-label");
  if(aead_encryption == NULL){
  	fprintf(stderr, "Failed to create AEAD context");
  	ptls_free(tls);
  	close(sock_fd);
  	exit(EXIT_FAILURE);
  }
 
  int stream_id = allocate_client_stream_id();
  const char *message = "Hello World";
  size_t message_len = strlen(message);
 
  // Serialize packet: stream_id, length, payload
  uint8_t plain[BUFFER_SIZE];
  size_t plain_len = 2 * sizeof(int) + message_len;
  memcpy(plain, &stream_id, sizeof(int));
  memcpy(plain + sizeof(int), &message_len, sizeof(int));
  memcpy(plain + 2 * sizeof(int), message, message_len);
 
  // Encrypt Message
  uint8_t encrypted[BUFFER_SIZE];
  size_t encrypted_len = ptls_aead_encrypt(aead_encryption, encrypted, plain, plain_len, 0, NULL, 0);
   
  // Send encrypted packet
  ssize_t sent = sendto(sock_fd, encrypted, encrypted_len, 0, (struct sockaddr *)&server_addr, addr_len);
  if(sent < 0){
  	perror("sendto failed");
  }
 
  ptls_aead_free(aead_encryption);
  ptls_free(tls);
  close(sock_fd);
  return 0;
}
