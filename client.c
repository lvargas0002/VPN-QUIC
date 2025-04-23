#include <arpa/inet.h> //Networking functions like inet_pton(), htons()
#include <signal.h>   // <csignal> is part of the C++ standard library, use this instead
#include <netinet/in.h> //Defines Internet address structures.
#include <stdio.h>      //Standard I/O functions like printf()
#include <stdlib.h>     //Standard functions like exit()
#include <string.h>     //String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h>     //POSIX OS functions like close()

#include <picotls.h>             // Core PicoTLS definitions
#include <picotls/openssl.h>     // OpenSSL backend integration
#include <openssl/ssl.h>         // OpenSSL SSL functions

#define PORT 8080
#define BUFFER_SIZE 1024

ptls_context_t tls_ctx = {
 .random_bytes = ptls_openssl_random_bytes,
 .get_time = &ptls_get_time,
 .key_exchanges = ptls_openssl_key_exchanges,
 .cipher_suites = ptls_openssl_cipher_suites
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
 // Create PTLS context
 ptls_t *tls = ptls_new(&tls_ctx, 1);
 if(tls == NULL){
   fprintf(stderr, "Failed to create ptls context");
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

  // Encrypt Message
 const char *message = "Hello World";
 size_t message_len = strlen(message);
 uint8_t encrypted[BUFFER_SIZE];
 size_t encrypted_len = ptls_aead_encrypt(aead_encryption, encrypted, message, message_len, 0, NULL, 0);
  // Send encrypted message
 ssize_t sent = sendto(sock_fd, encrypted, encrypted_len, 0, (struct sockaddr *)&server_addr, addr_len);
 
 if(sent < 0){
   perror("sendto failed");
   ptls_aead_free(aead_encryption);
   ptls_free(tls);
   close(sock_fd);
   exit(EXIT_FAILURE);
 }
 
 ptls_aead_free(aead_encryption);
 ptls_free(tls);
 close(sock_fd);
 return 0;
}
