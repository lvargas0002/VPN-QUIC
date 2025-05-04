#include <arpa/inet.h> //Networking functions like inet_pton(), htons()
#include <netinet/in.h> //Defines Internet address structures.
#include <openssl/ssl.h> // OpenSSL SSL functions
#include <picotls.h> // Core PicoTLS definitions
#include <picotls/openssl.h> // OpenSSL backend integration
#include <stdint.h>
#include <stdio.h> //Standard I/O functions like printf()
#include <stdlib.h> //Standard functions like exit()
#include <string.h> //String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h> //POSIX OS functions like close()

#define PORT 8080 // Port number
#define BUFFER_SIZE 2048

// Define encryption key - MUST match between client and server
uint8_t key[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

struct quic_packet {
	int stream_id;
	int length;
	char payload[BUFFER_SIZE];
};

int main() {
    int server_fd;
    struct sockaddr_in address, client_addr;
    char buffer[BUFFER_SIZE];
    
    socklen_t addr_len = sizeof(address);
    
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0){
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}
	
	// bind
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0){
		perror("Bind Failed");
		close(server_fd);
		exit(EXIT_FAILURE);
	}
	
	printf("Server listening on port %d\n", PORT);

    ptls_cipher_suite_t *suite = ptls_openssl_cipher_suites[0];
    if(!suite){
		perror("Failed to get cipher suite");
		close(server_fd);
		exit(EXIT_FAILURE);
	}
	
    ptls_aead_context_t *aead = ptls_aead_new(suite->aead, suite->hash, 0, key, "key-label");
    if(!aead){
		perror("Failed to create AEAD decryption context");
		close(server_fd);
		exit(EXIT_FAILURE);
	}
	
	while (1) {
        int bytes = recvfrom(server_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
        if(bytes < 0){
			perror("receive failed");
			continue;
		}
     
        printf("Server received %d bytes from client\n", bytes);
        
        printf("Encrypted data (dex): ");
        for(int i = 0; i < (bytes > 32 ? 32 : bytes); i++){
			printf("%02x", (unsigned char)buffer[i]);
		}
		printf("\n");

        uint8_t decrypted[BUFFER_SIZE];
        size_t decrypted_len = ptls_aead_decrypt(aead, decrypted, (const uint8_t *)buffer, bytes, 0, NULL, 0);

        if (decrypted_len == SIZE_MAX) {
            fprintf(stderr, "Decryption failed\n");
            continue;
        }
        
        printf("Decryption successful! Decrypted %zu bytes\n", decrypted_len);
        if(decrypted_len < 2 * sizeof(int)){
			fprintf(stderr, "Decrypted data too short (%zu bytes)\n", decrypted_len);
			continue;
		}
        
        int stream_id, length;
        memcpy(&stream_id, decrypted, sizeof(int));
        memcpy(&length, decrypted + sizeof(int), sizeof(int));
        
        if(length < 0 || decrypted_len < 2 * sizeof(int) + (size_t)length){
			fprintf(stderr, "Invalid payload length: %d (decrypted_len: %zu)\n", length, decrypted_len);
		}
		
		struct quic_packet packet;
		packet.stream_id = stream_id;
		packet.length = length;
		
        if(length + 1 > BUFFER_SIZE){
			fprintf(stderr, "Payload too large for buffer\n");
			continue;
		}
		memcpy(packet.payload, decrypted + 2 * sizeof(int), length);
		packet.payload[length] = '\0';

        printf("Received packet - Stream ID: %d\nLength: %d\nPayload: %.*s\n", packet.stream_id, packet.length, packet.length, packet.payload);
    }

    ptls_aead_free(aead);
    close(server_fd);
    return 0;
}
