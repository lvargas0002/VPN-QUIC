#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdbool.h>

#define PORT 8080
#define BUFFER_SIZE 2048
#define MAX_STREAMS 1024

uint8_t key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                   0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

static int global_stream_id = 0;
pthread_mutex_t stream_id_mutex = PTHREAD_MUTEX_INITIALIZER;

// For outgoing packets
static uint64_t outgoing_packet_number = 1000;
// For incoming packets from server
static uint64_t incoming_packet_number = 2000;

// Stream tracking
typedef struct {
    int stream_id;
    bool active;
    time_t last_activity;
} client_stream_t;

static client_stream_t active_streams[MAX_STREAMS];

int open_tun_device(char *dev) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
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
    register_stream(id);
    return id;
}

// Register a new stream
void register_stream(int stream_id) {
    pthread_mutex_lock(&stream_id_mutex);
    
    // Find free slot
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!active_streams[i].active) {
            active_streams[i].stream_id = stream_id;
            active_streams[i].active = true;
            active_streams[i].last_activity = time(NULL);
            pthread_mutex_unlock(&stream_id_mutex);
            return;
        }
    }
    
    // No free slots
    fprintf(stderr, "Error: No free slots for new stream\n");
    pthread_mutex_unlock(&stream_id_mutex);
}

// Check if a stream is active
bool is_stream_active(int stream_id) {
    pthread_mutex_lock(&stream_id_mutex);
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (active_streams[i].active && active_streams[i].stream_id == stream_id) {
            pthread_mutex_unlock(&stream_id_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&stream_id_mutex);
    return false;
}

// Clean up streams that haven't been active for a while
void cleanup_old_streams(int timeout_seconds) {
    time_t now = time(NULL);
    pthread_mutex_lock(&stream_id_mutex);
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (active_streams[i].active && (now - active_streams[i].last_activity > timeout_seconds)) {
            printf("Cleaning up inactive stream ID: %d (inactive for %ld seconds)\n", 
                  active_streams[i].stream_id, now - active_streams[i].last_activity);
            active_streams[i].active = false;
        }
    }
    pthread_mutex_unlock(&stream_id_mutex);
}

int main(int argc, char *argv[]) {
    int sock_fd, tun_fd;
    char server_ip_addr[] = "127.0.0.1";
    char tun_device[IFNAMSIZ] = "tun1";
    if(argc >= 2){
		strncpy(tun_device, argv[1], IFNAMSIZ);
		tun_device[IFNAMSIZ - 1] = '\0';
	}
    struct sockaddr_in server_addr;

    // Initialize all streams as inactive
    memset(active_streams, 0, sizeof(active_streams));

    // Create UDP socket
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, server_ip_addr, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    tun_fd = open_tun_device(tun_device);
    if (tun_fd < 0) {
        fprintf(stderr, "failed to open tun");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Initialize PicoTLS
    ptls_cipher_suite_t *suite = ptls_openssl_cipher_suites[0];
    
    // Create AEAD contexts for both directions
    ptls_aead_context_t *encrypt_aead = 
        ptls_aead_new(suite->aead, suite->hash, 1, key, "key-label");
    ptls_aead_context_t *decrypt_aead = 
        ptls_aead_new(suite->aead, suite->hash, 0, key, "key-label");
        
    if (encrypt_aead == NULL || decrypt_aead == NULL) {
        fprintf(stderr, "Failed to create AEAD contexts");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    printf("Client initialized with key: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    // Make socket non-blocking
    int flags = fcntl(sock_fd, F_GETFL, 0);
    fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);
    
    // Timer for stream cleanup
    time_t last_cleanup = time(NULL);

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        FD_SET(sock_fd, &readfds);
        int max_fd = (tun_fd > sock_fd) ? tun_fd : sock_fd;

        // Set timeout for select to allow periodic cleanup
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int activity = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (activity < 0) {
            perror("select error");
            break;
        }
        
        // Periodic stream cleanup
        time_t now = time(NULL);
        if (now - last_cleanup > 60) { // Every minute
            cleanup_old_streams(300); // 5-minute timeout
            last_cleanup = now;
        }

        if (FD_ISSET(tun_fd, &readfds)) {
            uint8_t tun_buffer[BUFFER_SIZE];
            int bytes_read = read(tun_fd, tun_buffer, sizeof(tun_buffer));

            if (bytes_read <= 0) {
                perror("Reading from tun error");
                continue;
            }

            printf("Read %d bytes from TUN\n", bytes_read);

            int stream_id = allocate_client_stream_id();

            // Wrap with QUIC-like stream header
            uint8_t plain[BUFFER_SIZE];
            memcpy(plain, &stream_id, sizeof(int));
            memcpy(plain + sizeof(int), &bytes_read, sizeof(int));
            memcpy(plain + 2 * sizeof(int), tun_buffer, bytes_read);
            size_t plain_len = 2 * sizeof(int) + bytes_read;

            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = ptls_aead_encrypt(
                encrypt_aead, encrypted, plain, plain_len, outgoing_packet_number++, NULL, 0);

            if (encrypted_len == 0) {
                fprintf(stderr, "Failed to encrypt message\n");
                continue;
            }

            if (send(sock_fd, encrypted, encrypted_len, 0) < 0) {
                perror("send failed");
                continue;
            }

            printf("Client sent encrypted message (stream %d, %d bytes IP payload)\n", 
                  stream_id, bytes_read);
        }

        // Handle packets from socket
        if (FD_ISSET(sock_fd, &readfds)) {
            uint8_t buffer[BUFFER_SIZE];
            int bytes_received = recv(sock_fd, buffer, sizeof(buffer), 0);
            
            if (bytes_received > 0) {
                printf("Received %d bytes from server\n", bytes_received);
                
                // Decrypt the packet
                uint8_t decrypted[BUFFER_SIZE];
                size_t dec_len = ptls_aead_decrypt(
                    decrypt_aead, decrypted, buffer, bytes_received, 
                    incoming_packet_number++, NULL, 0);
                    
                if (dec_len == SIZE_MAX) {
                    fprintf(stderr, "Failed to decrypt server message\n");
                    continue;
                }
                
                if (dec_len < 2 * sizeof(int)) {
                    fprintf(stderr, "Decrypted server data too short (%zu bytes)\n", dec_len);
                    continue;
                }
                
                // Extract stream ID and payload length
                int stream_id, length;
                memcpy(&stream_id, decrypted, sizeof(int));
                memcpy(&length, decrypted + sizeof(int), sizeof(int));
                
                if (length < 0 || dec_len < 2 * sizeof(int) + (size_t)length) {
                    fprintf(stderr, "Invalid server payload length: %d (decrypted_len: %zu)\n", 
                           length, dec_len);
                    continue;
                }
                
                printf("Received server response on stream %d | Payload length: %d\n", 
                      stream_id, length);
                
                if (!is_stream_active(stream_id)) {
                    fprintf(stderr, "Warning: Received data for unknown stream ID: %d\n", stream_id);
                }
                
                // Extract and write the payload to TUN
                uint8_t payload[BUFFER_SIZE];
                memcpy(payload, decrypted + 2 * sizeof(int), length);
                
                int written = write(tun_fd, payload, length);
                if (written != length) {
                    fprintf(stderr, "Incomplete write to TUN: %d/%d\n", written, length);
                } else {
                    printf("Wrote %d bytes from server to TUN device\n", written);
                }
            }
        }
    }

    ptls_aead_free(encrypt_aead);
    ptls_aead_free(decrypt_aead);
    close(sock_fd);
    close(tun_fd);
    return 0;
}
