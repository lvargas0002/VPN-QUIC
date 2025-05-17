#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>    // OpenSSL base
#include <picotls.h>    // PicoTLS core
#include <picotls/openssl.h>    //PicoTLS OpenSSL
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_tun.h>    // TUN Interface
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdbool.h>
#include <time.h>

#define PORT 8080    // UDP port number
#define BUFFER_SIZE 2048    // Max buffer size for packets
#define MAX_STREAMS 1024    // Max number of client streams

// Stream state structure
typedef struct {
    int stream_id;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    bool active;
    time_t last_activity;
    uint64_t expected_packet_number; // per-client nonce tracking
    uint64_t outgoing_packet_number; // for packets going to this client
} stream_state_t;

// Global variables (shared symmetric key)
uint8_t key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

// Global stream registry and mutex
static stream_state_t streams[MAX_STREAMS];
static pthread_mutex_t streams_mutex = PTHREAD_MUTEX_INITIALIZER;

// Find all active streams given matching client address
stream_state_t* find_stream_by_addr(struct sockaddr_in *addr) {
    pthread_mutex_lock(&streams_mutex);
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (streams[i].active && streams[i].client_addr.sin_addr.s_addr == addr->sin_addr.s_addr && streams[i].client_addr.sin_port == addr->sin_port) {
            pthread_mutex_unlock(&streams_mutex);
            return &streams[i];
        }
    }
    pthread_mutex_unlock(&streams_mutex);
    return NULL;
}

// Register new stream if client doesn't exist yet
void register_stream(int stream_id, struct sockaddr_in *client_addr, socklen_t addr_len) {
    pthread_mutex_lock(&streams_mutex);
    
    // First check if this client already exists
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (streams[i].active && streams[i].client_addr.sin_addr.s_addr == client_addr->sin_addr.s_addr && streams[i].client_addr.sin_port == client_addr->sin_port) {
            // Update the existing stream with new ID if needed
            if (streams[i].stream_id != stream_id) {
                printf("Updated stream ID for existing client %s:%d: %d -> %d\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), streams[i].stream_id, stream_id); 
                streams[i].stream_id = stream_id;
            }
            streams[i].last_activity = time(NULL);
            pthread_mutex_unlock(&streams_mutex);
            return;
        }
    }
    
    // If not found, create a new stream
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!streams[i].active) {
            streams[i].stream_id = stream_id;
            memcpy(&streams[i].client_addr, client_addr, sizeof(struct sockaddr_in));
            streams[i].addr_len = addr_len;
            streams[i].active = true;
            streams[i].last_activity = time(NULL);
            streams[i].expected_packet_number = 1000;  // Starting value for incoming packets
            streams[i].outgoing_packet_number = 2000;  // Starting value for outgoing packets
            printf("Registered new stream ID %d for client %s:%d\n", stream_id, inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
            pthread_mutex_unlock(&streams_mutex);
            return;
        }
    }
    fprintf(stderr, "No available slots for new stream\n");
    pthread_mutex_unlock(&streams_mutex);
}

// Clean inactive streams periodically
void* cleanup_thread(void *arg) {
    while (1) {
        sleep(60);  // Check every minute
        time_t now = time(NULL);
        pthread_mutex_lock(&streams_mutex);
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (streams[i].active && (now - streams[i].last_activity) > 300) {  // 5 minutes timeout
                printf("Cleaning up inactive stream %d from %s:%d\n", streams[i].stream_id, inet_ntoa(streams[i].client_addr.sin_addr), ntohs(streams[i].client_addr.sin_port));
                streams[i].active = false;
            }
        }
        pthread_mutex_unlock(&streams_mutex);
    }
    return NULL;
}

int main() {
    // Initialize all streams as inactive
    memset(streams, 0, sizeof(streams));

    // Open and configure TUN device as tun0
    char tun_device[IFNAMSIZ] = "tun0";
    int tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) { perror("Opening /dev/net/tun"); return 1; }

    
    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, tun_device, IFNAMSIZ);
    if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl(TUNSETIFF)"); close(tun_fd); return 1;
    }
    printf("TUN device %s opened\n", tun_device);

    // Initialize socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(sock);
        close(tun_fd);
        return 1;
    }
    
    printf("Server listening on port %d\n", PORT);

    // Initialize the picotls AEAD contexts
    ptls_cipher_suite_t *suite = ptls_openssl_cipher_suites[0];
    ptls_aead_context_t *decrypt_aead = ptls_aead_new(suite->aead, suite->hash, 0, key, "key-label");
    ptls_aead_context_t *encrypt_aead = ptls_aead_new(suite->aead, suite->hash, 1, key, "key-label");

    if (!decrypt_aead || !encrypt_aead) {
        fprintf(stderr, "Failed to initialize AEAD contexts\n");
        close(sock);
        close(tun_fd);
        return 1;
    }
    
    // Start the cleanup thread
    pthread_t cleanup_tid;
    if (pthread_create(&cleanup_tid, NULL, cleanup_thread, NULL) != 0) {
        perror("Creating cleanup thread");
    } else {
        pthread_detach(cleanup_tid);
    }

    // Keep server open indefinetly 
    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        FD_SET(tun_fd, &fds);
        
        int max_fd = (sock > tun_fd) ? sock : tun_fd;
        
        if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
            perror("select");
            continue;
        }
        // Handle packet from client
        if (FD_ISSET(sock, &fds)) {
            struct sockaddr_in client;
            socklen_t clen = sizeof(client);
            uint8_t buf[BUFFER_SIZE], decrypted[BUFFER_SIZE];
            int len = recvfrom(sock, buf, BUFFER_SIZE, 0, (struct sockaddr *)&client, &clen);

            if (len <= 0) {
                perror("recvfrom");
                continue;
            }

            // Try initial decryption using a shared packet number (before registering stream)
            uint64_t temp_packet_number = 1000;
            size_t dec_len = ptls_aead_decrypt(decrypt_aead, decrypted, buf, len, temp_packet_number, NULL, 0);

            if (dec_len == SIZE_MAX) {
                fprintf(stderr, "Initial decryption failed for client %s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
                continue;
            }

            if (dec_len < 2 * sizeof(int)) {
                fprintf(stderr, "Decrypted packet too short\n");
                continue;
            }

            // Extract stream ID and payload length
            int stream_id, payload_len;
            memcpy(&stream_id, decrypted, sizeof(int));
            memcpy(&payload_len, decrypted + sizeof(int), sizeof(int));

            // Check for payload length
            if (payload_len < 0 || payload_len > dec_len - 2 * sizeof(int)) {
                fprintf(stderr, "Invalid payload length: %d\n", payload_len);
                continue;
            }

            // Register the stream using the known stream_id
            register_stream(stream_id, &client, clen);
            stream_state_t *stream = find_stream_by_addr(&client);
            if (!stream) {
                fprintf(stderr, "Failed to register new stream after decryption\n");
                continue;
            }

            // Increment expected packet number and refresh activity time
            stream->expected_packet_number = temp_packet_number + 1;
            stream->last_activity = time(NULL);
            
            printf("Received packet from %s:%d (stream %d, %d bytes payload)\n", 
            inet_ntoa(client.sin_addr), ntohs(client.sin_port), stream_id, payload_len);

            // Write the decrypted payload to the TUN device
            ssize_t written = write(tun_fd, decrypted + 2 * sizeof(int), payload_len);
            if (written != payload_len) {
                perror("Writing to TUN");
            }
        }
        // Handle packet packet back to client through TUN device
        if (FD_ISSET(tun_fd, &fds)) {
            uint8_t buffer[BUFFER_SIZE], encrypted[BUFFER_SIZE];
            ssize_t len = read(tun_fd, buffer, BUFFER_SIZE);
            
            if (len <= 0) {
                perror("Reading from TUN");
                continue;
            }
            
            if (len < 20) {
                fprintf(stderr, "Packet too short for IP\n");
                continue;
            }
            
            pthread_mutex_lock(&streams_mutex);
            for (int i = 0; i < MAX_STREAMS; i++) {
                if (!streams[i].active) continue;
                
                // Prepare packet header (stream_id + payload_length)
                uint8_t packet[BUFFER_SIZE];
                int stream_id = streams[i].stream_id;
                int payload_len = len;
                
                memcpy(packet, &stream_id, sizeof(int));
                memcpy(packet + sizeof(int), &payload_len, sizeof(int));
                memcpy(packet + 2 * sizeof(int), buffer, len);
                
                size_t total_len = 2 * sizeof(int) + len;
                size_t enc_len = ptls_aead_encrypt(encrypt_aead, encrypted, packet, total_len, streams[i].outgoing_packet_number++, NULL, 0);
                
                if (enc_len == SIZE_MAX) {
                    fprintf(stderr, "Encryption failed for stream %d\n", stream_id);
                    continue;
                }
                
                ssize_t sent = sendto(sock, encrypted, enc_len, 0, (struct sockaddr *)&streams[i].client_addr, streams[i].addr_len);
                
                if (sent != enc_len) {
                    perror("sendto");
                } else {
                    printf("Sent packet to %s:%d (stream %d, %d bytes)\n", inet_ntoa(streams[i].client_addr.sin_addr), ntohs(streams[i].client_addr.sin_port), stream_id, (int)len);
                }
            }
            pthread_mutex_unlock(&streams_mutex);
        }
    }
    
    ptls_aead_free(encrypt_aead);
    ptls_aead_free(decrypt_aead);
    close(sock);
    close(tun_fd);
    
    return 0;
}
