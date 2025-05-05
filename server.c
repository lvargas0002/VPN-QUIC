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
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 2048
#define MAX_STREAMS 1024

// Stream state structure
typedef struct {
    int stream_id;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    bool active;
    time_t last_activity;
    uint64_t expected_packet_number; // per-client nonce tracking
} stream_state_t;

// Global variables
uint8_t key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };

//static uint64_t outgoing_packet_number = 2000;
static stream_state_t streams[MAX_STREAMS];
static pthread_mutex_t streams_mutex = PTHREAD_MUTEX_INITIALIZER;

stream_state_t* find_stream_by_addr(struct sockaddr_in *addr) {
    pthread_mutex_lock(&streams_mutex);
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (streams[i].active &&
            memcmp(&streams[i].client_addr, addr, sizeof(struct sockaddr_in)) == 0) {
            pthread_mutex_unlock(&streams_mutex);
            return &streams[i];
        }
    }
    pthread_mutex_unlock(&streams_mutex);
    return NULL;
}

void register_stream(int stream_id, struct sockaddr_in *client_addr, socklen_t addr_len) {
    pthread_mutex_lock(&streams_mutex);
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!streams[i].active) {
            streams[i].stream_id = stream_id;
            streams[i].client_addr = *client_addr;
            streams[i].addr_len = addr_len;
            streams[i].active = true;
            streams[i].last_activity = time(NULL);
            streams[i].expected_packet_number = 1000;
            printf("Registered new stream ID: %d\n", stream_id);
            pthread_mutex_unlock(&streams_mutex);
            return;
        }
    }
    fprintf(stderr, "No available slots for new stream\n");
    pthread_mutex_unlock(&streams_mutex);
}

int main() {
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

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    ptls_cipher_suite_t *suite = ptls_openssl_cipher_suites[0];
    ptls_aead_context_t *decrypt_aead = ptls_aead_new(suite->aead, suite->hash, 0, key, NULL);

    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        FD_SET(tun_fd, &fds);
        select(sock + 1, &fds, NULL, NULL, NULL);

        if (FD_ISSET(sock, &fds)) {
            struct sockaddr_in client;
            socklen_t clen = sizeof(client);
            uint8_t buf[BUFFER_SIZE], decrypted[BUFFER_SIZE];
            int len = recvfrom(sock, buf, BUFFER_SIZE, 0, (struct sockaddr *)&client, &clen);

            stream_state_t *stream = find_stream_by_addr(&client);
            if (!stream) {
                fprintf(stderr, "Unregistered client, ignoring\n");
                continue;
            }

            size_t dec_len = ptls_aead_decrypt(
                decrypt_aead, decrypted, buf, len, stream->expected_packet_number++, NULL, 0);

            if (dec_len == SIZE_MAX) {
                fprintf(stderr, "Decryption failed\n");
                continue;
            }

            int stream_id, payload_len;
            memcpy(&stream_id, decrypted, sizeof(int));
            memcpy(&payload_len, decrypted + sizeof(int), sizeof(int));
            write(tun_fd, decrypted + 2 * sizeof(int), payload_len);
        }
    }
}
