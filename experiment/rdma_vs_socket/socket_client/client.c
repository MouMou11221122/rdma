#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#define TIMESTAMP_BUFFER            ((1UL) << 0)
#define PORT                        8080
#define ITERATIONS                  TIMESTAMP_BUFFER

/* socket info */
int sockfd;

/* timestamp */
int timestamp_count;
struct timespec timestamp[TIMESTAMP_BUFFER];
struct timespec server_timestamp[TIMESTAMP_BUFFER];

void setup_client_socket ()
{
    struct sockaddr_in server_addr;

    // create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "10.10.10.2", &server_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        exit(1);
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect failed");
        exit(1);
    }
    printf("Connected to server.\n");
}

void calculate_bandwidth(struct timespec start, struct timespec end, int size) {
    long long sec_diff = end.tv_sec - start.tv_sec;
    long long nsec_diff = end.tv_nsec - start.tv_nsec;

    // adjust if nanosecond difference is negative.
    if (nsec_diff < 0) {
        sec_diff--;
        nsec_diff += 1000000000L;
    }

    // calculate elapsed time in microseconds.
    long long elapsed_us = sec_diff * 1000000LL + nsec_diff / 1000LL;

    // calculate bandwidth in Gbps.
    double bandwidth_gbps = ((double)size * 8) / (elapsed_us * 1000.0);

    //print the elapsed time and bandwidth.
    printf("Elapsed time: %lld micro seconds, bandwidth: %.6f Gbps\n", elapsed_us, bandwidth_gbps);
}

int main (int argc, char* argv[]) 
{
    /* setup client socket */
    setup_client_socket();

    int buf_size = 1 << 2;
    unsigned char* buf = malloc(sizeof(unsigned char) * buf_size);
    unsigned char cnt = 0;
    for (int i = 0; i < buf_size; i++) {
        buf[i] = cnt;
        cnt++;
    }
    /* perform continuous socket write */
    int total_send = 0;
    int n;
    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_REALTIME, &timestamp[timestamp_count++]);
        while (total_send != buf_size) {
            if ((n = send(sockfd, buf + total_send, buf_size - total_send, 0)) < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                perror("Send data failed");
                exit(1);
            }
            total_send += n;
        }
    }

    /* receive timestamps from server */
    if (recv(sockfd, server_timestamp, sizeof(struct timespec) * ITERATIONS, 0) < 0) {
        perror("Receive server timestamps failed");
        exit(1);
    }

    for (int i = 0; i < ITERATIONS; i++) calculate_bandwidth(timestamp[i], server_timestamp[i], buf_size);

    exit(0);
}
