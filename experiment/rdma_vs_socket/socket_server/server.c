#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#define TIMESTAMP_BUFFER            ((1UL) << 0)
#define PORT                        8080
#define ITERATIONS                  TIMESTAMP_BUFFER

/* socket info */
int sockfd, clientfd;

/* timestamp */
int timestamp_count;
struct timespec timestamp[TIMESTAMP_BUFFER];

void setup_server_socket ()
{
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // configure server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all available interfaces
    server_addr.sin_port = htons(PORT);

    // bind the socket to the specified IP and port
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    // start listening for incoming connections
    if (listen(sockfd, 5) < 0) {
        perror("Listen failed");
        exit(1);
    }
    printf("Server is listening on port %d...\n", PORT);

    // accept an incoming connection
    if ((clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
        perror("Accept failed");
        exit(1);
    }
    printf("A client connected.\n");
}

int main (int argc, char* argv[])
{
    /* setup server socket */
    setup_server_socket();

    int buf_size = 1 << 2;
    unsigned char* buf = malloc(sizeof(unsigned char) * buf_size);
    int n, total_recv = 0;
    /* continuously perform socket read */
    for (int i = 0; i < ITERATIONS; i++) {
        while (total_recv != buf_size) {
            if ((n = recv(clientfd, buf + total_recv, buf_size - total_recv, 0)) > 0) {
                total_recv += n;
            } else if (n == 0) {
                perror("Connection closed");
                exit(1);
            } else {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                perror("Receive data failed");
                exit(1);
            }
        }
        /* end timestamp */
        clock_gettime(CLOCK_REALTIME, &timestamp[timestamp_count++]);
    }

    bool correct = true;
    unsigned char cnt = 0;
    for (int i = 0; i < buf_size; i++) {
        if (buf[i] != cnt) {
            printf("[%d] is false\n", i);
            correct = false;
            break;
        }
        cnt++;
    }
    if (correct) printf("Result is correct.\n");
    else printf("Result is false.\n");

    /* send timestamps to client */
    if (send(clientfd, timestamp, sizeof(struct timespec) * ITERATIONS, 0) < 0) {
        perror("Send timestamps failed");
        exit(1);
    }


    /* poll the memory content */
    /*
    while(((unsigned char *)buffer)[RDMA_BUFFER_SIZE - 1] != (RDMA_BUFFER_SIZE - 1) % 256);
    fprintf(stdout, "%hhu\n", ((unsigned char *)buffer)[RDMA_BUFFER_SIZE - 1]); 
    */

    /* check memory content */
    /*
    bool correct = true;
    unsigned char cnt = 0;
    for (int i = 0; i < RDMA_BUFFER_SIZE; i++) {
        if (((unsigned char *)buffer)[i] != cnt) {
            correct = false;
            break;
        }
        cnt++;
    }
    if(correct) fprintf(stdout, "Result is correct!\n");
    else fprintf(stdout, "Result is not correct!\n");
    */

    exit(0);
}


