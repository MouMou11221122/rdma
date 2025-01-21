#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int server_fd = -1;  // Global variable to store the server socket descriptor
int new_socket = -1; // Global variable to store the client connection socket descriptor

void cleanup(int sig) {
    printf("\n[INFO] Received SIGINT, cleaning up resources...\n");
    if (new_socket != -1) close(new_socket);
    if (server_fd != -1) close(server_fd);
    exit(0);
}

void setup_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = cleanup;
    sa.sa_flags = 0; // No special flags
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to set up SIGINT handler");
        exit(EXIT_FAILURE);
    }
}

int main() {
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char *response = "Hello from B (SDP)!";

    // Setup reliable signal handling
    setup_signal_handler();

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind address and port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  // Accept connections from any IP
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        cleanup(0);
    }

    // Start listening
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        cleanup(0);
    }

    printf("B: Listening on port %d (SDP mode)...\n", PORT);

    // Accept a connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("Accept failed");
        cleanup(0);
    }

    printf("B: Connection established with A.\n");

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);

        // Receive data from A
        int bytes_received = recv(new_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            printf("B: Connection closed.\n");
            break;
        }
        printf("B received: %s\n", buffer);

        // Respond to A
        send(new_socket, response, strlen(response), 0);
        printf("B sent: %s\n", response);
    }

    cleanup(0);  // Clean up resources and exit
    return 0;
}

