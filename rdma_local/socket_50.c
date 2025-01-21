#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int sock = -1;  // Global variable to store the client socket descriptor

void cleanup(int sig) {
    printf("\n[INFO] Received SIGINT, cleaning up resources...\n");
    if (sock != -1) close(sock);
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
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    char *message = "Hello from A!";

    // Setup reliable signal handling
    setup_signal_handler();

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Set the server IP address (B's address)
    if (inet_pton(AF_INET, "10.10.10.2", &serv_addr.sin_addr) <= 0) {  // B machine's IP
        perror("Invalid address / Address not supported");
        cleanup(0);
    }

    // Attempt to connect to the server (B)
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        cleanup(0);
    }

    printf("A: Connected to B.\n");

    while (1) {
        // Send data to B
        send(sock, message, strlen(message), 0);
        printf("A sent: %s\n", message);

        // Receive response from B
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(sock, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            printf("A: Connection closed.\n");
            break;
        }
        printf("A received: %s\n", buffer);

        sleep(2);  // Send data every 2 seconds
    }

    cleanup(0);  // Clean up resources and exit
    return 0;
}

