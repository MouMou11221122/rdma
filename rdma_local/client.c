#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>

#define PORT 8080
#define BUFFER_SIZE 128

int main(int argc, char* argv[]) {
    /* Client rdma info */
    uint16_t client_lid = 1;
    uint32_t client_qp_num = 77;
    uint16_t server_lid ;
    uint32_t server_qp_num;
    uint64_t server_virt_addr;
    uint32_t server_rkey;

    /* Client socket info */
    int sock = 0;
    struct sockaddr_in serv_addr;

    int bytes_recv;    

    /* Create client socket */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    /* Convert address to binary form */
    if (inet_pton(AF_INET, "10.10.10.2", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

    /* Connect to the server */
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    /* Send client lid to server */
    send(sock, &client_lid, sizeof(client_lid), 0);
    printf("Client lid sent to server\n");

    /* Send client qp number to server */
    send(sock, &client_qp_num, sizeof(client_qp_num), 0);
    printf("Client qp number sent to server\n");

    /* Receive server lid */
    bytes_recv = recv(sock, &server_lid, sizeof(server_lid), 0);
    if (bytes_recv <= 0) {
        if (bytes_recv == 0) printf("Server disconnected\n");
        else perror("Client receive server lid error");
        close(sock);
        exit(1);
    }
    printf("Receive server lid : [%u]\n", server_lid);

    /* Receive server qp number */
    bytes_recv = recv(sock, &server_qp_num, sizeof(server_qp_num), 0);
    if (bytes_recv <= 0) {
        if (bytes_recv == 0) printf("Server disconnected\n");
        else perror("Client receive server qp number error");
        close(sock);
        exit(1);
    }
    printf("Receive server qp number : [%u]\n", server_qp_num);

    /* Receive server virtual address */
    bytes_recv = recv(sock, &server_virt_addr, sizeof(server_virt_addr), 0);
    if (bytes_recv <= 0) {
        if (bytes_recv == 0) printf("Server disconnected\n");
        else perror("Client receive server vitual address error");
        close(sock);
        exit(1);
    }
    printf("Receive server virtual address : [%" PRIx64 "]\n", server_virt_addr);
    
    /* Receive server rkey */
    bytes_recv = recv(sock, &server_rkey, sizeof(server_rkey), 0);
    if (bytes_recv <= 0) {
        if (bytes_recv == 0) printf("Server disconnected\n");
        else perror("Client receive server rkey error");
        close(sock);
        exit(1);
    }
    printf("Receive server rkey : [%" PRIx32 "]\n", server_rkey);
    
    close(sock);
    exit(0);
}

