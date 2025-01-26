#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>

#define PORT 8080

#define MAX_CLIENTS         32
#define MAX_EVENTS          10
#define HASH_TABLE_SIZE     32      

int server_socket, epoll_fd;
int thread_count;

/* mutex locks */
pthread_mutex_t thread_count_lock;
pthread_mutex_t hash_table_lock;
pthread_mutex_t epoll_lock;


/* hash table node */
struct client_info {
    int socket;
    uint16_t lid;
    uint32_t qp_num;
    struct client_info* next;
};

/* hash table */
struct client_info* hash_table[HASH_TABLE_SIZE];

/* Hash function */
unsigned int hash_function(int fd) {
    return fd % HASH_TABLE_SIZE; 
}

void cleanup() {
    printf("Cleaning up resources...\n");
    if (server_socket > 0) close(server_socket);
    if (epoll_fd > 0) close(epoll_fd);
    exit(0);
}

/* Signal INT handler */
void handle_signal(int signun) {
    printf("SIGINT received.\n");
    cleanup();
}

/* Insert a node */
void insert(int socket) {
    unsigned int index = hash_function(socket);

    // Check if the same fd already exists
    struct client_info* current = hash_table[index];
    while (current != NULL) {
        if (current->socket == socket) {
            printf("Socket %d already exists in the hash table.\n", socket);
            return;
        }
        current = current->next;
    }

    // Create a new node
    struct client_info* new_node = (struct client_info*)malloc(sizeof(struct client_info));
    new_node->socket = socket;
    new_node->lid = 0;
    new_node->qp_num = 0;

    new_node->next = hash_table[index];

    // Insert into the hash table
    hash_table[index] = new_node;
}


/* Search for a node */
struct client_info* search(int socket) {
    unsigned int index = hash_function(socket);
    struct client_info* current = hash_table[index];

    while (current != NULL) {
        if (current->socket == socket) {
            return current; // Node found
        }
        current = current->next;
    }

    return NULL; // Node not found
}

/* Delete a node */
void delete(int socket) {
    unsigned int index = hash_function(socket);
    struct client_info* current = hash_table[index];
    struct client_info* prev = NULL;

    while (current != NULL) {
        if (current->socket == socket) {
            if (prev == NULL) {
                hash_table[index] = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }

    fprintf(stderr, "Socket %d not found in the hash table.\n", socket);
    cleanup();
    exit(1);
}

void* thread_handler(void* args) {
    struct client_info* client_struct = (struct client_info* )args;
    printf("An client is being handled by a server thread, lid : 0x%u, qp num : 0x%u\n", client_struct->lid, client_struct->qp_num);

    // Delete client socket from epoll
    pthread_mutex_lock(&epoll_lock); 
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_struct->socket, NULL) < 0) {
        pthread_mutex_unlock(&epoll_lock); 
        perror("epoll_ctl(EPOLL_CTL_DEL) failed");
        cleanup();
        exit(1);
    }    
    pthread_mutex_unlock(&epoll_lock); 

    // Delete client socket from hash table
    pthread_mutex_lock(&hash_table_lock);
    delete(client_struct->socket);
    pthread_mutex_unlock(&hash_table_lock);

    // Close client socket
    close(client_struct->socket);

    // Decreament thread count
    pthread_mutex_lock(&thread_count_lock);
    thread_count--;
    pthread_mutex_unlock(&thread_count_lock);
    return NULL;
}


int main(int argc, char* argv[]) {
    /* Server rdma info */
    //const char* device_name = "mlx5_0";             // IB device name
    //const uint8_t port_num = 1;                     // Default port number
    uint16_t server_lid = 4;
    uint32_t server_qp_num = 99; 
    uint64_t server_virt_addr = 0x6666666666666666; 
    uint32_t server_rkey = 0x77777777; 
    
    /* Server socket info */
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    struct epoll_event ev, events[MAX_EVENTS];

    /* Register signal handler for SIGINT*/
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Sigaction");
        exit(1);
    }

    /* Create server socket file descriptor */
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Failed to create socket");
        cleanup();
        exit(1);
    }

    /* Bind the socket to the port */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Failed to bind");
        cleanup();
        exit(1);
    }

    /* Listen for incoming connections */
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Failed to listen");
        cleanup();
        exit(1);
    }
    printf("[INFO] Server is listening on port %d\n", PORT);

    /* Set server socket to non-blocking mode */
    int flags = fcntl(server_socket, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl(F_GETFL)");
        cleanup();
        exit(1);
    }
    if (fcntl(server_socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL, O_NONBLOCK)");
        cleanup();
        exit(1);
    }
    printf("[INFO] Server socket set to non-blocking mode.\n");

    /* Create epoll instance */
    pthread_mutex_lock(&epoll_lock); 
    if ((epoll_fd = epoll_create1(0)) < 0) {
        pthread_mutex_unlock(&epoll_lock); 
        perror("Failed to create epoll fd");
        cleanup();
        exit(1);
    }
    pthread_mutex_unlock(&epoll_lock); 

    /* Add the server socket fd to the epoll instance */
    ev.events = EPOLLIN;
    ev.data.fd = server_socket;
    pthread_mutex_lock(&epoll_lock); 
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_socket, &ev) < 0) {
        pthread_mutex_unlock(&epoll_lock); 
        perror("Failed to control epoll");
        cleanup();
        exit(1);
    }
    pthread_mutex_unlock(&epoll_lock); 

    while (1) {
        // poll fds
        pthread_mutex_lock(&epoll_lock); 
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        pthread_mutex_unlock(&epoll_lock); 
        if (nfds < 0) {
            perror("Epoll wait failed");
            cleanup();
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_socket) {           // handle server fd
                if (thread_count >= MAX_CLIENTS) continue;
                while (1) {
                    // Accept new connections
                    int client_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                    if (client_socket < 0) {
                        if (errno == EAGAIN) break;
                        perror("Server failed to accept");
                        close(client_socket);
                        cleanup();
                        exit(1);
                    }
                    printf("[INFO] A new client has connected\n");

                    // Send all server's rdma informations to client
                    send(client_socket, &server_lid, sizeof(server_lid), 0);                
                    send(client_socket, &server_qp_num, sizeof(server_qp_num), 0);                
                    send(client_socket, &server_virt_addr, sizeof(server_virt_addr), 0);                
                    send(client_socket, &server_rkey, sizeof(server_rkey), 0);                
                    printf("All server's rdma informations have been send\n");

                    // Add new client socket fd to epoll instance
                    ev.events = EPOLLIN;
                    ev.data.fd = client_socket;
                    pthread_mutex_lock(&epoll_lock); 
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &ev) < 0) {
                        pthread_mutex_unlock(&epoll_lock); 
                        perror("Epoll ctl failed for client");
                        close(client_socket);
                        cleanup();
                        exit(1);
                    }
                    pthread_mutex_unlock(&epoll_lock); 

                    // Add new client socket fd to hash table
                    pthread_mutex_lock(&hash_table_lock);
                    insert(client_socket);                
                    pthread_mutex_unlock(&hash_table_lock);
                }
            } else {                                        // Handle client fd
                int bytes_recv;
                pthread_mutex_lock(&hash_table_lock);
                struct client_info* client_struct = search(events[i].data.fd);
                pthread_mutex_unlock(&hash_table_lock);
                
                if (client_struct->lid == 0) {              // Receive client's lid
                    bytes_recv = recv(events[i].data.fd, &(client_struct->lid), sizeof(uint16_t), 0); 
                    if (bytes_recv <= 0) {
                        if (bytes_recv == 0) fprintf(stderr, "Client disconnected\n");
                        else perror("Server reiceve lid error");
                        close(events[i].data.fd);

                        pthread_mutex_lock(&hash_table_lock);
                        delete(events[i].data.fd);
                        pthread_mutex_unlock(&hash_table_lock);

                        pthread_mutex_lock(&thread_count_lock);
                        thread_count--;
                        pthread_mutex_unlock(&thread_count_lock);
                        continue;
                    }
                    continue;
                }
 
                if (client_struct->qp_num == 0) {           // Receive client's qp num
                    bytes_recv = recv(events[i].data.fd, &(client_struct->qp_num), sizeof(uint32_t), 0); 
                    if (bytes_recv <= 0) {
                        if (bytes_recv == 0) fprintf(stderr, "Client disconnected\n");
                        else perror("Server reiceve qp num error");
                        close(events[i].data.fd);

                        pthread_mutex_lock(&hash_table_lock);
                        delete(events[i].data.fd);
                        pthread_mutex_unlock(&hash_table_lock);

                        pthread_mutex_lock(&thread_count_lock);
                        thread_count--;
                        pthread_mutex_unlock(&thread_count_lock); 
                        continue;
                    }
                    
                    // Do bottom half
                    pthread_t tid;
                    pthread_mutex_lock(&thread_count_lock);
                    thread_count++;
                    pthread_mutex_unlock(&thread_count_lock);
                    if (pthread_create(&tid, NULL, thread_handler, (void *)client_struct) != 0) {
                        perror("Server failed to create thread");
                        pthread_mutex_lock(&thread_count_lock);
                        thread_count--;
                        pthread_mutex_unlock(&thread_count_lock);
                        cleanup();
                        exit(1);
                    }
                    pthread_detach(tid);
                } 
            }
        }
    }

    exit(0);
}

