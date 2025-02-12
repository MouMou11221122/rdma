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
#define MAX_EVENTS          (MAX_CLIENTS + 1)
#define HASH_TABLE_SIZE     MAX_CLIENTS      
#define MAX_THREAD_NUM      MAX_CLIENTS
#define HCA_DEVICE_NAME     "mlx5_0" 
#define HCA_PORT_NUM        1

int server_socket, epoll_fd;

/* server RDMA infos(global) */
struct ibv_context* ctx;                            // RDMA device context
uint16_t lid;                                       // RDMA lid

/* server socket info */
struct sockaddr_in address;
int addrlen = sizeof(address);

/* mutex locks */
pthread_mutex_t thread_count_lock;
pthread_mutex_t hash_table_lock;
pthread_mutex_t epoll_lock;

/* thread info */
int thread_count;

/* hash table node */
struct client_info {
    int socket;
    uint16_t lid;
    uint32_t qp_num;
    struct client_info* next;
};

/* hash table */
struct client_info* hash_table[HASH_TABLE_SIZE];

/* hash function */
unsigned int hash_function(int fd) {
    return fd % HASH_TABLE_SIZE; 
}

void cleanup() {
    printf("Cleaning up resources...\n");
    if (server_socket > 0) close(server_socket);
    if (epoll_fd > 0) close(epoll_fd);
    exit(0);
}

/* signal INT handler */
void handle_signal(int signun) {
    printf("\nSIGINT received.\n");
    cleanup();
}

/* insert a node to the hash table */
void insert(int socket) {
    unsigned int index = hash_function(socket);

    // check if the same fd already exists
    struct client_info* current = hash_table[index];
    while (current != NULL) {
        if (current->socket == socket) {
            fprintf(stderr, "Socket %d already exists in the hash table.\n", socket);
            exit(1);
        }
        current = current->next;
    }

    // create a new node
    struct client_info* new_node = (struct client_info*)malloc(sizeof(struct client_info));
    new_node->socket = socket;
    new_node->lid = 0;
    new_node->qp_num = 0;

    new_node->next = hash_table[index];

    // insert into the hash table
    hash_table[index] = new_node;
}


/* search for a node from the hash table */
struct client_info* search(int socket) {
    unsigned int index = hash_function(socket);
    struct client_info* current = hash_table[index];

    while (current != NULL) {
        if (current->socket == socket) {
            return current; 
        }
        current = current->next;
    }
    return NULL; 
}

/* delete a node from the hash table */
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
    fprintf(stderr, "Socket %d is not found in the hash table.\n", socket);
    exit(1);
}

/* Open the HCA(IB) and generate a userspace device context */
struct ibv_context* create_context(const char* device_name) {
    struct ibv_context* context = NULL;
    int num_devices;

    /* Get the list of RDMA devices */
    struct ibv_device** device_list = ibv_get_device_list(&num_devices);
    if (!device_list) {
        perror("[ERROR] Failed to get RDMA device list");
        return NULL;
    }

    /* Iterate through the device list to find the matching device name */
    for (int i = 0; i < num_devices; i++) {
        if (strcmp(device_name, ibv_get_device_name(device_list[i])) == 0) {
            context = ibv_open_device(device_list[i]);
            if (!context) {
                fprintf(stderr, "[ERROR] Failed to open RDMA device: %s\n", device_name);
            }
            break;
        }
    }

    /* Free the device list to prevent memory leaks */
    ibv_free_device_list(device_list);

    if (!context) {
        fprintf(stderr, "[ERROR] Unable to find the device: %s\n", device_name);
    }
    return context;
}

/* query port attributes and get the LID */
uint16_t get_lid(struct ibv_context* context, uint8_t port_num) {
    struct ibv_port_attr port_attr;
    if (ibv_query_port(context, port_num, &port_attr)) {
        perror("[ERROR] Failed to query port attributes");
        return 0;
    }
    printf("[INFO] LID of the port being used(port %u) : %u\n", port_num, port_attr.lid);
    return port_attr.lid;
}

/* create a protection domain */
struct ibv_pd* create_protection_domain(struct ibv_context* context) {
    struct ibv_pd* pd = ibv_alloc_pd(context);
    if (!pd) {
        perror("[ERROR] Failed to allocate protection domain");
    } else {
        printf("[INFO] Protection domain created successfully.\n");
    }
    return pd;
}

/* register a memory region */
struct ibv_mr* register_memory_region(struct ibv_pd* pd, void** buffer, size_t size) {
    *buffer = malloc(size);
    if (!(*buffer)) {
        perror("[ERROR] Failed to allocate buffer");
        return NULL;
    }

    /* Initialize the buffer with "Hello world" */
    memset(*buffer, 0, size);
    //strncpy(*buffer, "Hello world", size - 1);
    unsigned char cnt = 0;
    for (long i = 0; i < RDMA_BUFFER_SIZE; i++) {
        ((unsigned char *)(*buffer))[i] = cnt;
        cnt++;
    }

    struct ibv_mr* mr = ibv_reg_mr(pd, *buffer, size, IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE);
    if (!mr) {
        perror("[ERROR] Failed to register memory region");
        free(*buffer);
        *buffer = NULL;
        return NULL;
    }

    printf("[INFO] Memory region registered successfully.\n");
    printf("[INFO] Remote side string content in the buffer %p: %s, size of the data that will be read : %zu bytes\n", *buffer, (char*)*buffer, size);
    printf("[INFO] Remote side RKey : 0x%x\n", mr->rkey);

    return mr;
}

void setup_rdma_connection(struct client_info* client_struct) {
    /* create a protection domain */
    struct ibv_pd* pd = create_protection_domain(context);
    if (!pd) cleanup_and_exit(-1);

    /* register a memory region */
    void* buffer = NULL;
    struct ibv_mr* mr = register_memory_region(pd, &buffer, buffer_size);
    if (!mr) cleanup_and_exit(-1);


}

void* thread_handler(void* args) {
    struct client_info* client_struct = (struct client_info* )args;
    printf("An client RDMA connection is being handled by a server thread %lu, lid : 0x%u, qp num : 0x%u\n", (unsigned long)pthread_self(), client_struct->lid, client_struct->qp_num);

    // do RDMA operation
    setup_rdma_connection(client_struct);

    // delete client socket from the epoll
    pthread_mutex_lock(&epoll_lock); 
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_struct->socket, NULL) < 0) {
        pthread_mutex_unlock(&epoll_lock); 
        perror("Epoll control deletion failed");
        cleanup();
        exit(1);
    }    
    pthread_mutex_unlock(&epoll_lock); 

    // close the client socket
    close(client_struct->socket);  
 
    // delete client socket metadata from the hash table
    pthread_mutex_lock(&hash_table_lock);
    delete(client_struct->socket);
    pthread_mutex_unlock(&hash_table_lock);

    // decreament thread count
    pthread_mutex_lock(&thread_count_lock);
    thread_count--;
    pthread_mutex_unlock(&thread_count_lock);

    return NULL;
}

void setup_server_socket() {
    /* create server socket file descriptor */
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Failed to create socket");
        cleanup();
        exit(1);
    }

    /* bind the socket to the port */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Failed to bind");
        cleanup();
        exit(1);
    }

    /* listen for incoming connections */
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Failed to listen");
        cleanup();
        exit(1);
    }
    printf("[INFO] Server is listening on port %d\n", PORT);

    /* set server socket to non-blocking mode */
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

    /* create epoll instance */
    pthread_mutex_lock(&epoll_lock); 
    if ((epoll_fd = epoll_create1(0)) < 0) {
        pthread_mutex_unlock(&epoll_lock); 
        perror("Failed to create epoll fd");
        cleanup();
        exit(1);
    }
    pthread_mutex_unlock(&epoll_lock); 

    /* add the server socket fd to the epoll instance */
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
}



int main(int argc, char* argv[]) {
    //uint16_t server_lid = 4;
    //uint32_t server_qp_num = 99; 
    //uint64_t server_virt_addr = 0x6666666666666666; 
    //uint32_t server_rkey = 0x77777777; 
    
    //struct epoll_event ev, events[MAX_EVENTS];

    /* server RDMA infos(local) */
    const char* device_name = HCA_DEVICE_NAME;                     // IB device name 
    const uint8_t port_num = HCA_PORT_NUM;                         // default port number

    /* enroll the SIGINT signal handler */
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Sigaction");
        exit(1);
    }

    /* open the RDMA device context */
    ctx = create_context(device_name);
    if (!context) cleanup_and_exit(-1);

    /* get the lid of the given port */
    lid = get_lid(context, port_num);
    if (lid == 0) cleanup_and_exit(-1);
 
    /* set up the server socket */
    setup_server_socket();

    while (1) {
        // polls fds
        pthread_mutex_lock(&epoll_lock); 
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        pthread_mutex_unlock(&epoll_lock); 
        if (nfds < 0) {
            perror("Epoll wait failed");
            cleanup();
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_socket) {           // handle the server socket fd
                pthread_mutex_lock(&thread_count_lock);
                if (thread_count >= MAX_CLIENTS) {
                    pthread_mutex_unlock(&thread_count_lock);
                    continue;
                }
                pthread_mutex_unlock(&thread_count_lock);

                while (1) {
                    // server accept the incoming connections
                    int client_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                    if (client_socket < 0) {
                        if (errno == EAGAIN) break;
                        perror("Server failed to accept");
                        close(client_socket);
                        cleanup();
                        exit(1);
                    }
                    printf("[INFO] A new client has connected to\n");

                    // send server's lid to the connected client
                    send(client_socket, &lid, sizeof(lid), 0);                
                    printf("[INFO] Server's rdma lid have been send to the connected client\n");

                    // increament the thread count
                    pthread_mutex_lock(&thread_count_lock);
                    thread_count++;
                    pthread_mutex_unlock(&thread_count_lock);

                    // add new client socket fd to epoll instance
                    ev.events = EPOLLIN;
                    ev.data.fd = client_socket;
                    pthread_mutex_lock(&epoll_lock); 
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &ev) < 0) {
                        pthread_mutex_unlock(&epoll_lock); 
                        perror("[ERROR] Epoll control failed for the client");
                        close(client_socket);
                        cleanup();
                        exit(1);
                    }
                    pthread_mutex_unlock(&epoll_lock); 

                    // add new client socket fd to the hash table
                    pthread_mutex_lock(&hash_table_lock);
                    insert(client_socket);                
                    pthread_mutex_unlock(&hash_table_lock);
                }
            } else {                                        // handle some client fd
                int bytes_recv;
                pthread_mutex_lock(&hash_table_lock);
                struct client_info* client_struct = search(events[i].data.fd);
                pthread_mutex_unlock(&hash_table_lock);
                
                if (client_struct->lid == 0) {              // receive the client's lid
                    bytes_recv = recv(events[i].data.fd, &(client_struct->lid), sizeof(uint16_t), 0); 
                    if (bytes_recv <= 0) {
                        if (bytes_recv == 0) fprintf(stderr, "[ERROR] The client disconnected.\n");
                        else perror("[ERROR] Server reiceve lid from the client error");

                        pthread_mutex_lock(&epoll_lock); 
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL) < 0) {
                            pthread_mutex_unlock(&epoll_lock); 
                            perror("[ERROR] epoll_ctl(EPOLL_CTL_DEL) failed");
                            cleanup();
                            exit(1);
                        }    
                        pthread_mutex_unlock(&epoll_lock);

                        pthread_mutex_lock(&hash_table_lock);
                        delete(events[i].data.fd);
                        pthread_mutex_unlock(&hash_table_lock);

                        close(events[i].data.fd);

                        pthread_mutex_lock(&thread_count_lock);
                        thread_count--;
                        pthread_mutex_unlock(&thread_count_lock);
                        continue;
                    }
                    continue;
                }
 
                if (client_struct->qp_num == 0) {           // receive the client's qp num
                    bytes_recv = recv(events[i].data.fd, &(client_struct->qp_num), sizeof(uint32_t), 0); 
                    if (bytes_recv <= 0) {
                        if (bytes_recv == 0) fprintf(stderr, "[ERROR] The client disconnected.\n");
                        else perror("[ERROR] Server reiceved qp num from the client error");
    
                        pthread_mutex_lock(&epoll_lock); 
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL) < 0) {
                            pthread_mutex_unlock(&epoll_lock); 
                            perror("[ERROR] Epoll control deletion failed");
                            cleanup();
                            exit(1);
                        }    
                        pthread_mutex_unlock(&epoll_lock);
 
                        pthread_mutex_lock(&hash_table_lock);
                        delete(events[i].data.fd);
                        pthread_mutex_unlock(&hash_table_lock);

                        close(events[i].data.fd);

                        pthread_mutex_lock(&thread_count_lock);
                        thread_count--;
                        pthread_mutex_unlock(&thread_count_lock); 
                        continue;
                    }
                    
                    // do bottom-half using an independent worker thread
                    pthread_t tid;
                    if (pthread_create(&tid, NULL, thread_handler, (void *)client_struct) != 0) {
                        perror("[ERROR] Server failed to create a worker thread");
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

