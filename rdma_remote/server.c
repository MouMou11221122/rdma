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

#define MAX_CLIENTS                 32
#define MAX_EVENTS                  (MAX_CLIENTS + 1)
#define MAX_THREAD_NUM              MAX_CLIENTS
#define HASH_TABLE_SIZE             MAX_CLIENTS      
#define HCA_DEVICE_NAME             "mlx5_0" 
#define HCA_PORT_NUM                1
#define CLIENT_RDMA_READ_SUCCESS    1

#define HASH_FUNCTION(fd)           ((fd) % HASH_TABLE_SIZE)
#define INVALID_TID                 ((pthread_t)0)


/* server RDMA infos(global) */
struct ibv_context* ctx;                            // RDMA device context
uint16_t lid;                                       // RDMA lid
const uint8_t port_num = HCA_PORT_NUM;              // default port number

/* server socket info */
int server_socket;
struct sockaddr_in address;
int addrlen = sizeof(address);

/* server epoll */
int epoll_fd;
struct epoll_event ev, events[MAX_EVENTS];

/* thread info */
int thread_count;

/* thread local strorage */
pthread_key_t cq_key;
pthread_key_t qp_key;
pthread_key_t mr_key;
pthread_key_t buffer_key;
pthread_key_t pd_key;

/* hash table node */
struct client_info {
    int socket;
    pthread_t tid;
    uint16_t lid;
    uint32_t qp_num;
    struct client_info* next;
};

/* hash table */
struct client_info* hash_table[HASH_TABLE_SIZE];

/* clean up the resourses */
void clean_up () {
    for (int i = 0; i < HASH_TABLE_SIZE; i++)  
        for (struct client_info* client_struct = hash_table[i]; client_struct != NULL; client_struct = client_struct->next) 
            if (!pthread_equal(client_struct->tid, INVALID_TID)) pthread_cancel(client_struct->tid);
    
    /* main thread free the shared RDMA context */
    if(ctx) {
        ibv_close_device(ctx);
        fprintf(stdout, "RDMA device context closed successfully.\n");
    }

    pthread_exit(NULL);
}

/* signal handler */
void signal_handler(int signum) {
    if (signum == SIGINT) {
        fprintf(stdout, "\nSIGINT received by main thread.\n");
        clean_up();
    }
    /* reserved for other signals */
}

/* insert a node to the hash table */
void insert(int socket) {
    unsigned int index = HASH_FUNCTION(socket);

    // check if the same fd already exists
    struct client_info* current = hash_table[index];
    while (current != NULL) {
        if (current->socket == socket) {
            fprintf(stderr, "[ERROR] Socket %d already exists in the hash table.\n", socket);
            exit(1);
        }
        current = current->next;
    }

    // create a new node
    struct client_info* new_node = (struct client_info*)malloc(sizeof(struct client_info));
    new_node->socket = socket;
    new_node->tid = INVALID_TID;
    new_node->lid = 0;
    new_node->qp_num = 0;

    new_node->next = hash_table[index];

    // insert into the hash table
    hash_table[index] = new_node;
}


/* search for a node from the hash table */
struct client_info* search(int socket) {
    unsigned int index = HASH_FUNCTION(socket);
    struct client_info* current = hash_table[index];

    while (current != NULL) {
        if (current->socket == socket) return current; 
        current = current->next;
    }
    return NULL; 
}

/* delete a node from the hash table */
void delete(int socket) {
    unsigned int index = HASH_FUNCTION(socket);
    struct client_info* current = hash_table[index];
    struct client_info* prev = NULL;

    while (current != NULL) {
        if (current->socket == socket) {
            if (prev == NULL) hash_table[index] = current->next;
            else prev->next = current->next;
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
    fprintf(stderr, "[ERROR] Socket %d is not found in the hash table.\n", socket);
    exit(1);
}

/* open the HCA(IB) and generate a userspace device context */
struct ibv_context* create_context(const char* device_name) {
    struct ibv_context* context = NULL;
    int num_devices;

    /* get the list of RDMA devices */
    struct ibv_device** device_list = ibv_get_device_list(&num_devices);
    if (!device_list) {
        perror("[ERROR] Failed to get RDMA device list");
        return NULL;
    }

    /* iterate through the device list to find the matching device name */
    for (int i = 0; i < num_devices; i++) {
        if (strcmp(device_name, ibv_get_device_name(device_list[i])) == 0) {
            context = ibv_open_device(device_list[i]);
            if (!context) fprintf(stderr, "[ERROR] Failed to open RDMA device: %s\n", device_name);
            break;
        }
    }

    /* free the device list to prevent memory leaks */
    ibv_free_device_list(device_list);

    if (!context) fprintf(stderr, "[ERROR] Unable to find the device: %s\n", device_name);
    return context;
}

/* query port attributes and get the LID */
uint16_t get_lid(struct ibv_context* context) {
    struct ibv_port_attr port_attr;
    if (ibv_query_port(context, port_num, &port_attr)) {
        perror("[ERROR] Failed to query port attributes");
        return 0;
    }
    fprintf(stdout, "[INFO] LID of the port being used(port %u) : %u\n", port_num, port_attr.lid);

    return port_attr.lid;
}

/* create a protection domain */
struct ibv_pd* create_protection_domain(struct ibv_context* context) {
    struct ibv_pd* pd = ibv_alloc_pd(context);
    if (!pd) perror("[ERROR] Failed to allocate protection domain");
    else fprintf(stdout, "[INFO] Protection domain created successfully.\n");

    return pd;
}

/* register a memory region */
struct ibv_mr* register_memory_region(struct ibv_pd* pd, void** buffer, size_t size) {
    *buffer = malloc(size);
    if (!(*buffer)) {
        perror("[ERROR] Failed to allocate buffer");
        return NULL;
    }

    /* test the memory content */
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
    fprintf(stdout, "[INFO] Memory region registered successfully.\n");
    fprintf(stdout, "[INFO] Remote side string content in the buffer %p: %s, size of the data that will be read : %zu bytes\n", *buffer, (char*)*buffer, size);
    fprintf(stdout, "[INFO] Remote side RKey : 0x%x\n", mr->rkey);

    return mr;
}

/* create a completion queue */
struct ibv_cq* create_completion_queue(struct ibv_context* context, int cq_size) {
    struct ibv_cq* cq = ibv_create_cq(context, cq_size, NULL, NULL, 0);
    if (!cq) perror("[ERROR] Failed to create Completion Queue");
    else fprintf(stdout, "[INFO] Completion Queue created successfully with size %d bytes.\n", cq_size);

    return cq;
}

/* create a queue pair */
struct ibv_qp* create_queue_pair(struct ibv_pd* pd, struct ibv_cq* cq) {
    struct ibv_qp_init_attr qp_init_attr;
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));

    qp_init_attr.qp_type = IBV_QPT_RC;      // reliable Connection
    qp_init_attr.sq_sig_all = 1;            // signal completion for all send WRs
    qp_init_attr.send_cq = cq;              // send Completion Queue
    qp_init_attr.recv_cq = cq;              // receive Completion Queue
    qp_init_attr.cap.max_send_wr = 1;       // max send WRs
    qp_init_attr.cap.max_recv_wr = 1;       // max recv WRs
    qp_init_attr.cap.max_send_sge = 1;      // max scatter-gather entries for send WR
    qp_init_attr.cap.max_recv_sge = 1;      // max scatter-gather entries for recv WR

    struct ibv_qp* qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp) {
        perror("[ERROR] Failed to create Queue Pair");
        return NULL;
    }
    fprintf(stdout, "[INFO] Queue Pair created successfully. QP Number : %u\n", qp->qp_num);
    
    return qp;
}

/* transition QP to the INIT state */
int transition_to_init_state(struct ibv_qp* qp) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.pkey_index = 0;                   // default partition key
    qp_attr.port_num = port_num;              
    qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;

    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition QP to INIT state");
        return -1;
    }
    fprintf(stdout, "[INFO] Queue Pair transitioned to INIT state successfully.\n");
    
    return 0;
}

int transition_to_rtr_state(struct ibv_qp *qp, uint16_t local_lid, uint32_t local_qp_num) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_RTR;          // target state: RTR
    qp_attr.path_mtu = IBV_MTU_4096;         // path MTU; adjust based on your setup
    qp_attr.dest_qp_num = local_qp_num;      // destination Queue Pair Number
    qp_attr.rq_psn = 0;                      // remote Queue Pair Packet Sequence Number
    qp_attr.max_dest_rd_atomic = 1;          // maximum outstanding RDMA reads/atomic ops
    qp_attr.min_rnr_timer = 12;              // minimum RNR NAK timer

    /* Address handle (AH) attributes for IB within the same subnet */
    qp_attr.ah_attr.is_global = 0;           // not using GRH (Infiniband in the same subnet)
    qp_attr.ah_attr.dlid = local_lid;        // destination LID (Local Identifier)
    qp_attr.ah_attr.sl = 0;                  // service Level (QoS, typically set to 0)
    qp_attr.ah_attr.src_path_bits = 0;       // source path bits (used in LMC; set to 0 if not used)
    qp_attr.ah_attr.port_num = 1;            // use the given port; adjust based on your setup

    /* flags specifying which attributes to modify */
    int flags = IBV_QP_STATE | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER | IBV_QP_AV;

    /* modify the QP to transition to the RTR state */
    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition QP to the RTR state");
        return -1;
    }
    fprintf(stdout, "[INFO] Queue Pair transitioned to the RTR state successfully.\n");
    
    return 0;
}

void thread_cleanup_callback(void* arg) {
    struct ibv_cq* cq = pthread_getspecific(cq_key);
    if (cq) {
        ibv_destroy_cq(cq);
        fprintf(stdout, "Complete queue destroyed successfully.\n");
    }

    struct ibv_qp* qp = pthread_getspecific(qp_key);
    if (qp) {
        ibv_destroy_qp(qp);
        fprintf(stdout, "Queue Pair destroyed successfully.\n");
    }

    struct ibv_mr* mr = pthread_getspecific(mr_key);
    if (mr) {
        ibv_dereg_mr(mr);
        fprintf(stdout, "Memory region deregistered successfully.\n");
    }

    void* buffer = pthread_getspecific(buffer_key);
    if (buffer) {
        free(buffer);
        fprintf(stdout, "Buffer memory freed successfully.\n");
    }

    struct ibv_pd* pd = pthread_getspecific(pd_key);
    if (pd) {
        ibv_dealloc_pd(pd);
        fprintf(stdout, "Protection domain deallocated successfully.\n");
    }
}

void setup_rdma_connection(struct client_info* client_struct) {
    /* register cleanup callback function */
    pthread_cleanup_push(thread_cleanup_callback, NULL);

    /* create a protection domain */
    struct ibv_pd* pd = create_protection_domain(context);
    if (!pd) pthread_exit((void*)-1);
    pthread_setspecific(pd_key, pd);    

    /* register a memory region */
    void* buffer = NULL;
    struct ibv_mr* mr = register_memory_region(pd, &buffer, buffer_size);
    if (!mr) pthread_exit((void*)-1);
    pthread_setspecific(mr_key, mr);    
    pthread_setspecific(buffer_key, buffer);    

    /* create completion queue */
    int cq_size = 16;                   
    struct ibv_cq* cq = create_completion_queue(context, cq_size);
    if (!cq) pthread_exit((void*)-1);
    pthread_setspecific(cq_key, cq);    
    
    /* create a queue pair */
    struct ibv_qp* qp = create_queue_pair(pd, cq);
    if (!qp) pthread_exit((void*)-1);
    pthread_setspecific(qp_key, qp);    

    /* send the qp num, virtual address and rkey to the connected client */
    send(client_struct->socket, &(qp->qp_num), sizeof(qp->qp_num), 0);
    send(client_struct->socket, &buffer, sizeof(buffer), 0);
    send(client_struct0>socket, &(mr->rkey), sizeof(mr->rkey), 0);

    /* transition QP to the INIT state */
    if (transition_to_init_state(qp)) pthread_exit((void*)-1);

    // receive the local LID 
    uint16_t local_lid;
    if (recv(new_socket, &local_lid, sizeof(local_lid), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read the local LID.\n");
        pthread_exit((void*)-1);
    }
    fprintf(stdout, "[INFO] Local LID received by a thread : %u\n", local_lid);

    // receive the local QP number
    uint32_t local_qp_num; 
    if (recv(new_socket, &local_qp_num, sizeof(local_qp_num), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read the local QP number.\n");
        pthread_exit((void*)-1);
    }
    fprintf(stdout, "[INFO] Local QP number received by a thread : %u\n", local_qp_num);

    /* transition QP to the RTR state */
    if (transition_to_rtr_state(qp, local_lid, local_qp_num)) pthread_exit((void*)-1);

    fprintf(stdout, "[INFO] A server thread for rdma operation is ready.\n");
    
    pause();

    // no effect    
    pthread_exit(NULL);
}

void* thread_handler(void* args) {
    struct client_info* client_struct = (struct client_info* )args;
    fprintf(stdout, "An client RDMA connection is being handled by a server thread %lu, lid : 0x%u, qp num : 0x%u\n", (unsigned long)pthread_self(), client_struct->lid, client_struct->qp_num);

    // do RDMA operation
    setup_rdma_connection(client_struct);

    return NULL;
}

void setup_server_socket() {
    /* create server socket file descriptor */
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Failed to create socket");
        exit(1);
    }

    /* bind the socket to the port */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Failed to bind");
        exit(1);
    }

    /* listen for incoming connections */
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Failed to listen");
        exit(1);
    }
    fprintf(stdout, "[INFO] Server is listening on port %d\n", PORT);

    /* set server socket to non-blocking mode */
    int flags = fcntl(server_socket, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl(F_GETFL)");
        exit(1);
    }
    if (fcntl(server_socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL, O_NONBLOCK)");
        exit(1);
    }
    fprintf(stdout, "[INFO] Server socket set to non-blocking mode.\n");

    /* create epoll instance */
    pthread_mutex_lock(&epoll_lock); 
    if ((epoll_fd = epoll_create1(0)) < 0) {
        pthread_mutex_unlock(&epoll_lock); 
        perror("Failed to create epoll fd");
        exit(1);
    }
    pthread_mutex_unlock(&epoll_lock); 

    /* add the server socket fd to the epoll instance */
    ev.events = EPOLLIN;
    ev.data.fd = server_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_socket, &ev) < 0) {
        perror("Failed to control epoll");
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    //uint16_t server_lid = 4;
    //uint32_t server_qp_num = 99; 
    //uint64_t server_virt_addr = 0x6666666666666666; 
    //uint32_t server_rkey = 0x77777777; 

    /* server RDMA infos(local) */
    const char* device_name = HCA_DEVICE_NAME;                     // IB device name 

    /* enroll the SIGINT signal handler */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Sigaction");
        exit(1);
    }

    /* used for block the SIGINT later */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);

    /* open the RDMA device context */
    ctx = create_context(device_name);
    if (!ctx) exit(1);

    /* get the lid of the given port */
    lid = get_lid(context);
    if (lid == 0) exit(1);
    
    /* set up the TLS */
    pthread_key_create(&cq_key, NULL);
    pthread_key_create(&qp_key, NULL);
    pthread_key_create(&mr_key, NULL);
    pthread_key_create(&buffer_key, NULL);
    pthread_key_create(&pd_key, NULL);

    /* initialize the TLS. optional? */
    pthread_setspecific(cq_key, NULL);
    pthread_setspecific(qp_key, NULL);
    pthread_setspecific(mr_key, NULL);
    pthread_setspecific(buffer_key, NULL);
    pthread_setspecific(pd_key, NULL);

    /* set up the server socket */
    setup_server_socket();

    while (1) {
        // polls fds
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            perror("Epoll wait failed");
            clean_up();
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_socket) {           // handle the server socket fd
                while (1) {
                    // client number constrain
                    if (thread_count >= MAX_CLIENTS) break;

                    // increament the thread count
                    thread_count++;

                    // server accept the incoming connections
                    int client_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                    if (client_socket < 0) {
                        if (errno == EAGAIN) {
                            thread_count--;
                            break;
                        }
                        perror("Server failed to accept.");
                        clean_up();
                    }
                    fprintf(stdout, "[INFO] A new client has connected to.\n");

                    // send server's lid to the connected client
                    send(client_socket, &lid, sizeof(lid), 0);                
                    fprintf(stdout, "[INFO] Server's rdma lid have been send to the connected client.\n");


                    // add new client socket fd to epoll instance
                    ev.events = EPOLLIN;
                    ev.data.fd = client_socket;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &ev) < 0) {
                        perror("[ERROR] Epoll control failed for the client");
                        clean_up();
                    }

                    // add new client socket fd to the hash table
                    pthread_sigmask(SIG_BLOCK, &mask, NULL);    
                    insert(client_socket);                
                    pthread_sigmask(SIG_UNBLOCK, &mask, NULL);    
                }
            } else {                                        // handle some client fd
                int bytes_recv;
                struct client_info* client_struct = search(events[i].data.fd);
                
                if (client_struct->lid == 0) {              // receive the client's lid
                    bytes_recv = recv(events[i].data.fd, &(client_struct->lid), sizeof(uint16_t), 0); 
                    if (bytes_recv <= 0) {
                        if (bytes_recv == 0) fprintf(stderr, "[ERROR] The client disconnected.\n");
                        else perror("[ERROR] Server reiceve lid from the client error");

                        pthread_sigmask(SIG_BLOCK, &mask, NULL);    
                        delete(events[i].data.fd);
                        pthread_sigmask(SIG_UNBLOCK, &mask, NULL);   
 
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL) < 0) {
                            perror("[ERROR] epoll_ctl(EPOLL_CTL_DEL) failed");
                            clean_up();
                        }    

                        close(events[i].data.fd);

                        thread_count--;

                        continue;
                    }
                    continue;
                }
 
                if (client_struct->qp_num == 0) {           // receive the client's qp num
                    bytes_recv = recv(events[i].data.fd, &(client_struct->qp_num), sizeof(uint32_t), 0); 
                    if (bytes_recv <= 0) {
                        if (bytes_recv == 0) fprintf(stderr, "[ERROR] The client disconnected.\n");
                        else perror("[ERROR] Server reiceved qp num from the client error");
   
                        pthread_sigmask(SIG_BLOCK, &mask, NULL);    
                        delete(events[i].data.fd);
                        pthread_sigmask(SIG_UNBLOCK, &mask, NULL);    
 
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL) < 0) {
                            perror("[ERROR] Epoll control deletion failed");
                            clean_up();
                        }    

                        close(events[i].data.fd);

                        thread_count--;
                        
                        continue;
                    }
                    
                    /* do RDMA operation using an independent worker thread */
                    pthread_sigmask(SIG_BLOCK, &mask, NULL);    
                    pthread_t tid;
                    if (pthread_create(&tid, NULL, thread_handler, (void *)client_struct) != 0) {
                        perror("[ERROR] Server failed to create a worker thread");
                        thread_count--;
                        clean_up();
                    }
                    client_struct->tid = tid;
                    pthread_sigmask(SIG_UNBLOCK, &mask, NULL);  
                }

                int reply_from_client;
                bytes_recv = recv(events[i].data.fd, &reply_from_client, sizeof(int), 0);
                if (bytes_recv > 0) {
                    if (reply_from_client == CLIENT_RDMA_READ_SUCCESS) fprintf(stdout, "[INFO] Client RDMA read success.\n");
                    else fprintf(stderr, "[ERROR] Client RDMA read failed.\n");
                } else if (bytes_recv == 0) fprintf(stderr, "[ERROR] A client disconnected.\n");
                else fprintf(stderr, "[ERROR] Receive reply from the client error.\n");
                
                if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL) < 0) {
                    perror("[ERROR] Epoll control deletion failed");
                    clean_up();
                }    

                // cancel and join the thread
                pthread_cancel(client_struct->tid);
                pthread_join(client_struct->tid, NULL);     // TODO: retrival value ? 
                
                pthread_sigmask(SIG_BLOCK, &mask, NULL);    
                delete(events[i].data.fd);
                pthread_sigmask(SIG_UNBLOCK, &mask, NULL);    

                close(events[i].data.fd);

                thread_count--;
            }
        }
    }
    exit(0);
}

