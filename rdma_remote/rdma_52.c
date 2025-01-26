#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>

//#define RDMA_BUFFER_SIZE ((1UL) << 16)
//#define RDMA_BUFFER_SIZE ((1UL) << 24)
#define RDMA_BUFFER_SIZE ((1UL) << 30)

#define PORT 8080

struct ibv_qp* clean_qp;
struct ibv_mr* clean_mr;
void* clean_buffer;
struct ibv_pd* clean_pd;
struct ibv_cq* clean_cq;
struct ibv_context* clean_context;

/* socket */
struct sockaddr_in address;
int addrlen = sizeof(address);
int server_fd = -1;             // server socket descriptor
int new_socket = -1;            // client connection socket descriptor

/* Signal handler for cleanup */
void cleanup_and_exit(int signum) {
    printf("\n");
    if(signum >= 0) printf("SIGINT received. ");
    printf("Cleaning up resources...\n");

    if (clean_cq) {
	    ibv_destroy_cq(clean_cq);
	    printf("Complete queue destroyed successfully.\n");
    } 
    if (clean_qp) {
        ibv_destroy_qp(clean_qp);
        printf("Queue Pair destroyed successfully.\n");
    }
    if (clean_mr) {
        ibv_dereg_mr(clean_mr);
        printf("Memory region deregistered successfully.\n");
    }
    if (clean_buffer) {
        free(clean_buffer);
        printf("Buffer memory freed successfully.\n");
    }
    if (clean_pd) {
        ibv_dealloc_pd(clean_pd);
        printf("Protection domain deallocated successfully.\n");
    }
    if (clean_context) {
        ibv_close_device(clean_context);
        printf("RDMA device context closed successfully.\n");
    }    
    if (new_socket != -1) { 
        close(new_socket);
        printf("Server socket closed successfully.\n");
    }
    if (server_fd != -1) {
        close(server_fd);
        printf("Client connection socket closed successfully.\n");
    }
    exit (1);
}

void setup_socket() {
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        cleanup_and_exit(-1);
    }

    // Bind address and port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;       // Accept connections from any IP
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        cleanup_and_exit(-1);
    }

    // Start listening
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        cleanup_and_exit(-1);
    }

    printf("Remote B: Listening on port %d (SDP mode)...\n", PORT);

    // Accept a connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("Accept failed");
        cleanup_and_exit(-1);
    }

    printf("Remote B: Socket connection established with Local A.\n");
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

/* Query port attributes and get the LID */
uint16_t get_lid(struct ibv_context* context, uint8_t port_num) {
    struct ibv_port_attr port_attr;
    if (ibv_query_port(context, port_num, &port_attr)) {
        perror("[ERROR] Failed to query port attributes");
        return 0;
    }
    printf("[INFO] LID of the port being used(port %u) : %u\n", port_num, port_attr.lid);
    return port_attr.lid;
}

/* Create a protection domain */
struct ibv_pd* create_protection_domain(struct ibv_context* context) {
    struct ibv_pd* pd = ibv_alloc_pd(context);
    if (!pd) {
        perror("[ERROR] Failed to allocate protection domain");
    } else {
        printf("[INFO] Protection domain created successfully.\n");
    }
    return pd;
}

/* Create a Completion Queue */
struct ibv_cq* create_completion_queue(struct ibv_context* context, int cq_size) {
    struct ibv_cq* cq = ibv_create_cq(context, cq_size, NULL, NULL, 0);
    if (!cq) {
        perror("[ERROR] Failed to create Completion Queue");
    } else {
        printf("[INFO] Completion Queue created successfully with size %d bytes.\n", cq_size);
    }
    return cq;
}

/* Register a memory region */
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

    struct ibv_r* mr = ibv_reg_mr(pd, *buffer, size,
                                   IBV_ACCESS_REMOTE_READ |
                                   IBV_ACCESS_REMOTE_WRITE |
                                   IBV_ACCESS_LOCAL_WRITE);
    if (!mr) {
        perror("[ERROR] Failed to register memory region");
        free(*buffer);
        return NULL;
    }

    printf("[INFO] Memory region registered successfully.\n");
    printf("[INFO] Remote side string content in the buffer %p: %s, size of the data that will be read : %zu bytes\n", *buffer, (char*)*buffer, size);
    printf("[INFO] Remote side RKey : 0x%x\n", mr->rkey);

    return mr;
}

/* Create a Queue Pair */
struct ibv_qp* create_queue_pair(struct ibv_pd* pd, struct ibv_cq* cq) {
    struct ibv_qp_init_attr qp_init_attr;
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));

    qp_init_attr.qp_type = IBV_QPT_RC;		// Reliable Connection
    qp_init_attr.sq_sig_all = 1;       		// Signal completion for all send WRs
    qp_init_attr.send_cq = cq;         		// Send Completion Queue
    qp_init_attr.recv_cq = cq;         		// Receive Completion Queue
    qp_init_attr.cap.max_send_wr = 1; 		// Max send WRs
    qp_init_attr.cap.max_recv_wr = 1; 		// Max recv WRs
    qp_init_attr.cap.max_send_sge = 1; 		// Max scatter-gather entries for send WR
    qp_init_attr.cap.max_recv_sge = 1; 		// Max scatter-gather entries for recv WR

    struct ibv_qp* qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp) {
        perror("[ERROR] Failed to create Queue Pair");
        return NULL;
    }

    printf("[INFO] Queue Pair created successfully. QP Number : %u\n", qp->qp_num);
    return qp;
}

/* Transition QP to INIT state */
int transition_to_init_state(struct ibv_qp* qp, uint8_t port_num) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.pkey_index = 0;                   // Default partition key
    qp_attr.port_num = port_num;              // Physical port number
    qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;

    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition QP to INIT state");
        return -1;
    }

    printf("[INFO] Queue Pair transitioned to INIT state successfully.\n");
    return 0;
}

int transition_to_rtr_state(struct ibv_qp *qp, uint16_t local_lid, uint32_t local_qp_num) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_RTR;          // Target state: RTR
    qp_attr.path_mtu = IBV_MTU_4096;         // Path MTU; adjust based on your setup
    qp_attr.dest_qp_num = local_qp_num;       // Destination Queue Pair Number
    qp_attr.rq_psn = 0;                      // Remote Queue Pair Packet Sequence Number
    qp_attr.max_dest_rd_atomic = 1;          // Maximum outstanding RDMA reads/atomic ops
    qp_attr.min_rnr_timer = 12;              // Minimum RNR NAK timer

    /* Address handle (AH) attributes for IB within the same subnet */
    qp_attr.ah_attr.is_global = 0;           // Not using GRH (Infiniband in the same subnet)
    qp_attr.ah_attr.dlid = local_lid;             // Destination LID (Local Identifier)
    qp_attr.ah_attr.sl = 0;                  // Service Level (QoS, typically set to 0)
    qp_attr.ah_attr.src_path_bits = 0;       // Source path bits (used in LMC; set to 0 if not used)
    qp_attr.ah_attr.port_num = 1;            // Use port 1; adjust based on your setup

    /* Flags specifying which attributes to modify */
    int flags = IBV_QP_STATE | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
                IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER | IBV_QP_AV;

    /* Modify QP to transition to RTR state */
    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition QP to RTR state");
        return -1;
    }

    printf("[INFO] Queue Pair transitioned to RTR state successfully.\n");
    return 0;
}

/* remote/server side */
int main(int argc, char* argv[]) {
    const char* device_name = "mlx5_0";  	            // IB device name
    const uint8_t port_num = 1;          	            // Port number to use
    const size_t buffer_size = RDMA_BUFFER_SIZE;     	// Buffer size for RDMA operations

    /* Register SIGINT signal handler */
    struct sigaction sa;
    sa.sa_handler = cleanup_and_exit;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Sigaction");
        exit(1);
    }

    /* Set up socket */
    setup_socket();

    /* Step 1: Open the RDMA device context */
    struct ibv_context* context = create_context(device_name);
    if (!context) {
        fprintf(stderr, "[ERROR] Failed to open the RDMA device context.\n");
        cleanup_and_exit(-1);
    }
    clean_context = context;

    /* Step 2: Get the LID of the port */
    uint16_t lid = get_lid(context, port_num);
    if (lid == 0) {
        fprintf(stderr, "[ERROR] Failed to get the LID of the port.\n");
        cleanup_and_exit(-1);
    }
    send(new_socket, &lid, sizeof(lid), 0);

    /* Step 3: Create a protection domain */
    struct ibv_pd* pd = create_protection_domain(context);
    if (!pd) {
        fprintf(stderr, "[ERROR] Failed to create a protection domain.\n");
        cleanup_and_exit(-1);
    }
    clean_pd = pd;

    /* Step 4: Register a memory region */
    void* buffer = NULL;
    struct ibv_mr* mr = register_memory_region(pd, &buffer, buffer_size);
    if (!mr) {
        fprintf(stderr, "[ERROR] Failed to register memory region.\n");
        cleanup_and_exit(-1);
    }
    clean_mr = mr;
    clean_buffer = buffer;

    /* Create Completion Queue */
    int cq_size = 16;		        // Maximum number of CQ entries
    struct ibv_cq* cq = create_completion_queue(context, cq_size);
    if (!cq) {
    	fprintf(stderr, "[ERROR] Failed to create CQ.\n");
        cleanup_and_exit(-1);
    }
    clean_cq = cq;

	/* Step 5: Create a Queue Pair */
	struct ibv_qp* qp = create_queue_pair(pd, cq);
	if (!qp) {
        fprintf(stderr, "[ERROR] Failed to create a queue pair.\n");
        cleanup_and_exit(-1);
	}
    send(new_socket, &(qp->qp_num), sizeof(qp->qp_num), 0);
	clean_qp = qp;

    /* Send the remote size virtual address and rkey to local side */
    send(new_socket, &buffer, sizeof(buffer), 0);
    send(new_socket, &(mr->rkey), sizeof(mr->rkey), 0);

	/* Step 7: Transition QP to INIT state */
	if (transition_to_init_state(qp, 1)) {
    	fprintf(stderr, "[ERROR] Failed to transition QP to INIT state.\n");
        cleanup_and_exit(-1);
	}

	/* Step 8: Transition QP to RTR state */
	uint16_t local_lid;
	uint32_t local_qp_num;

    // Receive the local LID 
    if (recv(new_socket, &local_lid, sizeof(local_lid), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read local LID.\n");
        cleanup_and_exit(-1);
    }
    printf("[INFO] Local LID received by remote side : %u\n", local_lid);
 
    // Receive the local QP number
    if (recv(new_socket, &local_qp_num, sizeof(local_qp_num), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read destination QP number.\n");
        cleanup_and_exit(-1);
    }
    printf("[INFO] Local QP number received by remote side : %u\n", local_qp_num);

	if (transition_to_rtr_state(qp, local_lid, local_qp_num)) {
    	fprintf(stderr, "[ERROR] Failed to transition QP to RTR state.\n");
	    cleanup_and_exit(-1);
    }

    printf("[INFO] Remote Side B is ready.\n");
    while (1) pause();	        

    return 0;
}

