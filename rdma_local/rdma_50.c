#include <infiniband/verbs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>

#define RDMA_BUFFER_SIZE 16777216
#define PORT 8080

struct ibv_context* clean_context;
struct ibv_pd* clean_pd;
struct ibv_cq* clean_cq;
struct ibv_qp* clean_qp;
struct ibv_mr* clean_local_mr;
void* clean_local_buffer;

/* socket */
int sock = -1;                  //local socket descriptor
struct sockaddr_in serv_addr;

void cleanup_and_exit(int signum) {
    if (signum >= 0) printf("\n[INFO] Received SIGINT, cleaning up resources...\n");
    if (clean_context) {
        ibv_close_device(clean_context);
        printf("RDMA device context closed successfully.\n");
    }
    if (clean_cq) {
        ibv_destroy_cq(clean_cq);
        printf("Complete queue destroyed successfully.\n");
    }
    if (clean_qp) {
        ibv_destroy_qp(clean_qp);
        printf("Queue Pair destroyed successfully.\n");
    }
    if (clean_pd) {
        ibv_dealloc_pd(clean_pd);
        printf("Protection domain deallocated successfully.\n");
    }
    if (clean_local_mr) {
        ibv_dereg_mr(clean_local_mr);
        printf("Memory region deregistered successfully.\n");
    }
    if (clean_local_buffer) {
        free(clean_local_buffer);
        printf("Buffer memory freed successfully.\n");
    }
    if (sock != -1) {
        close(sock);
        printf("[INFO] Socket closed successfully.\n");
    }
    exit(1);
}

void connect_to_socket() {
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) cleanup_and_exit(-1);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Set the remote IP address (B's address)
    if (inet_pton(AF_INET, "10.10.10.2", &serv_addr.sin_addr) <= 0) {  
        perror("Invalid address / Address not supported");
        cleanup_and_exit(-1);
    }

    // Attempt to connect to remote B
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        cleanup_and_exit(-1);
    }

    printf("Local A : Connected to remote B (SDP mode).\n");
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

/* Create a Queue Pair */
struct ibv_qp* create_queue_pair(struct ibv_pd* pd, struct ibv_cq* cq) {
    struct ibv_qp_init_attr queue_pair_init_attr;
    memset(&queue_pair_init_attr, 0, sizeof(queue_pair_init_attr));

    /* Queue Pair configuration */
    queue_pair_init_attr.qp_type = IBV_QPT_RC;     // Reliable Connection
    queue_pair_init_attr.sq_sig_all = 1;           // Generate WC for all send WRs
    queue_pair_init_attr.send_cq = cq;             // Send Completion Queue
    queue_pair_init_attr.recv_cq = cq;             // Receive Completion Queue
    queue_pair_init_attr.cap.max_send_wr = 1;      // Max send WRs in Send Queue
    queue_pair_init_attr.cap.max_recv_wr = 1;      // Max recv WRs in Receive Queue
    queue_pair_init_attr.cap.max_send_sge = 1;     // Max scatter-gather entries per send WR
    queue_pair_init_attr.cap.max_recv_sge = 1;     // Max scatter-gather entries per recv WR

    /* Create the Queue Pair */
    struct ibv_qp* qp = ibv_create_qp(pd, &queue_pair_init_attr);
    if (!qp) {
        perror("[ERROR] Failed to create Queue Pair");
        return NULL;
    }

    return qp;
}

/* Transition Queue Pair to INIT state */
int transition_to_init_state(struct ibv_qp* qp, uint8_t port_num) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_INIT;          // Target state: INIT
    qp_attr.pkey_index = 0;                   // Default partition key index
    qp_attr.port_num = port_num;              // Physical port on the RDMA device
    qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;

    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition QP to INIT state");
        return -1;
    }

    printf("[INFO] QP transitioned to INIT state successfully.\n");
    return 0;
}


/* Transition Queue Pair to RTR (Ready to Receive) state */
int transition_to_rtr_state(struct ibv_qp *qp, uint16_t remote_lid, uint32_t remote_qp_num) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_RTR;          // Target state: RTR
    qp_attr.path_mtu = IBV_MTU_4096;         // Path MTU; adjust based on your setup
    qp_attr.dest_qp_num = remote_qp_num;       // Destination Queue Pair Number
    qp_attr.rq_psn = 0;                      // Remote Queue Pair Packet Sequence Number
    qp_attr.max_dest_rd_atomic = 1;          // Maximum outstanding RDMA reads/atomic ops
    qp_attr.min_rnr_timer = 12;              // Minimum RNR NAK timer

    /* Address handle (AH) attributes for IB within the same subnet */
    qp_attr.ah_attr.is_global = 0;           // Not using GRH (Infiniband in the same subnet)
    qp_attr.ah_attr.dlid = remote_lid;             // Destination LID (Local Identifier)
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

    printf("[INFO] QP transitioned to RTR state successfully.\n");
    return 0;
}

/* Register a Memory Region */
struct ibv_mr* register_memory_region(struct ibv_pd* pd, size_t buffer_size, void** buffer) {
    *buffer = malloc(buffer_size);
    if (!*buffer) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for buffer.\n");
        return NULL;
    }

    memset(*buffer, 0, buffer_size);	    // Initialize buffer with zeros

    struct ibv_mr* mr = ibv_reg_mr(pd, *buffer, buffer_size, IBV_ACCESS_LOCAL_WRITE |
                                                     IBV_ACCESS_REMOTE_READ |
                                                     IBV_ACCESS_REMOTE_WRITE);
    if (!mr) {
        perror("[ERROR] Failed to register memory region");
        free(*buffer);
        return NULL;
    }

    printf("[INFO] Memory region registered successfully.\n");
    return mr;
}

int transition_to_rts_state(struct ibv_qp *qp) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_RTS;
    qp_attr.timeout = 14;
    qp_attr.retry_cnt = 7;
    qp_attr.rnr_retry = 7;  
    qp_attr.sq_psn = 0;
    qp_attr.max_rd_atomic = 1;

    int flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition QP to RTS state");
        return -1;
    }

    printf("[INFO] QP transitioned to RTS state successfully.\n");
    return 0;
}

int perform_rdma_read(struct ibv_qp* qp, struct ibv_mr* mr, uint64_t remote_addr, uint32_t rkey) {
    struct ibv_sge sge;
    memset(&sge, 0, sizeof(sge));
    sge.addr   = (uintptr_t)mr->addr;		// Local buffer address
    sge.length = mr->length;           		// Local buffer length
    sge.lkey   = mr->lkey;             		// Local buffer lkey

    struct ibv_send_wr wr;
    memset(&wr, 0, sizeof(wr));
    wr.wr_id      = 0;
    wr.sg_list    = &sge;
    wr.num_sge    = 1;
    wr.opcode     = IBV_WR_RDMA_READ;  		// RDMA Read operation
    wr.send_flags = IBV_SEND_SIGNALED; 		// Request completion notification
    wr.wr.rdma.remote_addr = remote_addr; 	// Remote memory address
    wr.wr.rdma.rkey        = rkey;        	// Remote memory region key

    struct ibv_send_wr* bad_wr = NULL;
    if (ibv_post_send(qp, &wr, &bad_wr)) {
        perror("[ERROR] Failed to post RDMA Read request");
        return -1;
    }

    printf("[INFO] RDMA Read request posted successfully.\n");
    return 0;
}

/* Poll the Completion Queue (CQ) */
int poll_completion_queue(struct ibv_cq* cq) {
    struct ibv_wc wc;
    int num_completions;

    /* Poll the CQ for completion */
    do {
        num_completions = ibv_poll_cq(cq, 1, &wc);
    } while (num_completions == 0);		    // Continue polling if no completion

    if (num_completions < 0) {
        fprintf(stderr, "[ERROR] Failed to poll Completion Queue.\n");
        return -1;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "[ERROR] Work Completion error : %s\n", ibv_wc_status_str(wc.status));
        return -1;
    }

    printf("[INFO] Completion polled successfully.\n");
    return 0;
}


int main(int argc, char* argv[]) {
    const char* device_name = "mlx5_0"; 	    // Replace with your IB device name
    const int cq_size = 16; 			        // Maximum number of CQ entries
    const uint8_t port_num = 1;          	    // Port number to use
    size_t buffer_size = RDMA_BUFFER_SIZE; 		// Buffer size for RDMA operations

	/* Register SIGINT signal handler */
	struct sigaction sa;
	sa.sa_handler = cleanup_and_exit;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);

    /* Set up socket connection */
    connect_to_socket();

    /* Step 1: Open the RDMA device context */
    struct ibv_context* context = create_context(device_name);
    if (!context) { 
        fprintf(stderr, "[ERROR] Failed to open the RDMA device context.\n");
        cleanup_and_exit(-1);
    }
	clean_context = context;

    /* Get the LID of the port */
    uint16_t lid = get_lid(context, port_num);
    if (lid == 0) {
        fprintf(stderr, "[ERROR] Failed to get the LID of the port.\n");
        cleanup_and_exit(-1);
    }
    send(sock, &lid, sizeof(lid), 0);

    /* Step 2: Create a protection domain */
    struct ibv_pd* pd = create_protection_domain(context);
    if (!pd) {
        fprintf(stderr, "[ERROR] Failed to create a protection domain.\n");
        cleanup_and_exit(-1);
    }
	clean_pd = pd;

    /* Step 3: Create a Completion Queue */
    struct ibv_cq* cq = create_completion_queue(context, cq_size);
    if (!cq) {
        fprintf(stderr, "[ERROR] Failed to create CQ.\n");   
        cleanup_and_exit(-1);
    }
	clean_cq = cq;

    /* Step 4: Create a Queue Pair */
    struct ibv_qp* qp = create_queue_pair(pd, cq);
    if (!qp) {
        fprintf(stderr, "[ERROR] Failed to create a queue pair.\n");
        cleanup_and_exit(-1);
    }
	clean_qp = qp;
    printf("[INFO] Queue Pair created successfully with QP Number: %u\n", qp->qp_num);
    send(sock, &(qp->qp_num), sizeof(qp->qp_num), 0);

    /* Step 5: Register a memory region */
    void* local_buffer = NULL;
    struct ibv_mr* local_mr = register_memory_region(pd, buffer_size, &local_buffer);
    if (!local_mr) {
        fprintf(stderr, "[ERROR] Failed to register memory region.\n");   
        cleanup_and_exit(-1);
    }
	clean_local_buffer = local_buffer;
	clean_local_mr = local_mr;

    /* Step 6: Transition QP to INIT state */
    if (transition_to_init_state(qp, port_num)) {
        fprintf(stderr, "[ERROR] Failed to transition QP to INIT state.\n");
        cleanup_and_exit(-1);
    }

    /* Step 7: Transition QP to RTR state */
    uint16_t remote_lid;
    uint32_t remote_qp_num;

    // Receive the remote LID 
    if (recv(sock, &remote_lid, sizeof(remote_lid), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read destination LID.\n");
        cleanup_and_exit(-1);
    }
    printf("[DEBUG] Remote LID received by local side : %u\n", remote_lid);

    // Receive the remote QP number
    if (recv(sock, &remote_qp_num, sizeof(remote_qp_num), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read destination QP number.\n");
        cleanup_and_exit(-1);
    }
    printf("[DEBUG] Remote QP number received by local side : %u\n", remote_qp_num);

    if (transition_to_rtr_state(qp, remote_lid, remote_qp_num)) {
        fprintf(stderr, "[ERROR] Failed to transition QP to RTR state.\n");
        cleanup_and_exit(-1);
    }

	/* Step 8: Transition QP to RTS state */
    if (transition_to_rts_state(qp)) {
        fprintf(stderr, "[ERROR] Failed to transition QP to RTS state.\n");
        cleanup_and_exit(-1);
    }

	/* Step 9: Perform RDMA Read */
    uint64_t remote_addr;
    uint32_t remote_rkey;
    // Receive the remote memory address
    if (recv(sock, &remote_addr, sizeof(remote_addr), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to receive the remote memory address.\n");
        cleanup_and_exit(-1);
    }
    printf("[DEBUG] Remote virtual address received by local side : %p\n", (void *)remote_addr);

    // Receive the remote rkey
    if (recv(sock, &remote_rkey, sizeof(remote_rkey), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to receive the remote rkey.\n");
        cleanup_and_exit(-1);
    }
    printf("[DEBUG] Remote rkey received by local side : %x\n", remote_rkey);


    if (perform_rdma_read(qp, local_mr, remote_addr, remote_rkey)) {
        fprintf(stderr, "[ERROR] RDMA Read operation failed.\n");
        cleanup_and_exit(-1);
    }

	 /* Step 10: Poll Completion Queue */
    if (poll_completion_queue(cq)) {
        fprintf(stderr, "[ERROR] Failed to poll Completion Queue.\n");
        cleanup_and_exit(-1);
    }
    printf("[INFO] RDMA Read completed. Data in buffer: %s\n", (char*)local_buffer);

    /* Cleanup resources */
    printf("\n[INFO] Cleaning up resources...\n");
    ibv_close_device(context);
    printf("[INFO] RDMA device context closed successfully.\n");
    ibv_destroy_cq(cq);
    printf("[INFO] Completion Queue destroyed successfully.\n");
    ibv_destroy_qp(qp);
    printf("[INFO] Queue Pair destroyed successfully.\n");
    ibv_dereg_mr(local_mr);
    free(local_buffer);
    printf("[INFO] Memory region deregistered and buffer freed successfully.\n");
    ibv_dealloc_pd(pd);
    printf("[INFO] Protection domain deallocated successfully.\n");
    close(sock);
    printf("[INFO] Socket closed successfully.\n");

    return 0;
}
