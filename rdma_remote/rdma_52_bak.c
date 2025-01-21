#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

struct ibv_qp* global_qp = NULL;
struct ibv_mr* global_mr = NULL;
void* global_buffer = NULL;
struct ibv_pd* global_pd = NULL;
struct ibv_context* global_context = NULL;

/* Open the HCA and generate a userspace device context */
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
    strncpy(*buffer, "Hello world", size - 1);

    struct ibv_mr* mr = ibv_reg_mr(pd, *buffer, size,
                                   IBV_ACCESS_REMOTE_READ |
                                   IBV_ACCESS_REMOTE_WRITE |
                                   IBV_ACCESS_LOCAL_WRITE);
    if (!mr) {
        perror("[ERROR] Failed to register memory region");
        free(*buffer);
        return NULL;
    }

    printf("[INFO] Memory region registered successfully.\n");
    printf("[INFO] Remote side string content in the buffer : %s, size of the data that will be read : %zu bytes\n", (char*)*buffer, size);
    printf("[INFO] Remote side virtual address : %p\n", *buffer);
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

int transition_to_rtr_state(struct ibv_qp *qp, uint16_t dlid, uint32_t dest_qp_num) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_RTR;          // Target state: RTR
    qp_attr.path_mtu = IBV_MTU_4096;         // Path MTU; adjust based on your setup
    qp_attr.dest_qp_num = dest_qp_num;       // Destination Queue Pair Number
    qp_attr.rq_psn = 0;                      // Remote Queue Pair Packet Sequence Number
    qp_attr.max_dest_rd_atomic = 1;          // Maximum outstanding RDMA reads/atomic ops
    qp_attr.min_rnr_timer = 12;              // Minimum RNR NAK timer

    /* Address handle (AH) attributes for IB within the same subnet */
    qp_attr.ah_attr.is_global = 0;           // Not using GRH (Infiniband in the same subnet)
    qp_attr.ah_attr.dlid = dlid;             // Destination LID (Local Identifier)
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

/* Signal handler for cleanup */
void cleanup_and_exit(int signum) {
    printf("\nSIGINT received. Cleaning up resources...\n");

    if (global_qp) {
        ibv_destroy_qp(global_qp);
        printf("Queue Pair destroyed successfully.\n");
    }
    if (global_mr) {
        ibv_dereg_mr(global_mr);
        printf("Memory region deregistered successfully.\n");
    }
    if (global_buffer) {
        free(global_buffer);
        printf("Buffer memory freed successfully.\n");
    }
    if (global_pd) {
        ibv_dealloc_pd(global_pd);
        printf("Protection domain deallocated successfully.\n");
    }
    if (global_context) {
        ibv_close_device(global_context);
        printf("RDMA device context closed successfully.\n");
    }

    exit(EXIT_SUCCESS);
}


int main() {
    const char* device_name = "mlx5_0";  	// RDMA device name
    const uint8_t port_num = 1;          	// Port number to use
    const size_t buffer_size = 16777216;     	// Size of the memory buffer

    /* Register SIGINT signal handler */
    struct sigaction sa;
    sa.sa_handler = cleanup_and_exit;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    /* Step 1: Open the RDMA device context */
    struct ibv_context* context = create_context(device_name);
    if (!context) {
        return -1;
    }
    global_context = context;

    /* Step 2: Get the LID of the port */
    uint16_t lid = get_lid(context, port_num);
    if (lid == 0) {
        ibv_close_device(context);
        return -1;
    }

    /* Step 3: Create a protection domain */
    struct ibv_pd* pd = create_protection_domain(context);
    if (!pd) {
        ibv_close_device(context);
        return -1;
    }
    global_pd = pd;

    /* Step 4: Register a memory region */
    void* buffer = NULL;
    struct ibv_mr* mr = register_memory_region(pd, &buffer, buffer_size);
    if (!mr) {
        ibv_dealloc_pd(pd);
        ibv_close_device(context);
        return -1;
    }
    global_mr = mr;
    global_buffer = buffer;


    /* Create Completion Queue */
    int cq_size = 16;		// Maximum number of CQ entries
    struct ibv_cq* cq = create_completion_queue(context, cq_size);
    if (!cq) {
    	fprintf(stderr, "[ERROR] Failed to create CQ. Exiting...\n");
	ibv_dealloc_pd(pd);
	ibv_close_device(context);
	return -1;
    }

	/* Step 5: Create a Queue Pair */
	struct ibv_qp* qp = create_queue_pair(pd, cq);
	if (!qp) {
        ibv_dereg_mr(mr);
        free(buffer);
    	ibv_dealloc_pd(pd);
    	ibv_close_device(context);
   		return -1;
	}
	  global_qp = qp;

	/* Step 7: Transition QP to INIT state */
	if (transition_to_init_state(qp, 1)) {
    	fprintf(stderr, "[ERROR] Failed to transition QP to INIT state. Exiting...\n");
    	ibv_destroy_qp(qp);
        ibv_dereg_mr(mr);
        free(buffer);
    	ibv_dealloc_pd(pd);
    	ibv_close_device(context);
    	return -1;
	}


	/* Step 8: Transition QP to RTR state */
	uint16_t dlid;
	uint32_t dest_qp_num;

	printf("Please enter LID (dlid) in local size(A) : ");
	if (scanf("%hu", &dlid) != 1) {
    	fprintf(stderr, "[ERROR] Failed to read dlid.\n");
    	ibv_destroy_qp(qp);
    	ibv_dereg_mr(mr);
    	free(buffer);
    	ibv_dealloc_pd(pd);
    	ibv_close_device(context);
    	return -1;
	}

	printf("Please enter QP number (dest_qp_num) in local size(A) : ");
	if (scanf("%u", &dest_qp_num) != 1) {
    	fprintf(stderr, "[ERROR] Failed to read dest_qp_num.\n");
    	ibv_destroy_qp(qp);
    	ibv_dereg_mr(mr);
    	free(buffer);
    	ibv_dealloc_pd(pd);
    	ibv_close_device(context);
    	return -1;
	}

	if (transition_to_rtr_state(qp, dlid, dest_qp_num)) {
    	fprintf(stderr, "[ERROR] Failed to transition QP to RTR state.\n");
    	ibv_destroy_qp(qp);
    	ibv_dereg_mr(mr);
    	free(buffer);
    	ibv_dealloc_pd(pd);
    	ibv_close_device(context);
    	return -1;
	}


	printf("[INFO] Remote Side B is ready. Press Ctrl+C to exit.\n");
    while (1) {
        pause();	// Wait indefinitely until manually terminated
    }

    /* Cleanup resources */
	ibv_destroy_qp(qp);
    printf("Queue pair destroyed successfully.\n");
    ibv_dereg_mr(mr);
    printf("Memory region deregistered successfully.\n");
    free(buffer);
    printf("Buffer memory freed successfully.\n");
    ibv_dealloc_pd(pd);
    printf("Protection domain deallocated successfully.\n");
    ibv_close_device(context);
    printf("RDMA device context closed successfully.\n");

    return 0;
}

