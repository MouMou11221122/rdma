#include <infiniband/verbs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>

#define RDMA_BUFFER_SIZE            ((1UL) << 30)
#define HCA_DEVICE_NAME             "mlx5_0" 
#define HCA_PORT_NUM                1

#define PORT 8080

/*
struct ibv_context* clean_context;
struct ibv_pd* clean_pd;
struct ibv_cq* clean_cq;
struct ibv_qp* clean_qp;
struct ibv_mr* clean_local_mr;
void* clean_local_buffer;
*/

/* RDMA infos */
struct ibv_context* ccontext;
uint16_t lid;
struct ibv_pd* pd;
struct ibv_cq* cq;
struct ibv_qp* qp;
void* local_buffer;
struct ibv_mr* local_mr;

/* socket */
int sock = -1;                  //local socket descriptor
struct sockaddr_in serv_addr;

/* calculate the time difference in micro seconds */
long timeval_diff_micro(const struct timeval *start, const struct timeval *end) {
    long seconds_diff = end->tv_sec - start->tv_sec;        
    long microseconds_diff = end->tv_usec - start->tv_usec; 

    // adjust if microseconds difference is negative
    if (microseconds_diff < 0) {
        seconds_diff -= 1;
        microseconds_diff += 1000000;
    }

    // total time difference in microseconds
    return seconds_diff * 1000000 + microseconds_diff;
}

void clean_up() {
    printf("\n");
    if (signum >= 0) printf("SIGINT received. ");
    printf("Cleaning up resources...\n");
    if (cq) {
        ibv_destroy_cq(cq);
        printf("Complete queue destroyed successfully.\n");
    }
    if (qp) {
        ibv_destroy_qp(qp);
        printf("Queue Pair destroyed successfully.\n");
    }
    if (clean_local_mr) {
        ibv_dereg_mr(clean_local_mr);
        printf("Memory region deregistered successfully.\n");
    }
    if (clean_local_buffer) {
        free(clean_local_buffer);
        printf("Buffer memory freed successfully.\n");
    }
    if (pd) {
        ibv_dealloc_pd(pd);
        printf("Protection domain deallocated successfully.\n");
    }
    if (context) {
        ibv_close_device(context);
        printf("RDMA device context closed successfully.\n");
    }
    if (sock != -1) {
        close(sock);
        printf("Socket closed successfully.\n");
    }
    exit(1);
}

/* signal handler */
void signal_handler (int signum) {

}

void connect_to_socket() {
    // create client socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) cleanup_and_exit(-1);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // set the server's IP address 
    if (inet_pton(AF_INET, "10.10.10.2", &serv_addr.sin_addr) <= 0) {  
        perror("[ERROR] Invalid IP address");
        cleanup_and_exit(-1);
    }

    // attempt to connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("[ERROR] Connection failed");
        cleanup_and_exit(-1);
    }

    printf("[INFO] Client has connected to the server.\n");
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
    else fprintf(stdout, "[INFO] Context created successfully.\n");

    return context;
}

/* query port attributes and get the LID */
uint16_t get_lid(struct ibv_context* context) {
    struct ibv_port_attr port_attr;
    if (ibv_query_port(context, HCA_PORT_NUM, &port_attr)) {
        perror("[ERROR] Failed to query port attributes");
        return 0;
    }
    printf("[INFO] LID of the port being used(port %u) : %u\n", HCA_PORT_NUM, port_attr.lid);
    return port_attr.lid;
}

/* create a protection domain */
struct ibv_pd* create_protection_domain(struct ibv_context* context) {
    struct ibv_pd* pd = ibv_alloc_pd(context);
    if (!pd) perror("[ERROR] Failed to allocate protection domain");
    else printf("[INFO] Protection domain created successfully.\n");
    return pd;
}

/* create a completion queue */
struct ibv_cq* create_completion_queue(struct ibv_context* context, int cq_size) {
    struct ibv_cq* cq = ibv_create_cq(context, cq_size, NULL, NULL, 0);
    if (!cq) perror("[ERROR] Failed to create completion queue");
    else printf("[INFO] Completion queue created successfully with size %d bytes.\n", cq_size);
    return cq;
}

/* create a queue pair */
struct ibv_qp* create_queue_pair(struct ibv_pd* pd, struct ibv_cq* cq) {
    struct ibv_qp_init_attr queue_pair_init_attr;
    memset(&queue_pair_init_attr, 0, sizeof(queue_pair_init_attr));

    /* queue pair configuration */
    queue_pair_init_attr.qp_type = IBV_QPT_RC;     // reliable connection
    queue_pair_init_attr.sq_sig_all = 1;           // generate WC for all send WRs
    queue_pair_init_attr.send_cq = cq;             // send completion queue
    queue_pair_init_attr.recv_cq = cq;             // receive completion queue
    queue_pair_init_attr.cap.max_send_wr = 1;      // max send WRs in send queue
    queue_pair_init_attr.cap.max_recv_wr = 1;      // max recv WRs in receive queue
    queue_pair_init_attr.cap.max_send_sge = 1;     // max scatter-gather entries per send WR
    queue_pair_init_attr.cap.max_recv_sge = 1;     // max scatter-gather entries per recv WR

    /* create the queue pair */
    struct ibv_qp* qp = ibv_create_qp(pd, &queue_pair_init_attr);
    if (!qp) {
        perror("[ERROR] Failed to create queue pair");
        return NULL;
    }
    printf("[INFO] Queue pair created successfully with QP Number: %u\n", qp->qp_num);
    return qp;
}

/* transition the queue pair to INIT state */
int transition_to_init_state(struct ibv_qp* qp) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_INIT;          // target state: INIT
    qp_attr.pkey_index = 0;                   // default partition key index
    qp_attr.port_num = HCA_PORT_NUM;          // physical port on the RDMA device
    qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;

    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition the QP to INIT state");
        return -1;
    }

    printf("[INFO] Transition the QP to INIT state successfully.\n");
    return 0;
}


/* transition the queue pair to RTR (ready to receive) state */
int transition_to_rtr_state(struct ibv_qp *qp, uint16_t remote_lid, uint32_t remote_qp_num) {
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_RTR;                     // target state: RTR
    qp_attr.path_mtu = IBV_MTU_4096;                    // path MTU; adjust based on your setup
    qp_attr.dest_qp_num = remote_qp_num;                // destination queue pair number
    qp_attr.rq_psn = 0;                                 // remote queue pair packet sequence number
    qp_attr.max_dest_rd_atomic = 1;                     // maximum outstanding RDMA reads/atomic ops
    qp_attr.min_rnr_timer = 12;                         // minimum RNR NAK timer

    /* address handle (AH) attributes for IB within the same subnet */
    qp_attr.ah_attr.is_global = 0;                      // not using GRH (infiniband in the same subnet)
    qp_attr.ah_attr.dlid = remote_lid;                  // destination LID (local identifier)
    qp_attr.ah_attr.sl = 0;                             // service level (QoS, typically set to 0)
    qp_attr.ah_attr.src_path_bits = 0;                  // source path bits (used in LMC; set to 0 if not used)
    qp_attr.ah_attr.port_num = HCA_PORT_NUM;            // use given port; adjust based on your setup

    /* flags specifying which attributes to modify */
    int flags = IBV_QP_STATE | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER | IBV_QP_AV;

    /* transition the QP to RTR state */
    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition the QP to RTR state");
        return -1;
    }

    printf("[INFO] Transition the QP to RTR state successfully.\n");
    return 0;
}

/* register a memory region */
struct ibv_mr* register_memory_region(struct ibv_pd* pd, size_t buffer_size, void** buffer) {
    *buffer = malloc(buffer_size);
    if (!*buffer) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for buffer.\n");
        return NULL;
    }

    memset(*buffer, 0, buffer_size);	    // initialize buffer with zeros

    struct ibv_mr* mr = ibv_reg_mr(pd, *buffer, buffer_size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
    if (!mr) {
        perror("[ERROR] Failed to register memory region");
        free(*buffer);
        *buffer = NULL;
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

    int flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition the QP to RTS state");
        return -1;
    }

    printf("[INFO] Transition the QP to RTS state successfully.\n");
    return 0;
}

int perform_rdma_read(struct ibv_qp* qp, struct ibv_mr* mr, uint64_t remote_addr, uint32_t rkey) {
    struct ibv_sge sge;
    memset(&sge, 0, sizeof(sge));
    sge.addr  = (uintptr_t)mr->addr;		// client buffer address
    sge.length = mr->length;           		// client buffer length
    sge.lkey  = mr->lkey;             		// client buffer lkey

    struct ibv_send_wr wr;
    memset(&wr, 0, sizeof(wr));
    wr.wr_id  = 0;
    wr.sg_list  = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_RDMA_READ;  		    // RDMA read operation
    wr.send_flags = IBV_SEND_SIGNALED; 		// request completion notification
    wr.wr.rdma.remote_addr = remote_addr; 	// server memory address
    wr.wr.rdma.rkey = rkey;        	        // server memory region key

    struct ibv_send_wr* bad_wr = NULL;
    if (ibv_post_send(qp, &wr, &bad_wr)) {
        perror("[ERROR] Failed to post the RDMA Read request");
        return -1;
    }

    printf("[INFO] RDMA read request posted successfully.\n");
    return 0;
}

/* poll the completion queue (CQ) */
int poll_completion_queue(struct ibv_cq* cq) {
    struct ibv_wc wc;
    int num_completions;

    /* poll the CQ for completion */
    do {
        num_completions = ibv_poll_cq(cq, 1, &wc);
    } while (num_completions == 0);		   

    if (num_completions < 0) {
        fprintf(stderr, "[ERROR] Failed to poll the completion queue.\n");
        return -1;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "[ERROR] Work completion error : %s\n", ibv_wc_status_str(wc.status));
        return -1;
    }

    printf("[INFO] Completion polled successfully.\n");
    return 0;
}

/* function to calculate bandwidth */
double calculate_bandwidth(long time_us) {
    size_t data_size_bits = RDMA_BUFFER_SIZE * 8;
    double time_sec = time_us / 1000000.0;
    double bandwidth_bps = data_size_bits / time_sec;
    double bandwidth_gbps = bandwidth_bps / 1e9;
    return bandwidth_gbps;
}

/* client */
int main(int argc, char* argv[]) {
    const char* device_name = HCA_DEVICE_NAME; 	    

    struct timeval start, end;
    long elapsed_time;    

	/* register SIGINT signal handler */
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);

    /* set up socket connection */
    connect_to_socket();

    /* open the RDMA device context */
    context = create_context(device_name);
    if (!context) { 
        fprintf(stderr, "[ERROR] Failed to open the RDMA device context.\n");
        cleanup_and_exit(-1);
    }

    /* get the LID of the port */
    lid = get_lid(context);
    if (lid == 0) {
        fprintf(stderr, "[ERROR] Failed to get the LID of the port.\n");
        cleanup_and_exit(-1);
    }
    send(sock, &lid, sizeof(lid), 0);   // send the client LID to the server

    /* create a protection domain */
    pd = create_protection_domain(context);
    if (!pd) {
        fprintf(stderr, "[ERROR] Failed to create protection domain.\n");
        cleanup_and_exit(-1);
    }

    /* create a completion queue */
    const int cq_size = 16; 			       
    cq = create_completion_queue(context, cq_size);
    if (!cq) {
        fprintf(stderr, "[ERROR] Failed to create completion queue.\n");   
        cleanup_and_exit(-1);
    }

    /* create a queue pair */
    qp = create_queue_pair(pd, cq);
    if (!qp) {
        fprintf(stderr, "[ERROR] Failed to create queue pair.\n");
        cleanup_and_exit(-1);
    }
    send(sock, &(qp->qp_num), sizeof(qp->qp_num), 0);   // send the client QP number to the server

    /* register a memory region */
    size_t buffer_size = RDMA_BUFFER_SIZE; 	
    local_mr = register_memory_region(pd, buffer_size, &local_buffer);
    if (!local_mr) {
        fprintf(stderr, "[ERROR] Failed to register memory region.\n");   
        cleanup_and_exit(-1);
    }

    /* transition the QP to INIT state */
    if (transition_to_init_state(qp)) {
        fprintf(stderr, "[ERROR] Failed to transition the QP to INIT state.\n");
        cleanup_and_exit(-1);
    }

    /* transition the QP to RTR state */
    uint16_t remote_lid;
    uint32_t remote_qp_num;

    // receive the server LID 
    if (recv(sock, &remote_lid, sizeof(remote_lid), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read the server LID.\n");
        cleanup_and_exit(-1);
    }
    printf("[INFO] Server LID received by the client : %u\n", remote_lid);

    // receive the server QP number
    if (recv(sock, &remote_qp_num, sizeof(remote_qp_num), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read server QP number.\n");
        cleanup_and_exit(-1);
    }
    printf("[INFO] Server QP number received by the client : %u\n", remote_qp_num);

    if (transition_to_rtr_state(qp, remote_lid, remote_qp_num)) {
        fprintf(stderr, "[ERROR] Failed to transition the QP to RTR state.\n");
        cleanup_and_exit(-1);
    }

	/* transition the QP to RTS state */
    if (transition_to_rts_state(qp)) {
        fprintf(stderr, "[ERROR] Failed to transition the QP to RTS state.\n");
        cleanup_and_exit(-1);
    }

	/* perform the RDMA read */
    uint64_t remote_addr;
    uint32_t remote_rkey;

    // receive the server's virtual memory address
    if (recv(sock, &remote_addr, sizeof(remote_addr), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to receive the server virtual memory address.\n");
        cleanup_and_exit(-1);
    }
    printf("[INFO] Server virtual memory address received by the client : %p\n", (void *)remote_addr);

    // receive the server's rkey
    if (recv(sock, &remote_rkey, sizeof(remote_rkey), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to receive the server rkey.\n");
        cleanup_and_exit(-1);
    }
    printf("[INFO] Server rkey received by the client : 0x%x\n", remote_rkey);

    gettimeofday(&start, NULL);
    if (perform_rdma_read(qp, local_mr, remote_addr, remote_rkey)) {
        fprintf(stderr, "[ERROR] RDMA read operation failed.\n");
        cleanup_and_exit(-1);
    }

	/* polls the completion queue */
    if (poll_completion_queue(cq)) {
        fprintf(stderr, "[ERROR] Failed to poll the completion queue.\n");
        cleanup_and_exit(-1);
    }
    gettimeofday(&end, NULL);

    printf("[INFO] RDMA read operation completed.\n");

    /* check the result
    for (long long i = 0; i < RDMA_BUFFER_SIZE; i++) {
        printf("Loop %lld : ", i);
        printf("%u\n", ((unsigned char *)local_buffer)[i]);
    } 
    */

    /* get the real time of a single read operation */
    elapsed_time = timeval_diff_micro(&start, &end);
    printf("[INFO] Elapsed time of a single RDMA read(%ld bytes) : %ld us\n", RDMA_BUFFER_SIZE, elapsed_time);

    /* calculate the read bandwidth of read operation */
    double read_bandwidth;
    read_bandwidth = calculate_bandwidth(elapsed_time);
    printf("[INFO] Read bandwidth : %.6f Gbps\n", read_bandwidth); 

    /* cleanup resources */
    printf("Cleaning up resources...\n");
    if (cq) {
        ibv_destroy_cq(cq);
        printf("Complete queue destroyed successfully.\n");
    }
    if (qp) {
        ibv_destroy_qp(qp);
        printf("Queue Pair destroyed successfully.\n");
    }
    if (local_mr) {
        ibv_dereg_mr(local_mr);
        printf("Memory region deregistered successfully.\n");
    }
    if (local_buffer) {
        free(local_buffer);
        printf("Buffer memory freed successfully.\n");
    }
    if (pd) {
        ibv_dealloc_pd(pd);
        printf("Protection domain deallocated successfully.\n");
    }
    if (context) {
        ibv_close_device(context);
        printf("RDMA device context closed successfully.\n");
    }
    if (sock != -1) {
        close(sock);
        printf("Socket closed successfully.\n");
    }

    return 0;
}
