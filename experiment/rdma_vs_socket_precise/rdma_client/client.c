#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define HCA_PORT_NUM                1
#define RDMA_BUFFER_SIZE            ((1UL) << 0)
#define PORT                        8080

/* socket info */
int sockfd;

/* RDMA infos */
struct ibv_context* context;
uint16_t lid;
struct ibv_pd* pd;
struct ibv_cq* cq;
struct ibv_qp* qp;
void* buffer;
struct ibv_mr* mr;

/* time infos */
struct timespec start, end;

/* clean-up function */
void clean_up(int error_num) 
{
    fprintf(stdout, "\nCleaning up resources...\n");
    if (cq) {
        ibv_destroy_cq(cq);
        fprintf(stdout, "Complete queue destroyed successfully.\n");
    }
    if (qp) {
        ibv_destroy_qp(qp);
        fprintf(stdout, "Queue Pair destroyed successfully.\n");
    }
    if (mr) {
        ibv_dereg_mr(mr);
        fprintf(stdout, "Memory region mr deregistered successfully.\n");
    }
    if (buffer) {
        free(buffer);
        fprintf(stdout, "Client Buffer freed successfully.\n");
    }
    if (pd) {
        ibv_dealloc_pd(pd);
        fprintf(stdout, "Protection domain deallocated successfully.\n");
    }
    if (context) {
        ibv_close_device(context);
        fprintf(stdout, "RDMA device context closed successfully.\n");
    }
    if (sockfd) {
        close(sockfd);
        fprintf(stdout, "Client socket closed successfully.\n");
    }
    if (error_num == -1) exit(1);
    else exit(0);
}

/* signal handler */
void signal_handler (int signum) 
{
    if (signum == SIGINT) {
        fprintf(stdout, "SIGINT received.");
        clean_up(signum);
    }
    /* reserverd for other signals */
}

/* open the HCA(IB) and generate a userspace device context */
struct ibv_context* create_context(const char* device_name) 
{
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
            if (!context) {
                fprintf(stderr, "[ERROR] Failed to open RDMA device: %s\n", device_name);
                ibv_free_device_list(device_list); 
                return NULL;
            }
        }
    }

    ibv_free_device_list(device_list); 

    if (!context) fprintf(stderr, "[ERROR] Failed to find the device: %s\n", device_name);
    else fprintf(stdout, "[INFO] RDMA device context created successfully\n");

    return context;
}

/* query port attributes and get the LID */
uint16_t get_lid(struct ibv_context* context) 
{
    struct ibv_port_attr port_attr;
    if (ibv_query_port(context, HCA_PORT_NUM, &port_attr)) {
        perror("[ERROR] Failed to query the port attributes");
        return 0;
    }
    fprintf(stdout, "[INFO] LID of the port being used(port %u) : %u\n", HCA_PORT_NUM, port_attr.lid);
    return port_attr.lid;
}

/* create a protection domain */
struct ibv_pd* create_protection_domain(struct ibv_context* context) 
{
    struct ibv_pd* pd = ibv_alloc_pd(context);
    if (!pd) perror("[ERROR] Failed to allocate protection domain");
    else fprintf(stdout, "[INFO] Protection domain created successfully\n");
    return pd;
}

/* create a completion queue */
struct ibv_cq* create_completion_queue(struct ibv_context* context, int cq_size) 
{
    struct ibv_cq* cq = ibv_create_cq(context, cq_size, NULL, NULL, 0);
    if (!cq) perror("[ERROR] Failed to create completion queue");
    else fprintf(stdout, "[INFO] Completion queue created successfully with size %d bytes\n", cq_size);
    return cq;
}

/* create a queue pair */
struct ibv_qp* create_queue_pair(struct ibv_pd* pd, struct ibv_cq* cq) 
{
    struct ibv_qp_init_attr queue_pair_init_attr;
    memset(&queue_pair_init_attr, 0, sizeof(queue_pair_init_attr));

    /* queue pair configuration */
    queue_pair_init_attr.qp_type            = IBV_QPT_RC;      // reliable connection
    queue_pair_init_attr.sq_sig_all         = 1;               // generate WC for all send WRs
    queue_pair_init_attr.send_cq            = cq;              // send completion queue
    queue_pair_init_attr.recv_cq            = cq;              // receive completion queue
    queue_pair_init_attr.cap.max_send_wr    = 1;               // max send WRs in send queue
    queue_pair_init_attr.cap.max_recv_wr    = 1;               // max recv WRs in receive queue
    queue_pair_init_attr.cap.max_send_sge   = 1;               // max scatter-gather entries per send WR
    queue_pair_init_attr.cap.max_recv_sge   = 1;               // max scatter-gather entries per recv WR

    /* create the queue pair */
    struct ibv_qp* qp = ibv_create_qp(pd, &queue_pair_init_attr);
    if (!qp) perror("[ERROR] Failed to create queue pair");
    else fprintf(stdout, "[INFO] Queue pair created successfully with QP Number: %u\n", qp->qp_num);
    return qp;
}

/* transition the queue pair to INIT state */
int transition_to_init_state(struct ibv_qp* qp) 
{
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state        = IBV_QPS_INIT;          // target state: INIT
    qp_attr.pkey_index      = 0;                     // default partition key index
    qp_attr.port_num        = HCA_PORT_NUM;          // physical port on the RDMA device
    qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;

    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition the QP to INIT state");
        return -1;
    }

    fprintf(stdout, "[INFO] Transition the QP to INIT state successfully\n");
    return 0;
}

/* transition the queue pair to RTR(ready to receive) state */
int transition_to_rtr_state(struct ibv_qp *qp, uint16_t remote_lid, uint32_t remote_qp_num) 
{
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state                = IBV_QPS_RTR;           // target state: RTR
    qp_attr.path_mtu                = IBV_MTU_4096;          // path MTU; adjust based on your setup
    qp_attr.dest_qp_num             = remote_qp_num;         // destination queue pair number
    qp_attr.rq_psn                  = 0;                     // remote queue pair packet sequence number
    qp_attr.max_dest_rd_atomic      = 1;                     // maximum outstanding RDMA reads/atomic ops
    qp_attr.min_rnr_timer           = 12;                    // minimum RNR NAK timer

    /* address handle (AH) attributes for IB within the same subnet */
    qp_attr.ah_attr.is_global       = 0;                     // not using GRH (infiniband in the same subnet)
    qp_attr.ah_attr.dlid            = remote_lid;            // destination LID (local identifier)
    qp_attr.ah_attr.sl              = 0;                     // service level (QoS, typically set to 0)
    qp_attr.ah_attr.src_path_bits   = 0;                     // source path bits (used in LMC; set to 0 if not used)
    qp_attr.ah_attr.port_num        = HCA_PORT_NUM;          // use given port; adjust based on your setup

    /* flags specifying which attributes to modify */
    int flags = IBV_QP_STATE | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER | IBV_QP_AV;

    /* transition the QP to RTR state */
    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition the QP to RTR state");
        return -1;
    }

    fprintf(stdout, "[INFO] Transition the QP to RTR state successfully\n");
    return 0;
}

/* register a memory region */
struct ibv_mr* register_memory_region(struct ibv_pd* pd, size_t buffer_size, void** buffer) 
{
    *buffer = malloc(buffer_size);
    if (!*buffer) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for buffer\n");
        return NULL;
    }

    /* set the memory content */
    unsigned char cnt = 0;
    for (long i = 0; i < buffer_size; i++) {
        ((unsigned char *)(*buffer))[i] = cnt;
        cnt++;
    }

    struct ibv_mr* mr = ibv_reg_mr(pd, *buffer, buffer_size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
    if (!mr) {
        perror("[ERROR] Failed to register memory region");
        free(*buffer);
        *buffer = NULL;
        return NULL;
    }

    fprintf(stdout, "[INFO] Memory region registered successfully\n");
    return mr;
}

/* transition the queue pair to RTS(ready to send) state */
int transition_to_rts_state(struct ibv_qp *qp) 
{
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state        = IBV_QPS_RTS;
    qp_attr.timeout         = 14;
    qp_attr.retry_cnt       = 7;
    qp_attr.rnr_retry       = 7;
    qp_attr.sq_psn          = 0;
    qp_attr.max_rd_atomic   = 1;

    int flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition the QP to RTS state");
        return -1;
    }

    fprintf(stdout, "[INFO] Transition the QP to RTS state successfully\n");
    return 0;
}

/* post the RDMA write work request */
int perform_rdma_write(struct ibv_qp* qp, struct ibv_mr* mr, uint64_t remote_addr, uint32_t rkey) 
{
    struct ibv_sge sge;
    memset(&sge, 0, sizeof(sge));
    sge.addr                = (uintptr_t)mr->addr;     // client buffer address
    sge.length              = mr->length;              // client buffer length
    sge.lkey                = mr->lkey;                // client buffer lkey

    struct ibv_send_wr wr;
    memset(&wr, 0, sizeof(wr));
    wr.wr_id                = 0;
    wr.sg_list              = &sge;
    wr.num_sge              = 1;
    wr.opcode               = IBV_WR_RDMA_WRITE;    // RDMA write operation
    wr.send_flags           = IBV_SEND_SIGNALED;    // request completion notification
    wr.wr.rdma.remote_addr  = remote_addr;          // server memory address
    wr.wr.rdma.rkey         = rkey;                 // server memory region key

    struct ibv_send_wr* bad_wr = NULL;
    clock_gettime(CLOCK_REALTIME, &start);
    if (ibv_post_send(qp, &wr, &bad_wr)) {
        perror("[ERROR] Failed to post the RDMA write request");
        return -1;
    }

    //fprintf(stdout, "[INFO] RDMA write request posted successfully\n");
    return 0;
}

/* poll the completion queue (CQ) */
int poll_completion_queue(struct ibv_cq* cq) 
{
    struct ibv_wc wc;
    int num_completions;

    /* poll the CQ for completion */
    do {
        num_completions = ibv_poll_cq(cq, 1, &wc);
    } while (num_completions == 0);

    if (num_completions < 0) {
        fprintf(stderr, "[ERROR] Failed to poll the completion queue\n");
        return -1;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "[ERROR] Work completion error : %s\n", ibv_wc_status_str(wc.status));
        return -1;
    }

    fprintf(stdout, "[INFO] Completion polled successfully\n");
    return 0;
}

void setup_client_socket ()
{
    struct sockaddr_in server_addr;

    // create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        clean_up(-1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "10.10.10.2", &server_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        clean_up(-1);
    }

    // connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect failed");
        clean_up(-1);
    }
    printf("Connected to server.\n");
}

void calculate_bandwidth(struct timespec start, struct timespec end) {
    long long sec_diff = end.tv_sec - start.tv_sec;
    long long nsec_diff = end.tv_nsec - start.tv_nsec;

    // adjust if nanosecond difference is negative.
    if (nsec_diff < 0) {
        sec_diff--;
        nsec_diff += 1000000000L;
    }

    // calculate elapsed time in microseconds.
    long long elapsed_us = sec_diff * 1000000LL + nsec_diff / 1000LL;

    // calculate bandwidth in Gbps.
    double bandwidth_gbps = ((double) RDMA_BUFFER_SIZE * 8) / (elapsed_us * 1000.0);

    //print the elapsed time and bandwidth.
    printf("Elapsed time: %lld micro seconds, bandwidth: %.3f Gbps\n", elapsed_us, bandwidth_gbps);
}

int main (int argc, char* argv[]) 
{
    /* device name(RNIC physical port) */
    const char* device_name = "mlx5_0";

    /* register SIGINT signal handler */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    /* setup client socket */
    setup_client_socket();

    /* open the RDMA device context */
    context = create_context(device_name);
    if (!context) clean_up(-1);

    /* get the LID of the port */
    lid = get_lid(context);
    if (lid == 0) clean_up(-1);

    /* create a protection domain */
    pd = create_protection_domain(context);
    if (!pd) clean_up(-1);

    /* create a completion queue */
    const int cq_size = 16;
    cq = create_completion_queue(context, cq_size);
    if (!cq) clean_up(-1);

    /* create a queue pair */
    qp = create_queue_pair(pd, cq);
    if (!qp) clean_up(-1);

    /* register a memory region */
    size_t buffer_size = RDMA_BUFFER_SIZE;
    mr = register_memory_region(pd, buffer_size, &buffer);
    if (!mr) clean_up(-1);
    fprintf(stdout, "[INFO] Client buffer address: %p\n", buffer);
    fprintf(stdout, "[INFO] Client mr rkey : 0x%x\n", mr->rkey);

    /* transition the QP to INIT state */
    if (transition_to_init_state(qp)) clean_up(-1);

    /* transition the QP to RTR state */
    uint16_t server_lid;
    uint32_t server_qp_num;

    printf("Enter server LID: ");
    scanf("%" SCNu16, &server_lid);

    printf("Enter server QP number: ");
    scanf("%" SCNu32, &server_qp_num);

    /* transition the QP to RTR state */
    if (transition_to_rtr_state(qp, server_lid, server_qp_num)) clean_up(-1);

    /* transition the QP to RTS state */
    if (transition_to_rts_state(qp)) clean_up(-1);


    uint64_t server_addr;
    uint32_t server_rkey;

    printf("Enter server buffer address: ");
    scanf("%" SCNx64, &server_addr);

    printf("Enter server rkey: ");
    scanf("%" SCNx32, &server_rkey);

    /* post RDMA write and poll the completion queue */
    if (perform_rdma_write(qp, mr, server_addr, server_rkey)) clean_up(-1);
    if (poll_completion_queue(cq)) clean_up(-1);

    while (((unsigned char*)buffer)[0] == 0);
    clock_gettime(CLOCK_REALTIME, &end);
    if (((unsigned char*)buffer)[0] == 255) { fprintf(stdout, "Round trip success.\n"); }
    else { fprintf(stdout, "Round trip fail.\n"); }
    calculate_bandwidth(start, end);

    clean_up(0);
    exit(0);
}
