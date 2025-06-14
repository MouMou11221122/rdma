#include <infiniband/verbs.h> 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define HCA_PORT_NUM                1
#define RDMA_BUFFER_SIZE            ((1UL) << 30)
#define PORT                        8080

/* socket info */
int sockfd, clientfd;

/* RDMA infos */
struct ibv_context* context;
uint16_t lid;
struct ibv_pd* pd; 
struct ibv_cq* cq; 
struct ibv_qp* qp; 
void* buffer;
struct ibv_mr* mr;

/* clean-up function */
void clean_up(int error_num) {     
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
    if (clientfd) {
        fprintf(stdout, "Client socket fd closed successfully.\n");
        close(clientfd);
    }
    if (sockfd) {
        fprintf(stdout, "Server socket fd closed successfully.\n");
        close(sockfd);
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
                fprintf(stderr, "[ERROR] Failed to open the RDMA device: %s\n", device_name);
                ibv_free_device_list(device_list); 
                return NULL;
            }   
        }   
    }   
 
    ibv_free_device_list(device_list); 
 
    if (!context) fprintf(stderr, "[ERROR] Failed to find the RDMA device: %s\n", device_name);
    else fprintf(stdout, "[INFO] RDMA device context created successfully\n");
 
    return context;
}

/* query port attributes and get the LID */
uint16_t get_lid(struct ibv_context* context) 
{
    struct ibv_port_attr port_attr;
    if (ibv_query_port(context, HCA_PORT_NUM, &port_attr)) {
        perror("[ERROR] Failed to query port attributes");
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

/* register a memory region */
struct ibv_mr* register_memory_region(struct ibv_pd* pd, size_t size, void** buffer) 
{
    *buffer = malloc(size);
    if (!(*buffer)) {
        perror("[ERROR] Failed to allocate buffer");
        return NULL;
    }

    struct ibv_mr* mr = ibv_reg_mr(pd, *buffer, size, IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE);
    if (!mr) {
        perror("[ERROR] Failed to register memory region");
        free(*buffer);
        *buffer = NULL;
        return NULL;
    }
    fprintf(stdout, "[INFO] Memory region registered successfully\n");
    memset(*buffer, 0, size);

    return mr;
}

/* create a queue pair */
struct ibv_qp* create_queue_pair(struct ibv_pd* pd, struct ibv_cq* cq) 
{
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

/* transition the QP to INIT state */
int transition_to_init_state(struct ibv_qp* qp) 
{
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.pkey_index = 0;                   // default partition key
    qp_attr.port_num = HCA_PORT_NUM;
    qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;

    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition QP to INIT state");
        return -1;
    }
    fprintf(stdout, "[INFO] Queue Pair transitioned to INIT state successfully\n");

    return 0;
}


/* create a completion queue */
struct ibv_cq* create_completion_queue(struct ibv_context* context, int cq_size) 
{
    struct ibv_cq* cq = ibv_create_cq(context, cq_size, NULL, NULL, 0);                                                                                                                       
    if (!cq) perror("[ERROR] Failed to create Completion Queue");
    else fprintf(stdout, "[INFO] Completion Queue created successfully with size %d bytes\n", cq_size);
 
    return cq;
}

/* transition the QP to RTR state */
int transition_to_rtr_state(struct ibv_qp *qp, uint16_t local_lid, uint32_t local_qp_num) 
{
    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));
 
    qp_attr.qp_state = IBV_QPS_RTR;                 // target state: RTR
    qp_attr.path_mtu = IBV_MTU_4096;                // path MTU; adjust based on your setup
    qp_attr.dest_qp_num = local_qp_num;             // destination Queue Pair Number
    qp_attr.rq_psn = 0;                             // remote Queue Pair Packet Sequence Number
    qp_attr.max_dest_rd_atomic = 1;                 // maximum outstanding RDMA reads/atomic ops
    qp_attr.min_rnr_timer = 12;                     // minimum RNR NAK timer
 
    /* Address handle (AH) attributes for IB within the same subnet */
    qp_attr.ah_attr.is_global = 0;                  // not using GRH (Infiniband in the same subnet)
    qp_attr.ah_attr.dlid = local_lid;               // destination LID (Local Identifier)
    qp_attr.ah_attr.sl = 0;                         // service Level (QoS, typically set to 0)
    qp_attr.ah_attr.src_path_bits = 0;              // source path bits (used in LMC; set to 0 if not used)
    qp_attr.ah_attr.port_num = HCA_PORT_NUM;        // use the given port; adjust based on your setup
 
    /* flags specifying which attributes to modify */
    int flags = IBV_QP_STATE | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER | IBV_QP_AV;
 
    /* modify the QP to transition to the RTR state */
    if (ibv_modify_qp(qp, &qp_attr, flags)) {
        perror("[ERROR] Failed to transition QP to the RTR state");
        return -1;
    }
    fprintf(stdout, "[INFO] Queue Pair transitioned to the RTR state successfully\n");
    
    return 0;
}

/* transition the queue pair to RTS(ready to send) state */
int transition_to_rts_state(struct ibv_qp *qp) 
{
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
 
    fprintf(stdout, "[INFO] Transition the QP to RTS state successfully\n");
    return 0;
}

/* post the RDMA write work request */
int perform_rdma_write(struct ibv_qp* qp, struct ibv_mr* mr,
                       uint64_t remote_addr, uint32_t rkey)
{
    struct ibv_sge sge;
    memset(&sge, 0, sizeof(sge));
    sge.addr   = (uintptr_t)mr->addr;     // client buffer address
    sge.length = mr->length;              // client buffer length
    sge.lkey   = mr->lkey;                // client buffer lkey

    struct ibv_send_wr wr;
    memset(&wr, 0, sizeof(wr));
    wr.wr_id      = 0;
    wr.sg_list    = &sge;
    wr.num_sge    = 1;
    wr.opcode     = IBV_WR_RDMA_WRITE;    // RDMA write operation
    wr.send_flags = IBV_SEND_SIGNALED;    // request completion notification
    wr.wr.rdma.remote_addr = remote_addr; // server memory address
    wr.wr.rdma.rkey        = rkey;        // server memory region key

    struct ibv_send_wr* bad_wr = NULL;
    if (ibv_post_send(qp, &wr, &bad_wr)) {
        perror("[ERROR] Failed to post the RDMA write request");
        return -1;
    }

    fprintf(stdout, "[INFO] RDMA write request posted successfully\n");
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

void setup_server_socket ()
{
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        clean_up(-1);
    }

    /* avoid address in use */
    int opt = 1;                                                                                                                                                                                                    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
        clean_up(-1);
    }       
#ifdef SO_REUSEPORT         
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEPORT)");
        clean_up(-1);
    }       
#endif 

    // configure server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;       // listen on all available interfaces
    server_addr.sin_port = htons(PORT);

    // bind the socket to the specified IP and port
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        clean_up(-1);
    }

    // start listening for incoming connections
    if (listen(sockfd, 5) < 0) {
        perror("Listen failed");
        clean_up(-1);
    }
    printf("Server is listening on port %d...\n", PORT);

    // accept an incoming connection
    if ((clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
        perror("Accept failed");
        clean_up(-1);
    }
    printf("A client connected.\n");
}

int main (int argc, char* argv[])
{
    /* device name(RNIC physical port) */
    const char* device_name = "mlx5_1";

    /* enroll the SIGINT signal handler */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Sigaction SIGINT");
        exit(1);
    }

    /* setup server socket */
    setup_server_socket();

    /* open the RDMA device context */
    context = create_context(device_name);
    if (!context) clean_up(-1);

    /* get the lid of the given port */
    lid = get_lid(context);
    if (lid == 0) clean_up(-1);

    /* create a protection domain */
    pd = create_protection_domain(context);
    if (!pd) clean_up(-1);

    /* register a memory region */
    const size_t buffer_size = RDMA_BUFFER_SIZE;        
    buffer = NULL;
    mr = register_memory_region(pd, buffer_size, &buffer);
    if (!mr) clean_up(-1);
    fprintf(stdout, "[INFO] Server buffer address: %p\n", buffer);
    fprintf(stdout, "[INFO] Server mr rkey : 0x%x\n", mr->rkey);

    /* create completion queue */
    int cq_size = 16;                   
    cq = create_completion_queue(context, cq_size);
    if (!cq) clean_up(-1);

    /* create a queue pair */
    struct ibv_qp* qp = create_queue_pair(pd, cq);
    if (!qp) clean_up(-1);

    /* transition QP to the INIT state */
    if (transition_to_init_state(qp)) clean_up(-1);

    /* transition QP to the RTR state */
    uint16_t client_lid;
    uint32_t client_qp_num;

    printf("Enter client LID: ");
    scanf("%" SCNu16, &client_lid);

    printf("Enter client QP number: ");
    scanf("%" SCNu32, &client_qp_num);

    /* transition the QP to RTR state */
    if (transition_to_rtr_state(qp, client_lid, client_qp_num)) clean_up(-1);

    /* transition the QP to RTS state */
    if (transition_to_rts_state(qp)) clean_up(-1);

    /* check memory content */
    while(((unsigned char *)buffer)[RDMA_BUFFER_SIZE - 1] == 0);
    bool correct = true;
    unsigned char cnt = 0;
    for (int i = 0; i < RDMA_BUFFER_SIZE; i++) {
        if (((unsigned char *)buffer)[i] != cnt) {
            correct = false;
            break;
        }
        cnt++;
    }
    if(correct) fprintf(stdout, "Result is correct!\n");
    else fprintf(stdout, "Result is not correct!\n");

    clean_up(0);
    exit(0);
}


