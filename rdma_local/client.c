#include <infiniband/verbs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <fcntl.h>

#define RDMA_BUFFER_SIZE            ((1UL) << 30)
#define HCA_DEVICE_NAME             "mlx5_0" 
#define HCA_PORT_NUM                1
#define CLIENT_RDMA_READ_SUCCESS    1
#define CLIENT_RDMA_READ_FAILURE    -1

#define PORT 8080

/* test: multi-stream */
#define SHARED_PROCESS_NUM          2
#define SHARED_VARIABLE_FILE_NAME   "/shm1" 
#define SEMAPHORE_FILE_NAME         "/sem1" 
typedef struct {
    bool flag;      
    int counter;   
} shared_data_t;
shared_data_t* shared_data;
int shm_fd;
sem_t *sem;
void test_multi_stream_init() {
    /* open or create the shared memory */
    shm_fd = shm_open(SHARED_VARIABLE_FILE_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open failed");
        exit(1);
    }

    /* set the size of shared memory, initialized to zeros when first created */
    ftruncate(shm_fd, sizeof(shared_data_t));

    /* memory mapping */
    shared_data = (shared_data_t *)mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared_data == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }

    /* close the shared memory fd */
    close(shm_fd);

    /* open or create the semaphore */
    sem = sem_open(SEMAPHORE_FILE_NAME, O_CREAT, 0666, 1);
    if (sem == SEM_FAILED) {
        perror("sem_open failed");
        exit(1);
    }
}

/* RDMA infos */
struct ibv_context* context;
uint16_t lid;
struct ibv_pd* pd;
struct ibv_cq* cq;
struct ibv_qp* qp;
void* buffer;
struct ibv_mr* mr;

/* socket */
int sock;                        //local socket descriptor
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
        fprintf(stdout, "Memory region deregistered successfully.\n");
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

    if (error_num == -1) exit(1);
    else exit(0);
}

/* signal handler */
void signal_handler (int signum) {
    if (signum == SIGINT) {
        fprintf(stdout, "SIGINT received.");
        clean_up(signum);
    }
    /* reserverd for other signals */
}

/* client conncet to server */
void connect_to_socket() {
    // create client socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) clean_up(-1);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // set the server's IP address 
    if (inet_pton(AF_INET, "10.10.10.2", &serv_addr.sin_addr) <= 0) {  
        perror("[ERROR] Invalid server IP address");
        clean_up(-1);
    }

    // attempt to connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("[ERROR] Connection failed");
        clean_up(-1);
    }

    fprintf(stdout, "[INFO] Client has connected to the server.\n");
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
            if (!context) {
                fprintf(stderr, "[ERROR] Failed to open RDMA device: %s.\n", device_name);
                ibv_free_device_list(device_list);      // free the device list to prevent memory leaks 
                return NULL;
            }
        }
    }

    ibv_free_device_list(device_list);      // free the device list to prevent memory leaks 

    if (!context) fprintf(stderr, "[ERROR] Failed to find the device: %s.\n", device_name);
    else fprintf(stdout, "[INFO] RDMA device context created successfully.\n");

    return context;
}

/* query port attributes and get the LID */
uint16_t get_lid(struct ibv_context* context) {
    struct ibv_port_attr port_attr;
    if (ibv_query_port(context, HCA_PORT_NUM, &port_attr)) {
        perror("[ERROR] Failed to query the port attributes");
        return 0;
    }
    fprintf(stdout, "[INFO] LID of the port being used(port %u) : %u\n", HCA_PORT_NUM, port_attr.lid);
    return port_attr.lid;
}

/* create a protection domain */
struct ibv_pd* create_protection_domain(struct ibv_context* context) {
    struct ibv_pd* pd = ibv_alloc_pd(context);
    if (!pd) perror("[ERROR] Failed to allocate protection domain");
    else fprintf(stdout, "[INFO] Protection domain created successfully.\n");
    return pd;
}

/* create a completion queue */
struct ibv_cq* create_completion_queue(struct ibv_context* context, int cq_size) {
    struct ibv_cq* cq = ibv_create_cq(context, cq_size, NULL, NULL, 0);
    if (!cq) perror("[ERROR] Failed to create completion queue");
    else fprintf(stdout, "[INFO] Completion queue created successfully with size %d bytes.\n", cq_size);
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
    if (!qp) perror("[ERROR] Failed to create queue pair");
    else fprintf(stdout, "[INFO] Queue pair created successfully with QP Number: %u\n", qp->qp_num);
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

    fprintf(stdout, "[INFO] Transition the QP to INIT state successfully.\n");
    return 0;
}

/* transition the queue pair to RTR(ready to receive) state */
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

    fprintf(stdout, "[INFO] Transition the QP to RTR state successfully.\n");
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

    fprintf(stdout, "[INFO] Memory region registered successfully.\n");
    return mr;
}

/* transition the queue pair to RTS(ready to send) state */
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

    fprintf(stdout, "[INFO] Transition the QP to RTS state successfully.\n");
    return 0;
}

/* post the RDMA read work request */
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
        perror("[ERROR] Failed to post the RDMA read request");
        return -1;
    }

    fprintf(stdout, "[INFO] RDMA read request posted successfully.\n");
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
        fprintf(stderr, "[ERROR] Work completion error : %s.\n", ibv_wc_status_str(wc.status));
        return -1;
    }

    fprintf(stdout, "[INFO] Completion polled successfully.\n");
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

    /* init the shared memory and semaphore */
    test_multi_stream_init();

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
    if (!context) clean_up(-1);

    /* get the LID of the port */
    lid = get_lid(context);
    if (lid == 0) clean_up(-1);
    send(sock, &lid, sizeof(lid), 0);   // send the client LID to the server

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
    send(sock, &(qp->qp_num), sizeof(qp->qp_num), 0);   // send the client QP number to the server

    /* register a memory region */
    size_t buffer_size = RDMA_BUFFER_SIZE; 	
    mr = register_memory_region(pd, buffer_size, &buffer);
    if (!mr) clean_up(-1);

    /* transition the QP to INIT state */
    if (transition_to_init_state(qp)) clean_up(-1);

    /* transition the QP to RTR state */
    uint16_t server_lid;
    uint32_t server_qp_num;

    // receive the server LID 
    if (recv(sock, &server_lid, sizeof(server_lid), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read the server LID.\n");
        clean_up(-1);
    }
    fprintf(stdout, "[INFO] Server LID received by the client : %u\n", server_lid);

    // receive the server QP number
    if (recv(sock, &server_qp_num, sizeof(server_qp_num), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to read server QP number.\n");
        clean_up(-1);
    }
    fprintf(stdout, "[INFO] Server QP number received by the client : %u\n", server_qp_num);

    if (transition_to_rtr_state(qp, server_lid, server_qp_num)) clean_up(-1);

	/* transition the QP to RTS state */
    if (transition_to_rts_state(qp)) clean_up(-1);

	/* perform the RDMA read */
    uint64_t server_addr;
    uint32_t server_rkey;

    // receive the server's virtual memory address
    if (recv(sock, &server_addr, sizeof(server_addr), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to receive the server virtual memory address.\n");
        clean_up(-1);
    }
    fprintf(stdout, "[INFO] Server virtual memory address received by the client : %p\n", (void *)server_addr);

    // receive the server's rkey
    if (recv(sock, &server_rkey, sizeof(server_rkey), 0) <= 0) {
        fprintf(stderr, "[ERROR] Failed to receive the server rkey.\n");
        clean_up(-1);
    }
    fprintf(stdout, "[INFO] Server rkey received by the client : 0x%x\n", server_rkey);

    /* test: barrier synchronization */
    sem_wait(sem);  
    shared_data->counter++;
    if (shared_data->counter == SHARED_PROCESS_NUM) shared_data->flag = true;  
    sem_post(sem); 
    while(!shared_data->flag);
     
    gettimeofday(&start, NULL);
    /* post RDMA read */
    if (perform_rdma_read(qp, mr, server_addr, server_rkey)) clean_up(-1);

	/* polls the completion queue and send ack/nack to the server */
    int reply_to_server;
    if (poll_completion_queue(cq)) {
        reply_to_server = CLIENT_RDMA_READ_FAILURE;
        send(sock, &reply_to_server, sizeof(reply_to_server), 0);
        clean_up(-1);
    }
    gettimeofday(&end, NULL);
    reply_to_server = CLIENT_RDMA_READ_SUCCESS;
    send(sock, &reply_to_server, sizeof(reply_to_server), 0);

    fprintf(stdout, "[INFO] RDMA read operation completed.\n");

    /* test: close the shared memory & semaphore */
    sem_wait(sem);
    shared_data->counter--;   
    if (shared_data->counter == 0) {
        munmap(shared_data, sizeof(shared_data_t));
        shm_unlink(SHARED_VARIABLE_FILE_NAME);
        sem_close(sem);   
        sem_unlink(SEMAPHORE_FILE_NAME);  
    } else {   
        munmap(shared_data, sizeof(shared_data_t));
        sem_post(sem);
        sem_close(sem);   
    }

    /* check the result */
    bool correct_result = true;
    unsigned char cnt = 0;
    for (long long i = 0; i < RDMA_BUFFER_SIZE; i++) {
        if (memcmp(&cnt, ((unsigned char *)buffer), 1)) {
            correct_result = false;
            break;
        }
    }     
    if (correct_result) fprintf(stdout, "Result read from the server is correct.\n");
    else fprintf(stdout, "Result read from the server is not correct.\n");

    /* get the real time of a single read operation */
    elapsed_time = timeval_diff_micro(&start, &end);
    fprintf(stdout, "[INFO] Elapsed time of a single RDMA read(%ld bytes) : %ld us\n", RDMA_BUFFER_SIZE, elapsed_time);

    /* calculate the read bandwidth of read operation */
    double read_bandwidth;
    read_bandwidth = calculate_bandwidth(elapsed_time);
    fprintf(stdout, "[INFO] Read bandwidth : %.6f Gbps\n", read_bandwidth); 

    exit(0);
}
