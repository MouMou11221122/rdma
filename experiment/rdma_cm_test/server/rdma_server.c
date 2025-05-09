/*
 * RDMA Server using librdmacm and libibverbs
 * Receives a one-sided RDMA_WRITE from client
 * Publishes its buffer addr & rkey via private_data
 * Requires environment variable (optional):
 *   RDMA_SERVER_PORT - CM listen port (default 8080)
 * Usage:
 *   export RDMA_SERVER_PORT=8080
 *   ./rdma_cm_server
 */

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stdbool.h>

#define RDMA_BUF_SIZE (1ULL << 30)

// RDMA resources (globals for cleanup)
static struct rdma_event_channel    *ec         = NULL;
static struct rdma_cm_id            *listen_id  = NULL;
static struct rdma_cm_id            *conn_id    = NULL;
static struct ibv_pd                *pd         = NULL;
static struct ibv_cq                *cq         = NULL;
static struct ibv_qp                *qp         = NULL;
static struct ibv_mr                *mr         = NULL;
static char                         *buffer     = NULL;

/* metadata sent to client */
struct metadata { uint64_t addr; uint32_t rkey; };

static void cleanup(int sig) {
    if (conn_id && qp)         rdma_destroy_qp(conn_id);
    if (mr)                    ibv_dereg_mr(mr);
    if (buffer)                free(buffer);
    if (pd)                    ibv_dealloc_pd(pd);
    if (listen_id)             rdma_destroy_id(listen_id);
    if (ec)                    rdma_destroy_event_channel(ec);
    exit(0);
}

int main() {
    // register SIGINT handler via sigaction
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
    // get server port
    char *port_s = getenv("RDMA_SERVER_PORT");
    int port = port_s ? atoi(port_s) : 8080;

    // create CM event channel and listening ID
    ec = rdma_create_event_channel();
    rdma_create_id(ec, &listen_id, NULL, RDMA_PS_TCP);

    // bind to local address and listen
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(port);
    sin.sin_addr.s_addr = INADDR_ANY;
    rdma_bind_addr(listen_id, (struct sockaddr*)&sin);
    rdma_listen(listen_id, 0);
    printf("[INFO] RDMA CM listening on port %d\n", port);

    // wait for connection request
    struct rdma_cm_event *evt;
    while (rdma_get_cm_event(ec, &evt) == 0) {
        if (evt->event == RDMA_CM_EVENT_CONNECT_REQUEST) {
            conn_id = evt->id;
            rdma_ack_cm_event(evt);
            break;
        }
        rdma_ack_cm_event(evt);
    }

    // allocate PD/CQ and create QP for this connection
    pd = ibv_alloc_pd(conn_id->verbs);
    cq = ibv_create_cq(conn_id->verbs, 16, NULL, NULL, 0);
    struct ibv_qp_init_attr qp_attr = {
        .send_cq = cq,
        .recv_cq = cq,
        .qp_type = IBV_QPT_RC,
        .cap     = { .max_send_wr   = 0,
                     .max_recv_wr   = 1,
                     .max_send_sge  = 0,
                     .max_recv_sge  = 1 }
    };
    rdma_create_qp(conn_id, pd, &qp_attr);
    qp = conn_id->qp;

    // register memory region published to client
    buffer = malloc(RDMA_BUF_SIZE);
    memset(buffer, 0, RDMA_BUF_SIZE);
    mr = ibv_reg_mr(pd, buffer, RDMA_BUF_SIZE,
                   IBV_ACCESS_LOCAL_WRITE |
                   IBV_ACCESS_REMOTE_READ |
                   IBV_ACCESS_REMOTE_WRITE);

    printf("[INFO] Buffer at %p, rkey = 0x%x\n", buffer, mr->rkey);

    // accept with private_data = { addr, rkey }
    struct metadata md = { .addr = (uintptr_t)buffer, .rkey = mr->rkey };
    struct rdma_conn_param conn_param   = {0};
    conn_param.private_data             = &md;
    conn_param.private_data_len         = sizeof(md);
    conn_param.responder_resources      = 1;
    conn_param.initiator_depth          = 1;
    rdma_accept(conn_id, &conn_param);

    // wait for ESTABLISHED
    while (rdma_get_cm_event(ec, &evt) == 0) {
        if (evt->event == RDMA_CM_EVENT_ESTABLISHED) {
            rdma_ack_cm_event(evt);
            break;
        }
        rdma_ack_cm_event(evt);
    }
    printf("[INFO] RDMA connection established\n");

    // spin-wait for client RDMA_WRITE
    while (((volatile char*)buffer)[RDMA_BUF_SIZE - 1] == 0);
    printf("[INFO] Detected write completion\n");
    
    // validate data if desired...
    
    bool result = true;
    char cnt = 0;
    for (int i = 0; i < RDMA_BUF_SIZE; i++) {
        if (buffer[i] != cnt) {
            result = false;
            break;
        }
        cnt++;
    }
    if (result) printf("Result is true.\n");
    else printf("Result is false.\n");
    
    cleanup(0);
    return 0;
}

