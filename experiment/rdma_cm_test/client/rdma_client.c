/*
 * RDMA Client using librdmacm and libibverbs
 * Sends a one-sided RDMA_WRITE to server via RDMA CM
 * Requires environment variables:
 *   RDMA_SERVER_IP   - server's IP (e.g., 10.10.10.2)
 *   RDMA_SERVER_PORT - server's CM listen port (e.g., 7471)
 *   RDMA_CLIENT_IP   - client local IP on chosen RNIC (e.g., 10.10.10.1)
 * Usage:
 *   export RDMA_SERVER_IP=10.10.10.2
 *   export RDMA_SERVER_PORT=7471
 *   export RDMA_CLIENT_IP=10.10.10.1
 *   ./rdma_cm_client
 */

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <arpa/inet.h>

#define RDMA_BUF_SIZE   (1ULL << 30)

/* RDMA resources (globals for cleanup) */
static struct rdma_event_channel *ec = NULL;
static struct rdma_cm_id       *cm_id = NULL;
static struct ibv_pd            *pd    = NULL;
static struct ibv_cq            *cq    = NULL;
static struct ibv_qp            *qp    = NULL;
static struct ibv_mr            *mr    = NULL;
static char                     *buf   = NULL;

/* metadata struct exchanged by server */
struct metadata { uint64_t addr; uint32_t rkey; };

/* cleanup both on normal exit and SIGINT */
static void cleanup(int sig) {
    if (qp)   rdma_destroy_qp(cm_id);
    if (mr)   ibv_dereg_mr(mr);
    if (buf)  free(buf);
    if (pd)   ibv_dealloc_pd(pd);
    if (cm_id)rdma_destroy_id(cm_id);
    if (ec)   rdma_destroy_event_channel(ec);
    exit(0);
}

int main() {
    /* register SIGINT handler via sigaction */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    /* read environment variables */
    char *srv_ip     = getenv("RDMA_SERVER_IP");
    char *srv_port_s = getenv("RDMA_SERVER_PORT");
    char *cli_ip     = getenv("RDMA_CLIENT_IP");
    if (!srv_ip || !srv_port_s || !cli_ip) {
        fprintf(stderr, "Set RDMA_SERVER_IP, RDMA_SERVER_PORT, RDMA_CLIENT_IP\n");
        return 1;
    }
    int srv_port = atoi(srv_port_s);

    /* create CM channel and ID */
    ec = rdma_create_event_channel();
    rdma_create_id(ec, &cm_id, NULL, RDMA_PS_TCP);

    /* bind to local client IP for selecting correct RNIC */
    struct sockaddr_in cli_addr = {0};
    cli_addr.sin_family = AF_INET;
    inet_pton(AF_INET, cli_ip, &cli_addr.sin_addr);
    rdma_bind_addr(cm_id, (struct sockaddr*)&cli_addr);

    /* resolve server address and route */
    struct sockaddr_in srv_addr = {0};
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port   = htons(srv_port);
    inet_pton(AF_INET, srv_ip, &srv_addr.sin_addr);
    rdma_resolve_addr(cm_id, NULL, (struct sockaddr*)&srv_addr, 2000);
    rdma_resolve_route(cm_id, 2000);

    /* allocate PD/CQ and create QP via CM */
    pd = ibv_alloc_pd(cm_id->verbs);
    cq = ibv_create_cq(cm_id->verbs, 16, NULL, NULL, 0);
    struct ibv_qp_init_attr qp_attr = {
        .send_cq = cq,
        .recv_cq = cq,
        .qp_type = IBV_QPT_RC,
        .cap     = { .max_send_wr = 1, .max_recv_wr = 1,
                     .max_send_sge=1, .max_recv_sge=1 }
    };
    rdma_create_qp(cm_id, pd, &qp_attr);
    qp = cm_id->qp;

    /* connect to server */
    rdma_connect(cm_id, NULL);

    /* event loop: wait for ESTABLISHED to get remote metadata */
    struct rdma_cm_event *evt;
    uint64_t remote_addr;
    uint32_t remote_rkey;
    while (rdma_get_cm_event(ec, &evt) == 0) {
        if (evt->event == RDMA_CM_EVENT_ESTABLISHED) {
            const struct metadata *md = (const struct metadata *)evt->param.conn.private_data;
            remote_addr = md->addr;
            remote_rkey = md->rkey;
            rdma_ack_cm_event(evt);
            break;
        }
        rdma_ack_cm_event(evt);
    }

    /* register local buffer */
    buf = malloc(RDMA_BUF_SIZE);
    mr  = ibv_reg_mr(pd, buf, RDMA_BUF_SIZE,
            IBV_ACCESS_LOCAL_WRITE |
            IBV_ACCESS_REMOTE_READ |
            IBV_ACCESS_REMOTE_WRITE);

    /* post one-sided RDMA_WRITE */
    struct ibv_sge      sge = { .addr=(uintptr_t)buf, .length=RDMA_BUF_SIZE, .lkey=mr->lkey };
    struct ibv_send_wr  wr  = {0}, *bad_wr;
    wr.opcode              = IBV_WR_RDMA_WRITE;
    wr.sg_list             = &sge;
    wr.num_sge             = 1;
    wr.send_flags          = IBV_SEND_SIGNALED;
    wr.wr.rdma.remote_addr = remote_addr;
    wr.wr.rdma.rkey        = remote_rkey;
    ibv_post_send(qp, &wr, &bad_wr);

    /* poll for completion */
    struct ibv_wc wc;
    while (ibv_poll_cq(cq, 1, &wc) == 0);
    if (wc.status != IBV_WC_SUCCESS)
        fprintf(stderr, "RDMA_WRITE failed: %s\n", ibv_wc_status_str(wc.status));
    else
        printf("RDMA_WRITE completed successfully\n");

    /* cleanup */
    cleanup(0);
    return 0;
}

