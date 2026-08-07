#include "infiniband/verbs.h"
#include <stdlib.h>
#include <string.h>

struct ibv_context* rdma_open_device(const char* name) {
    struct ibv_device** dev_list = ibv_get_device_list(NULL);
    if (!dev_list) return NULL;
    struct ibv_context* ctx = NULL;
    for (int i = 0; dev_list[i]; i++) {
        if (strcmp(ibv_get_device_name(dev_list[i]), name) == 0) {
            ctx = ibv_open_device(dev_list[i]);
            break;
        }
    }
    ibv_free_device_list(dev_list);
    return ctx;
}

const char* rdma_first_device_name(void) {
    struct ibv_device** dev_list = ibv_get_device_list(NULL);
    if (!dev_list || !dev_list[0]) return NULL;
    const char* name = strdup(ibv_get_device_name(dev_list[0]));
    ibv_free_device_list(dev_list);
    return name;
}

struct ibv_pd* rdma_create_pd(struct ibv_context* ctx) { return ibv_alloc_pd(ctx); }
struct ibv_mr* rdma_register_mr(struct ibv_pd* pd, void* buf, size_t len, int access) {
    return ibv_reg_mr(pd, buf, len, access);
}
uint32_t rdma_mr_lkey(struct ibv_mr* mr) { return mr->lkey; }
uint32_t rdma_mr_rkey(struct ibv_mr* mr) { return mr->rkey; }
int rdma_dereg_mr(struct ibv_mr* mr) { return ibv_dereg_mr(mr); }
struct ibv_cq* rdma_create_cq(struct ibv_context* ctx, int cqe) {
    return ibv_create_cq(ctx, cqe, NULL, NULL, 0);
}

struct ibv_qp* rdma_create_qp(struct ibv_pd* pd, struct ibv_cq* scq, struct ibv_cq* rcq,
                               uint32_t max_send_wr, uint32_t max_recv_wr) {
    struct ibv_qp_init_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.send_cq = scq;
    attr.recv_cq = rcq;
    attr.cap.max_send_wr = max_send_wr;
    attr.cap.max_recv_wr = max_recv_wr;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    attr.qp_type = IBV_QPT_RC;
    attr.sq_sig_all = 1;
    return ibv_create_qp(pd, &attr);
}

int rdma_modify_qp_to_init(struct ibv_qp* qp, uint8_t port_num) {
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = port_num;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    return ibv_modify_qp(qp, &attr,
        IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
}

int rdma_modify_qp_to_rtr(struct ibv_qp* qp, uint32_t dest_qp_num,
                                   uint16_t dlid, uint8_t port_num) {
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_4096;
    attr.dest_qp_num = dest_qp_num;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = port_num;
    return ibv_modify_qp(qp, &attr,
        IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
        IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
        IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
}

int rdma_modify_qp_to_rts(struct ibv_qp* qp) {
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    return ibv_modify_qp(qp, &attr,
        IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
        IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);
}

int rdma_post_rdma_read(struct ibv_qp* qp, void* local_addr, uint32_t lkey,
                        size_t len, uint64_t remote_addr, uint32_t rkey) {
    struct ibv_sge sge;
    sge.addr = (uintptr_t)local_addr;
    sge.length = (uint32_t)len;
    sge.lkey = lkey;
    struct ibv_send_wr wr;
    memset(&wr, 0, sizeof(wr));
    wr.wr_id = 1;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_RDMA_READ;
    wr.send_flags = IBV_SEND_SIGNALED;
    wr.wr.rdma.remote_addr = remote_addr;
    wr.wr.rdma.rkey = rkey;
    struct ibv_send_wr* bad = NULL;
    return ibv_post_send(qp, &wr, &bad);
}

typedef struct { uint64_t wr_id; int status; uint32_t byte_len, qp_num; } rdma_wc_t;

int rdma_poll_cq(struct ibv_cq* cq, rdma_wc_t* out) {
    struct ibv_wc wc;
    int ret = ibv_poll_cq(cq, 1, &wc);
    if (ret > 0) { out->wr_id = wc.wr_id; out->status = wc.status; out->byte_len = wc.byte_len; out->qp_num = wc.qp_num; }
    return ret;
}

uint32_t rdma_get_qp_num(struct ibv_qp* qp) { return qp->qp_num; }
uint16_t rdma_get_lid(struct ibv_context* ctx, uint8_t port) {
    struct ibv_port_attr attr;
    if (ibv_query_port(ctx, port, &attr) == 0) return attr.lid;
    return 0;
}

void rdma_destroy_qp(struct ibv_qp* qp) { if (qp) ibv_destroy_qp(qp); }
void rdma_destroy_cq(struct ibv_cq* cq) { if (cq) ibv_destroy_cq(cq); }
void rdma_destroy_pd(struct ibv_pd* pd) { if (pd) ibv_dealloc_pd(pd); }
void rdma_close_device(struct ibv_context* ctx) { if (ctx) ibv_close_device(ctx); }
