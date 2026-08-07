#ifndef _RDMA_VERBS_H_
#define _RDMA_VERBS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Opaque types --- */
struct ibv_device;
struct ibv_context;
struct ibv_cq;
struct ibv_comp_channel;
struct ibv_srq;

/* --- Enums --- */
enum ibv_access_flags {
    IBV_ACCESS_LOCAL_WRITE  = 1,
    IBV_ACCESS_REMOTE_WRITE = (1 << 1),
    IBV_ACCESS_REMOTE_READ  = (1 << 2),
    IBV_ACCESS_REMOTE_ATOMIC = (1 << 3),
};

enum ibv_qp_type  { IBV_QPT_RC = 2 };
enum ibv_qp_state { IBV_QPS_RESET, IBV_QPS_INIT, IBV_QPS_RTR, IBV_QPS_RTS, IBV_QPS_SQD, IBV_QPS_SQE, IBV_QPS_ERR };
enum ibv_mtu      { IBV_MTU_256 = 1, IBV_MTU_512 = 2, IBV_MTU_1024 = 3, IBV_MTU_2048 = 4, IBV_MTU_4096 = 5 };

enum ibv_wr_opcode   { IBV_WR_RDMA_WRITE, IBV_WR_RDMA_WRITE_WITH_IMM, IBV_WR_SEND, IBV_WR_SEND_WITH_IMM, IBV_WR_RDMA_READ, IBV_WR_ATOMIC_CMP_AND_SWP, IBV_WR_ATOMIC_FETCH_AND_ADD };
enum ibv_send_flags  { IBV_SEND_FENCE = 1, IBV_SEND_SIGNALED = 2, IBV_SEND_SOLICITED = 4, IBV_SEND_INLINE = 8 };
enum ibv_wc_status   { IBV_WC_SUCCESS };

enum ibv_qp_attr_mask {
    IBV_QP_STATE             = 1,     IBV_QP_CUR_STATE          = 2,
    IBV_QP_EN_SQD_ASYNC_NOTIFY = 4,   IBV_QP_ACCESS_FLAGS       = 8,
    IBV_QP_PKEY_INDEX        = 16,    IBV_QP_PORT               = 32,
    IBV_QP_QKEY              = 64,    IBV_QP_AV                 = 128,
    IBV_QP_PATH_MTU          = 256,   IBV_QP_TIMEOUT            = 512,
    IBV_QP_RETRY_CNT         = 1024,  IBV_QP_RNR_RETRY          = 2048,
    IBV_QP_RQ_PSN            = 4096,  IBV_QP_MAX_QP_RD_ATOMIC   = 8192,
    IBV_QP_DEST_QPN          = 16384, IBV_QP_SQ_PSN             = 65536,
    IBV_QP_MAX_DEST_RD_ATOMIC = 131072, IBV_QP_MIN_RNR_TIMER    = 262144,
};

/* --- Structs --- */
struct ibv_pd { struct ibv_context *context; uint32_t handle; };

struct ibv_mr {
    struct ibv_context *context; struct ibv_pd *pd;
    void *addr; size_t length; uint32_t handle; uint32_t lkey; uint32_t rkey;
};

struct ibv_qp_cap     { uint32_t max_send_wr, max_recv_wr, max_send_sge, max_recv_sge, max_inline_data; };
struct ibv_ah_attr    { uint8_t is_global, dlid_path_bits, sl, src_path_bits; uint16_t dlid; uint8_t port_num; };

struct ibv_qp_attr {
    enum ibv_qp_state qp_state, cur_qp_state; enum ibv_mtu path_mtu;
    enum { IBV_MIG_REARM = 1 } path_mig_state;
    uint32_t qkey, rq_psn, sq_psn, dest_qp_num; int qp_access_flags;
    struct ibv_qp_cap cap; struct ibv_ah_attr ah_attr, alt_ah_attr;
    uint16_t pkey_index, alt_pkey_index; uint8_t en_sqd_async_notify, sq_draining;
    uint8_t max_rd_atomic, max_dest_rd_atomic, min_rnr_timer, port_num;
    uint8_t timeout, retry_cnt, rnr_retry, alt_port_num, alt_timeout;
};

struct ibv_qp_init_attr {
    void *qp_context; struct ibv_cq *send_cq, *recv_cq;
    struct ibv_srq *srq; struct ibv_qp_cap cap;
    enum ibv_qp_type qp_type; int sq_sig_all;
};

struct ibv_qp {
    struct ibv_context *context; void *qp_context; struct ibv_pd *pd;
    struct ibv_cq *send_cq, *recv_cq; struct ibv_srq *srq;
    uint32_t handle, qp_num; enum ibv_qp_state state; enum ibv_qp_type qp_type;
};

struct ibv_port_attr {
    int state, max_mtu, active_mtu, gid_tbl_len; uint32_t port_cap_flags;
    uint32_t max_msg_sz, bad_pkey_cntr, qkey_viol_cntr; uint16_t pkey_tbl_len;
    uint16_t lid; uint16_t sm_lid; uint8_t lmc, max_vl_num, sm_sl, subnet_timeout;
    uint8_t init_type_reply, active_width, active_speed, phys_state, link_layer, flags;
};

struct ibv_sge     { uint64_t addr; uint32_t length; uint32_t lkey; };
struct ibv_send_wr  { uint64_t wr_id; struct ibv_send_wr *next; struct ibv_sge *sg_list;
    int num_sge; enum ibv_wr_opcode opcode; int send_flags;
    union { struct { uint64_t remote_addr; uint32_t rkey; } rdma; } wr; };
struct ibv_recv_wr  { uint64_t wr_id; struct ibv_recv_wr *next; struct ibv_sge *sg_list; int num_sge; };
struct ibv_wc       { uint64_t wr_id; enum ibv_wc_status status; int opcode;
    uint32_t vendor_err, byte_len; uint32_t imm_data, qp_num, src_qp;
    int wc_flags; uint16_t pkey_index, slid; uint8_t sl, dlid_path_bits; };

/* --- Kernel IOCTL dispatch (libibverbs.so.1 exports these) --- */
extern int ibv_cmd_create_qp(struct ibv_pd *pd, struct ibv_qp *qp,
                              struct ibv_qp_init_attr *attr,
                              struct ibv_cmd_create_qp *cmd,
                              size_t cmd_size, ...);
extern int ibv_cmd_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
                               int attr_mask, ...);
extern int ibv_cmd_destroy_qp(struct ibv_qp *qp);
extern int ibv_cmd_close_device(struct ibv_context *context);

/* --- Libibverbs public inline functions (reimplemented here) --- */

static inline int ibv_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr,
                                 struct ibv_send_wr **bad_wr) {
    (void)bad_wr;
    /* Direct ioctl dispatch -- calls into kernel */
    extern int ibv_cmd_post_send(struct ibv_qp*, struct ibv_send_wr*, struct ibv_send_wr**, size_t, ...);
    return ibv_cmd_post_send(qp, wr, bad_wr, sizeof(*wr));
}

static inline int ibv_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr,
                                 struct ibv_recv_wr **bad_wr) {
    (void)bad_wr;
    extern int ibv_cmd_post_recv(struct ibv_qp*, struct ibv_recv_wr*, struct ibv_recv_wr**, size_t);
    return ibv_cmd_post_recv(qp, wr, bad_wr, sizeof(*wr));
}

static inline struct ibv_qp *ibv_create_qp(struct ibv_pd *pd,
                                             struct ibv_qp_init_attr *init_attr) {
    struct ibv_qp *qp = calloc(1, sizeof(*qp));
    if (!qp) return NULL;
    if (ibv_cmd_create_qp(pd, qp, init_attr, NULL, 0)) {
        free(qp);
        return NULL;
    }
    return qp;
}

static inline int ibv_query_port(struct ibv_context *ctx, uint8_t port_num,
                                   struct ibv_port_attr *attr) {
    extern int ibv_cmd_query_port(struct ibv_context*, uint8_t, struct ibv_port_attr*, size_t);
    return ibv_cmd_query_port(ctx, port_num, attr, sizeof(*attr));
}

static inline int ibv_poll_cq(struct ibv_cq *cq, int num, struct ibv_wc *wc) {
    extern int ibv_cmd_poll_cq(struct ibv_cq*, int, struct ibv_wc*, size_t);
    return ibv_cmd_poll_cq(cq, num, wc, sizeof(*wc));
}

/* --- Libibverbs public symbols (exported directly) --- */
struct ibv_device  **ibv_get_device_list(int *num);
void                  ibv_free_device_list(struct ibv_device **list);
const char           *ibv_get_device_name(struct ibv_device *dev);
struct ibv_context   *ibv_open_device(struct ibv_device *dev);
int                   ibv_close_device(struct ibv_context *ctx);
struct ibv_pd        *ibv_alloc_pd(struct ibv_context *ctx);
int                   ibv_dealloc_pd(struct ibv_pd *pd);
struct ibv_mr        *ibv_reg_mr(struct ibv_pd *pd, void *addr, size_t len, int access);
int                   ibv_dereg_mr(struct ibv_mr *mr);
struct ibv_cq        *ibv_create_cq(struct ibv_context *ctx, int cqe, void *cq_ctx,
                                      struct ibv_comp_channel *ch, int vec);
int                   ibv_destroy_cq(struct ibv_cq *cq);
int                   ibv_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int mask);
int                   ibv_destroy_qp(struct ibv_qp *qp);

#ifdef __cplusplus
}
#endif
#endif
