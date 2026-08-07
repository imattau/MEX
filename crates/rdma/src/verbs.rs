#![allow(non_camel_case_types, dead_code)]

use std::ffi::c_void;

pub enum ibv_context {}
pub enum ibv_pd {}
pub enum ibv_mr {}
pub enum ibv_cq {}
pub enum ibv_qp {}

#[repr(C)]
pub struct rdma_wc {
    pub wr_id: u64,
    pub status: i32,
    pub byte_len: u32,
    pub qp_num: u32,
}

extern "C" {
    pub fn rdma_open_device(name: *const libc::c_char) -> *mut ibv_context;
    pub fn rdma_first_device_name() -> *const libc::c_char;
    pub fn rdma_create_pd(ctx: *mut ibv_context) -> *mut ibv_pd;
    pub fn rdma_register_mr(
        pd: *mut ibv_pd,
        buf: *mut c_void,
        len: libc::size_t,
        access: libc::c_int,
    ) -> *mut ibv_mr;
    pub fn rdma_mr_lkey(mr: *mut ibv_mr) -> u32;
    pub fn rdma_mr_rkey(mr: *mut ibv_mr) -> u32;
    pub fn rdma_dereg_mr(mr: *mut ibv_mr) -> libc::c_int;
    pub fn rdma_create_cq(ctx: *mut ibv_context, cqe: libc::c_int) -> *mut ibv_cq;
    pub fn rdma_create_qp(
        pd: *mut ibv_pd,
        scq: *mut ibv_cq,
        rcq: *mut ibv_cq,
        max_send_wr: u32,
        max_recv_wr: u32,
    ) -> *mut ibv_qp;
    pub fn rdma_modify_qp_to_init(qp: *mut ibv_qp, port_num: u8) -> libc::c_int;
    pub fn rdma_modify_qp_to_rtr(
        qp: *mut ibv_qp,
        dest_qp_num: u32,
        dlid: u16,
        port_num: u8,
    ) -> libc::c_int;
    pub fn rdma_modify_qp_to_rts(qp: *mut ibv_qp) -> libc::c_int;
    pub fn rdma_post_rdma_read(
        qp: *mut ibv_qp,
        local_addr: *mut c_void,
        lkey: u32,
        len: libc::size_t,
        remote_addr: u64,
        rkey: u32,
    ) -> libc::c_int;
    pub fn rdma_poll_cq(cq: *mut ibv_cq, out: *mut rdma_wc) -> libc::c_int;
    pub fn rdma_get_qp_num(qp: *mut ibv_qp) -> u32;
    pub fn rdma_get_lid(ctx: *mut ibv_context, port: u8) -> u16;
    pub fn rdma_destroy_qp(qp: *mut ibv_qp);
    pub fn rdma_destroy_cq(cq: *mut ibv_cq);
    pub fn rdma_destroy_pd(pd: *mut ibv_pd);
    pub fn rdma_close_device(ctx: *mut ibv_context);
}

pub const IBV_ACCESS_LOCAL_WRITE: i32 = 1;
pub const IBV_ACCESS_REMOTE_WRITE: i32 = 2;
pub const IBV_ACCESS_REMOTE_READ: i32 = 4;
pub const IBV_WC_SUCCESS: i32 = 0;
