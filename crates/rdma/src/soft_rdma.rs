use crate::verbs;
use std::ffi::CStr;
use std::ptr::NonNull;

pub struct SoftRdmaDevice {
    ctx: NonNull<verbs::ibv_context>,
    pd: NonNull<verbs::ibv_pd>,
    pub cq: NonNull<verbs::ibv_cq>,
}

unsafe impl Send for SoftRdmaDevice {}

impl SoftRdmaDevice {
    pub fn open() -> Result<Self, String> {
        let name = unsafe { verbs::rdma_first_device_name() };
        if name.is_null() {
            return Err("No RDMA device found. Is softRoCE (rxe) loaded?".into());
        }
        let name_cstr = unsafe { CStr::from_ptr(name) };
        let dev_name = name_cstr.to_string_lossy().to_string();

        let ctx = NonNull::new(unsafe { verbs::rdma_open_device(name) })
            .ok_or_else(|| format!("Failed to open device '{}'", dev_name))?;

        let pd = NonNull::new(unsafe { verbs::rdma_create_pd(ctx.as_ptr()) })
            .ok_or("Failed to create PD")?;

        let cq = NonNull::new(unsafe { verbs::rdma_create_cq(ctx.as_ptr(), 128) })
            .ok_or("Failed to create CQ")?;

        Ok(Self { ctx, pd, cq })
    }

    pub fn register_memory(&self, buf: &[u8]) -> Result<RegisteredMemory, String> {
        let access = verbs::IBV_ACCESS_LOCAL_WRITE
            | verbs::IBV_ACCESS_REMOTE_READ
            | verbs::IBV_ACCESS_REMOTE_WRITE;

        let mr = NonNull::new(unsafe {
            verbs::rdma_register_mr(
                self.pd.as_ptr(),
                buf.as_ptr() as *mut std::ffi::c_void,
                buf.len(),
                access,
            )
        })
        .ok_or("Memory registration failed")?;

        let lkey = unsafe { verbs::rdma_mr_lkey(mr.as_ptr()) };
        let rkey = unsafe { verbs::rdma_mr_rkey(mr.as_ptr()) };

        Ok(RegisteredMemory {
            mr,
            len: buf.len(),
            lkey,
            rkey,
        })
    }

    pub fn create_qp_pair(&self) -> Result<(QueuePair, QueuePair), String> {
        let qp0 = QueuePair::create(self.pd, self.cq, 16, 16)?;
        let qp1 = QueuePair::create(self.pd, self.cq, 16, 16)?;

        let lid = unsafe { verbs::rdma_get_lid(self.ctx.as_ptr(), 1) };

        qp0.connect(qp1.qp_num(), lid)?;
        qp1.connect(qp0.qp_num(), lid)?;

        Ok((qp0, qp1))
    }
}

impl Drop for SoftRdmaDevice {
    fn drop(&mut self) {
        unsafe {
            verbs::rdma_destroy_cq(self.cq.as_ptr());
            verbs::rdma_destroy_pd(self.pd.as_ptr());
            verbs::rdma_close_device(self.ctx.as_ptr());
        }
    }
}

pub struct RegisteredMemory {
    mr: NonNull<verbs::ibv_mr>,
    len: usize,
    lkey: u32,
    rkey: u32,
}

impl RegisteredMemory {
    pub fn lkey(&self) -> u32 { self.lkey }
    pub fn rkey(&self) -> u32 { self.rkey }
    pub fn len(&self) -> usize { self.len }
    pub fn remote_addr(&self) -> u64 { self.mr.as_ptr() as u64 }
}

impl Drop for RegisteredMemory {
    fn drop(&mut self) {
        unsafe { verbs::rdma_dereg_mr(self.mr.as_ptr()); }
    }
}

pub struct QueuePair {
    qp: NonNull<verbs::ibv_qp>,
}

impl QueuePair {
    fn create(
        pd: NonNull<verbs::ibv_pd>,
        cq: NonNull<verbs::ibv_cq>,
        max_send: u32,
        max_recv: u32,
    ) -> Result<Self, String> {
        let qp = NonNull::new(unsafe {
            verbs::rdma_create_qp(pd.as_ptr(), cq.as_ptr(), cq.as_ptr(), max_send, max_recv)
        })
        .ok_or("QP creation failed")?;

        let ret = unsafe { verbs::rdma_modify_qp_to_init(qp.as_ptr(), 1) };
        if ret != 0 {
            unsafe { verbs::rdma_destroy_qp(qp.as_ptr()) };
            return Err(format!("QP init failed: {}", ret));
        }

        Ok(Self { qp })
    }

    fn connect(&self, dest_qpn: u32, dlid: u16) -> Result<(), String> {
        let ret = unsafe {
            verbs::rdma_modify_qp_to_rtr(self.qp.as_ptr(), dest_qpn, dlid, 1)
        };
        if ret != 0 {
            return Err(format!("QP RTR failed: {}", ret));
        }
        let ret = unsafe { verbs::rdma_modify_qp_to_rts(self.qp.as_ptr()) };
        if ret != 0 {
            return Err(format!("QP RTS failed: {}", ret));
        }
        Ok(())
    }

    pub fn qp_num(&self) -> u32 {
        unsafe { verbs::rdma_get_qp_num(self.qp.as_ptr()) }
    }

    pub fn rdma_read(
        &self,
        dst: &mut [u8],
        dst_mr: &RegisteredMemory,
        remote_addr: u64,
        remote_rkey: u32,
        len: usize,
    ) -> Result<(), String> {
        let ret = unsafe {
            verbs::rdma_post_rdma_read(
                self.qp.as_ptr(),
                dst.as_mut_ptr() as *mut std::ffi::c_void,
                dst_mr.lkey(),
                len,
                remote_addr,
                remote_rkey,
            )
        };
        if ret != 0 {
            return Err(format!("RDMA read post failed: {}", ret));
        }
        Ok(())
    }

    pub fn poll_completion(&self, cq: NonNull<verbs::ibv_cq>) -> Option<verbs::rdma_wc> {
        let mut wc = verbs::rdma_wc { wr_id: 0, status: 0, byte_len: 0, qp_num: 0 };
        let ret = unsafe { verbs::rdma_poll_cq(cq.as_ptr(), &mut wc) };
        if ret > 0 && wc.status == verbs::IBV_WC_SUCCESS {
            Some(wc)
        } else {
            None
        }
    }
}

impl Drop for QueuePair {
    fn drop(&mut self) {
        unsafe { verbs::rdma_destroy_qp(self.qp.as_ptr()); }
    }
}
