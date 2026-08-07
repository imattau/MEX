fn main() {
    println!("cargo::rustc-check-cfg=cfg(soft_rdma_available)");
    println!("cargo:rerun-if-changed=rdma_helper.c");
    println!("cargo:rerun-if-changed=include/");

    let has_lib = std::process::Command::new("ldconfig")
        .arg("-p")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("libibverbs"))
        .unwrap_or(false);

    if has_lib {
        cc::Build::new()
            .file("rdma_helper.c")
            .include("include")
            .compile("rdma_helper");
        println!("cargo:rustc-link-arg=-l:libibverbs.so.1");
        println!("cargo:rustc-cfg=soft_rdma_available");
    } else {
        println!("cargo:warning=libibverbs.so.1 not found — softRDMA disabled, using mock");
    }
}
