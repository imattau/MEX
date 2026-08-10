fn main() {
    // The dev machine has no system `protoc`; point prost-build at the
    // vendored binary instead of requiring one to be installed.
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary");
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["proto/frg.proto"], &["proto"])
        .expect("failed to compile vendored frg.proto");
}
