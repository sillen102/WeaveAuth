const PROTO: &str = "../proto/weaveauth/plugin/plugin.proto";

fn main() {
    println!("cargo:rerun-if-changed={PROTO}");

    // prost-build shells out to protoc. Point it at the vendored binary so a
    // build needs nothing installed -- the alternative is every developer,
    // CI job and Docker stage growing a protoc dependency.
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path().expect("vendored protoc for this platform"));

    tonic_prost_build::configure()
        .compile_with_config(config, &[PROTO], &["../proto"])
        .expect("the plugin contract compiles");
}
