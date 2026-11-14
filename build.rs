use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/lagblame.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("lagblame.skel.rs");
    let mut b = SkeletonBuilder::new();
    b.source(SRC)
        .clang_args(["-Wall", "-Wno-unused-function", "-Isrc/bpf"]);
    // CLANG=/path/to/clang if clang is not on PATH
    if let Some(clang) = env::var_os("CLANG") {
        b.clang(clang);
    }
    b.build_and_generate(&out)
        .expect("building the BPF program (needs clang)");
    println!("cargo:rerun-if-changed=src/bpf");
    println!("cargo:rerun-if-env-changed=CLANG");
}
