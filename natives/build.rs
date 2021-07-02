use std::path::Path;
use std::env;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}", Path::new(&dir).join("../contracts/ckb-cheque-script/ckb-lib-secp256k1/build-x86").display());
    println!("cargo:rustc-link-lib=static=ckb-lib-secp256k1");
}
