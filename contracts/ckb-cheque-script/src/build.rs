fn main() {
    println!("cargo:rustc-link-search=native=../../../ckb-lib-secp256k1/build/");
    println!("cargo:rustc-link-lib=static=ckb-lib-secp256k1");
}
