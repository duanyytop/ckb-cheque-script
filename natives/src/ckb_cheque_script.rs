extern crate alloc;

#[path = "../../contracts/ckb-cheque-script/src/entry.rs"]
mod entry;
#[path = "../../contracts/ckb-cheque-script/src/error.rs"]
mod error;
#[path = "../../contracts/ckb-cheque-script/src/claim.rs"]
mod claim;
#[path = "../../contracts/ckb-cheque-script/src/withdraw.rs"]
mod withdraw;
#[path = "../../contracts/ckb-cheque-script/src/hash.rs"]
mod hash;
#[path = "../../contracts/ckb-cheque-script/src/helper.rs"]
mod helper;

fn main() {
    if let Err(err) = entry::main() {
        std::process::exit(err as i32);
    }
}