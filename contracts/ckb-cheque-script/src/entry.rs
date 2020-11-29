// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::load_script,
};

use crate::error::Error;

mod claim;
mod withdraw;

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    if args.len() != 40 {
        return Err(Error::InvalidArgument);
    }

    if is_claim() {
        claim::validate()
    } else if is_withdraw() {
        withdraw::validate()
    } else {
        return Err(Error::ConditionNotMatch)
    }
}

fn is_claim() -> bool {
  return false;
}

fn is_withdraw() -> bool {
  return false;
}