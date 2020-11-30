// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{load_script, load_witness_args, load_cell, QueryIter},
};

use crate::error::Error;

mod claim;
mod withdraw;
mod hash;

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    if args.len() != 40 {
        return Err(Error::InvalidArgument);
    }
    
    let mut receiver = [0u8; 20];
    let mut sender_lock_hash = [0u8; 20];
    receiver.copy_from_slice(&args[0..20]);
    sender_lock_hash.copy_from_slice(&args[20..]);

    let witness_lock_is_none = load_witness_args(0, Source::Input)?.lock().to_opt().is_none();
    let is_claim = !witness_lock_is_none || (witness_lock_is_none && has_same_input(receiver));
    let is_withdraw = witness_lock_is_none && has_same_input(sender_lock_hash);
    return if is_claim {
        claim::validate()
    } else if is_withdraw {
        withdraw::validate()
    } else {
        return Err(Error::ConditionNotMatch)
    }
}

fn has_same_input(parameter: [u8; 20]) -> bool {
    QueryIter::new(load_cell, Source::Input)
                            .any(|cell| hash::blake2b_256(cell.lock().as_slice())[0..20] == parameter)
}
