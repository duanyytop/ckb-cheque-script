use core::result::Result;

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{load_script, load_witness_args},
};
use crate::error::Error;

mod claim;
mod withdraw;
mod hash;
mod helper;

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    if args.len() != 40 {
        return Err(Error::InvalidArgument);
    }
    
    let mut receiver_lock_hash = [0u8; 20];
    let mut sender_lock_hash = [0u8; 20];
    receiver_lock_hash.copy_from_slice(&args[0..20]);
    sender_lock_hash.copy_from_slice(&args[20..]);

    let cheque_witness_is_none = cheque_cell_witness_is_none()?;
    if !cheque_witness_is_none {
        // Validate the signatures of receiver and sender
        match helper::validate_blake2b_sighash_all(&receiver_lock_hash) {
            Ok(_) => claim::validate(&sender_lock_hash, &receiver_lock_hash, true),
            Err(_) => {
                match helper::validate_blake2b_sighash_all(&sender_lock_hash) {
                    Ok(_) => withdraw::validate(&sender_lock_hash, true),
                    Err(_) => Err(Error::WrongPubKey)
                }
            }
        }
    } else {
        // Check if the inputs contain the same input as receiver lock hash or sender lock hash
        if helper::has_input_by_lock_hash(&receiver_lock_hash) {
            claim::validate(&sender_lock_hash, &receiver_lock_hash, false)
        } else if helper::has_input_by_lock_hash(&sender_lock_hash) {
            withdraw::validate(&sender_lock_hash, false)
        } else {
            Err(Error::NoMatchedInputs)
        }
    }
}

fn cheque_cell_witness_is_none() -> Result<bool, Error> {
    match load_witness_args(0, Source::GroupInput) {
        Ok(witness_args) => Ok(witness_args.lock().to_opt().is_none()),
        Err(_) => Ok(true)
    }
}

