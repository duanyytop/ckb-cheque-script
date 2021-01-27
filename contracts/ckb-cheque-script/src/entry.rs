use core::result::Result;

use ckb_lib_secp256k1::LibSecp256k1;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    dynamic_loading::CKBDLContext,
    high_level::{load_script, load_witness_args},
};

use crate::error::Error;
use super::claim;
use super::helper;
use super::withdraw;

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
    if cheque_witness_is_none {
        // Check if the inputs contain the same input as receiver lock hash or sender lock hash
        if helper::has_input_by_lock_hash(&receiver_lock_hash) {
            claim::validate(&sender_lock_hash, &receiver_lock_hash, cheque_witness_is_none)
        } else if helper::has_input_by_lock_hash(&sender_lock_hash) {
            withdraw::validate(&sender_lock_hash, cheque_witness_is_none)
        } else {
            Err(Error::NoMatchedInputs)
        }
    } else {
        // Validate the signatures of receiver and sender
        let mut context = unsafe { CKBDLContext::<[u8; 128 * 1024]>::new() };
        let lib = LibSecp256k1::load(&mut context);
        match helper::validate_blake2b_sighash_all(&lib, &receiver_lock_hash, &sender_lock_hash) {
            Ok(is_receiver) => {
                if is_receiver {
                    claim::validate(&sender_lock_hash, &receiver_lock_hash, cheque_witness_is_none)
                } else {
                    withdraw::validate(&sender_lock_hash, cheque_witness_is_none)
                }
            }
            Err(_) => Err(Error::NoMatchedSignature),
        }
    }
}

fn cheque_cell_witness_is_none() -> Result<bool, Error> {
    match load_witness_args(0, Source::GroupInput) {
        Ok(witness_args) => Ok(witness_args.lock().to_opt().is_none()),
        Err(_) => Ok(true),
    }
}
