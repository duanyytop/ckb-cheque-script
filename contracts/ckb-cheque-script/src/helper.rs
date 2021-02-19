use ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed::*, prelude::*},
    high_level::{load_cell, load_input_since, load_witness_args, QueryIter},
};

use super::{hash, secp256k1};
use crate::error::Error;
use alloc::vec::Vec;

pub fn has_input_by_lock_hash(lock_hash: &[u8; 20]) -> bool {
    QueryIter::new(load_cell, Source::Input)
        .any(|cell| &hash::blake2b_160(cell.lock().as_slice()) == lock_hash)
}

pub fn position_input_by_lock_hash(lock_hash: &[u8; 20]) -> Option<usize> {
    QueryIter::new(load_cell, Source::Input)
        .position(|cell| &hash::blake2b_160(cell.lock().as_slice()) == lock_hash)
}

pub fn load_group_inputs_since() -> Vec<u64> {
    QueryIter::new(load_input_since, Source::GroupInput).collect::<Vec<_>>()
}

fn add_capacity(c1: u64, c2: u64) -> Result<u64, Error> {
    match c1.checked_add(c2) {
        Some(sum) => Ok(sum),
        None => Err(Error::Encoding),
    }
}

pub fn sum_cells_capacity_of_lock_hash(lock_hash: &[u8; 20], source: Source) -> Result<u64, Error> {
    QueryIter::new(load_cell, source)
        .filter(|cell| &hash::blake2b_160(cell.lock().as_slice()) == lock_hash)
        .try_fold(0, |sum, c| add_capacity(sum, c.capacity().unpack()))
}

pub fn check_witness_args(position: usize) -> Result<(), Error> {
    match load_witness_args(position, Source::Input) {
        Ok(witness_args) => {
            if witness_args.lock().to_opt().is_none() {
                Err(Error::WitnessSignatureWrong)
            } else {
                Ok(())
            }
        }
        Err(_) => Err(Error::WitnessSignatureWrong),
    }
}

const TYPE: u8 = 1;
const CODE_HASH_SECP256K1_BLAKE160: [u8; 32] = [
    155, 215, 224, 111, 62, 207, 75, 224, 242, 252, 210, 24, 139, 35, 241, 185, 252, 200, 142, 93,
    75, 101, 168, 99, 123, 23, 114, 59, 189, 163, 204, 232,
];
// Recover public key from the signature 
// and check whether the public key belongs to the receiver or sender.
pub fn validate_signature_of_receiver_and_sender(
    receiver_lock_hash: &[u8; 20],
    sender_lock_hash: &[u8; 20],
) -> Result<bool, Error> {
    let mut public_key_hash = [0u8; 20];
    secp256k1::validate_blake2b_signature(&mut public_key_hash)
        .map_err(|_| Error::Secp256k1)?;

    let lock_script = Script::new_builder()
        .code_hash(CODE_HASH_SECP256K1_BLAKE160.pack())
        .args(public_key_hash.pack())
        .hash_type(Byte::new(TYPE))
        .build();
    let lock_hash = hash::blake2b_160(lock_script.as_slice());

    if receiver_lock_hash == &lock_hash {
        Ok(true)
    } else if sender_lock_hash == &lock_hash {
        Ok(false)
    } else {
        Err(Error::WrongPubKey)
    }
}
