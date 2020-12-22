use ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed::*, prelude::*},
    high_level::{load_cell, load_input_since, load_witness_args, QueryIter},
};
use ckb_lib_secp256k1::{LibSecp256k1, CODE_HASH_SECP256K1};

use alloc::vec::Vec;
use crate::error::Error;
use super::hash;

pub fn has_input_by_lock_hash(lock_hash: &[u8; 20]) -> bool {
    QueryIter::new(load_cell, Source::Input)
            .any(|cell| &hash::blake2b_160(cell.lock().as_slice()) == lock_hash)
}

pub fn position_input_by_lock_hash(lock_hash: &[u8; 20]) -> Option<usize> {
    QueryIter::new(load_cell, Source::Input)
            .position(|cell| &hash::blake2b_160(cell.lock().as_slice()) == lock_hash)
}

pub fn filter_cells_by_lock_hash(lock_hash: &[u8; 20], source: Source) -> Option<Vec<CellOutput>> {
    let cells = QueryIter::new(load_cell, source)
            .filter(|cell| &hash::blake2b_160(cell.lock().as_slice()) == lock_hash)
            .collect::<Vec<_>>();
    if cells.len() == 0 {
      None
    } else {
      Some(cells)
    }
}

pub fn load_group_inputs_since() -> Vec<u64> {
    QueryIter::new(load_input_since, Source::GroupInput)
            .collect::<Vec<_>>()
}

pub fn calc_cells_capacity_sum(cells: Vec<CellOutput>) -> u64 {
  cells.into_iter().fold(0, |sum, c| sum + c.capacity().unpack())
}

pub fn check_witness_args(position: usize) -> Result<(), Error>{
  match load_witness_args(position, Source::Input) {
    Ok(witness_args) => {
      if witness_args.lock().to_opt().is_none() {
        Err(Error::WitnessSignatureWrong)
      } else {
        Ok(())
      }
    },
    Err(_) => Err(Error::WitnessSignatureWrong)
  }
}

const DATA: u8 = 0;
pub fn validate_blake2b_sighash_all(lib: &LibSecp256k1, lock_hash: &[u8; 20]) -> Result<(), Error> {
  // recover public_key_hash
  let mut public_key_hash = [0u8; 20];
  lib.validate_blake2b_sighash_all(&mut public_key_hash)
      .map_err(|_| Error::Secp256k1)?;

  let lock_script = Script::new_builder()
                                .code_hash(CODE_HASH_SECP256K1.pack())
                                .args(public_key_hash.pack())
                                .hash_type(Byte::new(DATA))
                                .build();

  if lock_hash != &hash::blake2b_160(lock_script.as_slice()) {
      return Err(Error::WrongPubKey);
  }
  Ok(())
}