use core::result::Result;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::*,
    dynamic_loading::CKBDLContext,
    high_level::{load_script_hash, load_witness_args},
};
use ckb_lib_secp256k1::LibSecp256k1;
use crate::error::Error;
use super::helper;

pub fn validate(receiver: [u8; 20], cheque_witness_is_none: bool, sender_lock_hash: [u8; 20]) -> Result<(), Error> {
  let script_hash = load_script_hash()?;
  let mut cheque_lock_hash = [0u8; 20];
  cheque_lock_hash.copy_from_slice(&script_hash[0..20]);

  if !check_sender_cells_capacity_same(sender_lock_hash, cheque_lock_hash) {
    return Err(Error::SenderCapacityNotSame);
  }

  if !check_cheque_inputs_since_zero() {
    return Err(Error::ClaimChequeInputSinceNotZero);
  }

  if cheque_witness_is_none {
    // The receiver is lock hash
    match helper::position_input_by_lock_hash(receiver) {
      Some(position) => {
        match load_witness_args(position, Source::Input) {
          Ok(witness_args) => {
            if witness_args.lock().to_opt().is_none() {
              return Err(Error::WitnessSignatureWrong)
            }
          },
          Err(_) => return Err(Error::WitnessSignatureWrong)
        }
      },
      None => return Err(Error::NoMatchedReceiverInput)
    }
  } else {
    // The receiver is lock args
    let mut context = unsafe{ CKBDLContext::<[u8; 128 * 1024]>::new()};
    let lib = LibSecp256k1::load(&mut context);
    validate_blake2b_sighash_all(&lib, &receiver)?;
  }
  Ok(())
}

fn check_sender_cells_capacity_same(sender_lock_hash: [u8; 20], cheque_lock_hash: [u8; 20]) -> bool {
  let sender_inputs = helper::filter_cells_by_lock_hash(sender_lock_hash, Source::Input);
  let sum_sender_inputs_capacity = match sender_inputs {
    Some(inputs) => helper::calc_cells_capacity_sum(inputs),
    None => 0
  };

  let sender_outputs = helper::filter_cells_by_lock_hash(sender_lock_hash, Source::Output);
  let sum_sender_outputs_capacity = match sender_outputs {
    Some(outputs) => helper::calc_cells_capacity_sum(outputs),
    None => 0
  };
  
  let cheque_inputs = helper::filter_cells_by_lock_hash(cheque_lock_hash, Source::Input);
  let sum_cheque_inputs_capacity = match cheque_inputs {
    Some(inputs) => helper::calc_cells_capacity_sum(inputs),
    None => 0
  };

  sum_cheque_inputs_capacity == sum_sender_outputs_capacity - sum_sender_inputs_capacity
}

fn check_cheque_inputs_since_zero() -> bool {
  let cheque_inputs = helper::load_group_inputs();
  for input in cheque_inputs.iter() {
    if input.since().unpack() > 0 {
      return false;
    }
  }
  true
}


fn validate_blake2b_sighash_all(
    lib: &LibSecp256k1,
    expected_pubkey_hash: &[u8],
) -> Result<(), Error> {
    let mut pubkey_hash = [0u8; 20];
    lib.validate_blake2b_sighash_all(&mut pubkey_hash)
        .map_err(|_err_code| Error::Secp256k1Wrong)?;

    if &pubkey_hash[..] != expected_pubkey_hash {
        return Err(Error::WrongPubKey);
    }
    Ok(())
}