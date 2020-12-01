use core::result::Result;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    dynamic_loading::CKBDLContext,
    high_level::{load_script_hash, load_witness_args},
};
use ckb_lib_secp256k1::LibSecp256k1;
use crate::error::Error;
use super::helper;

pub fn validate(receiver: [u8; 20], witness_lock_is_none: bool, sender_lock_hash: [u8; 20]) -> Result<(), Error> {
  let script_hash = load_script_hash()?;
  let mut cheque_lock_hash = [0u8; 20];
  cheque_lock_hash.copy_from_slice(&script_hash);

  if !check_sender_cells_capacity_same(sender_lock_hash, cheque_lock_hash) {
    return Err(Error::SenderCapacityNotSame);
  }

  if witness_lock_is_none {
    // receiver -> receiver lock hash
    match helper::position_input_by_lock_hash(receiver) {
      Some(position) => {
        let input_witness_args = load_witness_args(position, Source::Input)?;
        if input_witness_args.lock().to_opt().is_none() {
          return Err(Error::WitnessSignatureNone)
        }
      },
      None => return Err(Error::NoMatchedReceiverInput)
    }
  } else {
    // receiver -> receiver lock args
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


fn validate_blake2b_sighash_all(
    lib: &LibSecp256k1,
    expected_pubkey_hash: &[u8],
) -> Result<(), Error> {
    let mut pubkey_hash = [0u8; 20];
    lib.validate_blake2b_sighash_all(&mut pubkey_hash)
        .map_err(|_err_code| Error::Secp256k1Error)?;

    if &pubkey_hash[..] != expected_pubkey_hash {
        return Err(Error::WrongPubKey);
    }
    Ok(())
}