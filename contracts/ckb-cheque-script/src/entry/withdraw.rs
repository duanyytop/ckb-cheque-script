use core::result::Result;

use crate::error::Error;

use ckb_std::{
  high_level::{load_script, load_cell_lock_hash, QueryIter, load_witness_args},
  ckb_types::{bytes::Bytes, prelude::*},
  ckb_constants::Source
};


pub fn validate() -> Result<(), Error> {
  let script = load_script()?;
  let args: Bytes = script.args().unpack();

  check_same_lock_cell(&args)?;
  return Ok(())
}

fn check_same_lock_cell(args: &Bytes) -> Result<bool, Error> {
  let sender_cell_lock_hash = args.slice(20..40);
  let sender_cell_index = QueryIter::new(load_cell_lock_hash, Source::Input).position(|lock_hash| {
    &sender_cell_lock_hash[..] == &lock_hash[0 .. 20]
  });

  if sender_cell_index.is_none() {
    return Err(Error::SenderLockHashNotMatch)
  }

  let sender_witness_args = load_witness_args(sender_cell_index.unwrap(), Source::Input);

  if sender_witness_args.clone().is_ok() && sender_witness_args.clone().unwrap().total_size() != 0 {
      return Ok(true)
  } else {
      return Err(Error::SenderWitnessNotExist)
  }
}
