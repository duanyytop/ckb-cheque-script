use core::result::Result;
use ckb_std::{
    ckb_types::prelude::*,
};
use crate::error::Error;
use super::helper;

pub fn validate(sender_lock_hash: [u8; 20]) -> Result<(), Error> {
  const CHEQUE_CELL_SINCE: u64 = 0xA000000000000006;

  let cheque_inputs = helper::load_group_inputs();
  for input in cheque_inputs.iter() {
    if input.since().unpack() != CHEQUE_CELL_SINCE {
      return Err(Error::WithdrawChequeInputSinceError);
    }
  }

  match helper::position_input_by_lock_hash(sender_lock_hash) {
    Some(position) => helper::check_witness_args(position),
    None => Err(Error::NoMatchedSenderInput)
  }
}
