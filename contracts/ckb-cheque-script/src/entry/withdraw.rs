use core::result::Result;
use crate::error::Error;
use super::helper;

pub fn validate(sender_lock_hash: [u8; 20]) -> Result<(), Error> {
  const CHEQUE_CELL_SINCE: u64 = 0xA000000000000006;

  let cheque_inputs_since = helper::load_group_inputs_since();
  if cheque_inputs_since.into_iter().any(|since| since != CHEQUE_CELL_SINCE) {
    return Err(Error::WithdrawChequeInputSinceError);
  }

  match helper::position_input_by_lock_hash(sender_lock_hash) {
    Some(position) => helper::check_witness_args(position),
    None => Err(Error::NoMatchedInputs)
  }
}
