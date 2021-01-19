use super::helper;
use crate::error::Error;
use core::result::Result;

const CHEQUE_CELL_SINCE: u64 = 0xA000000000000006;

pub fn validate(sender_lock_hash: &[u8; 20], cheque_witness_is_none: bool) -> Result<(), Error> {
    let cheque_inputs_since = helper::load_group_inputs_since();
    if cheque_inputs_since
        .into_iter()
        .any(|since| since != CHEQUE_CELL_SINCE)
    {
        return Err(Error::WithdrawChequeInputSinceError);
    }

    if cheque_witness_is_none {
        match helper::position_input_by_lock_hash(sender_lock_hash) {
            Some(position) => helper::check_witness_args(position),
            None => Err(Error::NoMatchedInputs),
        }
    } else {
        Ok(())
    }
}
