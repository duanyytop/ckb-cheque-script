use ckb_std::error::SysError;

/// Error
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    InvalidArgument = 5,
    NoMatchedInputOrWitness,
    NoMatchedReceiverInput,
    WitnessSignatureWrong,
    SenderCapacityNotSame,
    WrongPubKey = 10,
    ClaimChequeInputSinceNotZero,
    LoadPrefilledData,
    RecoverPublicKey,
    NoMatchedSenderInput,
    WithdrawChequeInputSinceError = 15,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

