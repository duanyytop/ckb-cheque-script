const CKB_SUCCESS: i32 = 0;

#[link(name = "ckb-lib-secp256k1", kind="static")]
extern "C" {
    fn validate_blake2b_sighash_all(pubkey_hash: *const u8) -> i32;
}

pub fn validate_blake2b_signature(pubkey_hash: &mut [u8; 20]) -> Result<(), i32> {
    let error_code = unsafe { validate_blake2b_sighash_all(pubkey_hash.as_mut_ptr()) };
    if error_code != CKB_SUCCESS {
        return Err(error_code);
    }
    Ok(())
}

