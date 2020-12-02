use super::*;

use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::{Bytes, BytesMut, BufMut},
    packed::Bytes as PackedBytes,
    core::{TransactionBuilder, TransactionView},
    packed::*,
    prelude::*,
};
extern crate hex;
use hex::FromHex;
use ckb_tool::ckb_error::assert_error_eq;
use ckb_tool::ckb_script::ScriptError;

const MAX_CYCLES: u64 = 10_000_000;

// error numbers
const SENDER_LOCK_HASH_NOT_MATCH: i8 = 7;
const SENDER_WITNESS_NOT_EXIST: i8 = 8;

fn build_test_context(
    sender_lock_hash: Option<Bytes>,
    sender_witness: Option<PackedBytes>
) -> (Context, TransactionView) {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-cheque-script");
    let out_point = context.deploy_cell(contract_bin);

    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
    .build_script(&always_success_out_point, Bytes::from(vec![42]))
    .expect("script");
    let sender_always_success_lock_script_hash = always_success_lock_script.calc_script_hash().raw_data().slice(0..20);

    let mut buf = BytesMut::with_capacity(40);
    buf.put(Bytes::from("helloworldhelloworld"));
    buf.put(sender_lock_hash.unwrap_or(sender_always_success_lock_script_hash.clone()));

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, buf.clone().freeze())
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(out_point)
        .build();

    // prepare cells
    let cheque_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(162u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let sender_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(always_success_lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let inputs = vec![
        CellInput::new_builder()
            .previous_output(cheque_input_out_point)
            .build(),
        CellInput::new_builder()
            .previous_output(sender_input_out_point)
            .build()
    ];
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1019u64.pack())
            .lock(always_success_lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(142u64.pack())
            .lock(always_success_lock_script.clone())
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];
    let witnesses = vec![
        Bytes::new().pack(),
        sender_witness.unwrap_or(Vec::from_hex("55000000100000005500000055000000410000003d7e28511c3c5c4940cbddf0450aa27f830db1c8c76b9178b35b1cf7e67cfe3a7a1a949c6ede61bc4583a76d0cac3cdcb06f389eb7fd964c219d8a16ba7b860e01").unwrap().pack())
    ];

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .witnesses(witnesses)
        .build();
    (context, tx)
}

#[test]
fn test_verify_succeed() {
    let (mut context, tx) = build_test_context(None, None);
    let tx = context.complete_tx(tx);

    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("cycles: {}", cycles);
}

#[test]
fn test_lock_hash_not_match() {
    let wrong_lock_hash = Bytes::from("helloworldhelloworld");
    let (mut context, tx) = build_test_context(Some(wrong_lock_hash), None);
    let tx = context.complete_tx(tx);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(SENDER_LOCK_HASH_NOT_MATCH).input_lock_script(script_cell_index)
    );
}

#[test]
fn test_witness_not_exist() {
    let null_witness = Bytes::new().pack();
    let (mut context, tx) = build_test_context(None, Some(null_witness));
    let tx = context.complete_tx(tx);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(SENDER_WITNESS_NOT_EXIST).input_lock_script(script_cell_index)
    );
}
