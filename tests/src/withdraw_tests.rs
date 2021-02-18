use super::{
    helper::{blake160, sign_tx, write_native_setup, CODE_HASH_SECP256K1_BLAKE160, TYPE, MAX_CYCLES},
    *,
};
use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_crypto::secp::Generator;
use ckb_tool::ckb_error::assert_error_eq;
use ckb_tool::ckb_script::ScriptError;
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionBuilder, TransactionView},
    packed::*,
    prelude::*,
};
use ckb_x64_simulator::RunningSetup;
use std::collections::HashMap;

const NO_MATCHED_INPUTS: i8 = 6;
const WITNESS_SIGNATURE_WRONG: i8 = 7;
const WITHDRAW_CHEQUE_INPUT_SINCE_ERROR: i8 = 11;

fn build_test_context_with_sender_input(
    sender_lock_args: Bytes,
    receiver_lock_args: Bytes,
    inputs_token: Vec<u64>,
    outputs_token: Vec<u64>,
    signature: Bytes,
    since: u64,
    is_sender_input_error: bool,
) -> (Context, TransactionView) {
    // deploy cheque script
    let mut context = Context::default();
    let cheque_bin: Bytes = Loader::default().load_binary("ckb-cheque-script");
    let cheque_out_point = context.deploy_cell(cheque_bin);

    // deploy always_success script
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    // build lock script
    let receiver_always_success_lock_script = context
        .build_script(&always_success_out_point, receiver_lock_args)
        .expect("script");
    let receiver_always_success_lock_hash = receiver_always_success_lock_script.calc_script_hash();
    let sender_always_success_lock_script = context
        .build_script(&always_success_out_point, sender_lock_args)
        .expect("script");
    let sender_always_success_lock_hash = sender_always_success_lock_script.calc_script_hash();
    let always_success_lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    let mut cheque_lock_args = receiver_always_success_lock_hash
        .as_bytes()
        .slice(0..20)
        .to_vec();
    let sender_lock_hash = if is_sender_input_error {
        receiver_always_success_lock_hash
    } else {
        sender_always_success_lock_hash
    };
    cheque_lock_args.extend_from_slice(&sender_lock_hash.as_bytes().slice(0..20).to_vec());
    let cheque_script = context
        .build_script(&cheque_out_point, Bytes::copy_from_slice(&cheque_lock_args))
        .expect("script");

    // prepare inputs
    let mut inputs = vec![];
    for index in 0..inputs_token.len() {
        let token = inputs_token.get(index).unwrap();
        let capacity = Capacity::shannons(*token);
        let input_out_point = if index == 0 {
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(capacity.pack())
                    .lock(cheque_script.clone())
                    .build(),
                token.to_le_bytes().to_vec().into(),
            )
        } else {
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(capacity.pack())
                    .lock(sender_always_success_lock_script.clone())
                    .build(),
                token.to_le_bytes().to_vec().into(),
            )
        };
        let input_since = if index == 0 { since } else { 0 };
        let input = CellInput::new_builder()
            .previous_output(input_out_point)
            .since(input_since.pack())
            .build();
        inputs.push(input);
    }

    // prepare outputs
    let mut outputs = vec![];
    for index in 0..outputs_token.len() {
        let token = outputs_token.get(index).unwrap();
        let capacity = Capacity::shannons(*token);
        let output = CellOutput::new_builder()
            .capacity(capacity.pack())
            .lock(sender_always_success_lock_script.clone())
            .build();
        outputs.push(output);
    }

    let cheque_script_dep = CellDep::new_builder().out_point(cheque_out_point).build();
    let outputs_data: Vec<_> = outputs_token
        .iter()
        .map(|_token| Bytes::from("0x"))
        .collect();
    let mut witnesses = vec![];
    witnesses.push(Bytes::new());
    witnesses.push(signature);
    if inputs.len() > 2 {
        for _ in 2..inputs.len() {
            witnesses.push(Bytes::new())
        }
    }

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(cheque_script_dep)
        .cell_dep(always_success_lock_script_dep)
        .witnesses(witnesses.pack())
        .build();
    (context, tx)
}

fn build_test_context_with_sender_signature(
    receiver_lock_args: Bytes,
    inputs_token: Vec<u64>,
    outputs_token: Vec<u64>,
    since: u64,
) -> (Context, TransactionView) {
    // generate key pair
    let private_key = Generator::random_privkey();
    let public_key = private_key.pubkey().expect("pubkey");
    let sender_lock_args = blake160(&public_key.serialize());

    // deploy cheque script
    let mut context = Context::default();
    let cheque_bin: Bytes = Loader::default().load_binary("ckb-cheque-script");
    let cheque_out_point = context.deploy_cell(cheque_bin);

    let secp256k1_bin: Bytes =
        fs::read("../ckb-miscellaneous-scripts/build/secp256k1_blake2b_sighash_all_dual")
            .expect("load secp256k1")
            .into();
    let secp256k1_out_point = context.deploy_cell(secp256k1_bin);

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    let receiver_secp256k1_lock_script = Script::new_builder()
        .code_hash(CODE_HASH_SECP256K1_BLAKE160.pack())
        .args(receiver_lock_args.pack())
        .hash_type(Byte::new(TYPE))
        .build();
    let receiver_secp256k1_lock_hash = receiver_secp256k1_lock_script.calc_script_hash();

    let sender_secp256k1_lock_script = Script::new_builder()
        .code_hash(CODE_HASH_SECP256K1_BLAKE160.pack())
        .args(sender_lock_args.pack())
        .hash_type(Byte::new(TYPE))
        .build();
    let sender_secp256k1_lock_hash = sender_secp256k1_lock_script.calc_script_hash();

    let secp256k1_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point)
        .build();

    let mut cheque_lock_args = receiver_secp256k1_lock_hash
        .as_bytes()
        .slice(0..20)
        .to_vec();
    cheque_lock_args
        .extend_from_slice(&sender_secp256k1_lock_hash.as_bytes().slice(0..20).to_vec());
    let cheque_script = context
        .build_script(&cheque_out_point, Bytes::copy_from_slice(&cheque_lock_args))
        .expect("script");

    // prepare inputs
    let mut inputs = vec![];
    for index in 0..inputs_token.len() {
        let token = inputs_token.get(index).unwrap();
        let capacity = Capacity::shannons(*token);
        let input_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(cheque_script.clone())
                .build(),
            token.to_le_bytes().to_vec().into(),
        );
        let input_since = if index == 0 { since } else { 0 };
        let input = CellInput::new_builder()
            .previous_output(input_out_point)
            .since(input_since.pack())
            .build();
        inputs.push(input);
    }

    // prepare outputs
    let mut outputs = vec![];
    for index in 0..outputs_token.len() {
        let token = outputs_token.get(index).unwrap();
        let capacity = Capacity::shannons(*token);
        let output = CellOutput::new_builder()
            .capacity(capacity.pack())
            .lock(sender_secp256k1_lock_script.clone())
            .build();
        outputs.push(output);
    }

    let cheque_script_dep = CellDep::new_builder().out_point(cheque_out_point).build();
    let outputs_data: Vec<_> = outputs_token
        .iter()
        .map(|_token| Bytes::from("0x"))
        .collect();

    let mut witnesses = vec![];
    for _ in 0..inputs.len() {
        witnesses.push(Bytes::new())
    }

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(cheque_script_dep)
        .cell_dep(secp256k1_dep)
        .cell_dep(secp256k1_data_dep)
        .witnesses(witnesses.pack())
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(tx, &private_key);
    (context, tx)
}

#[test]
fn test_withdraw_with_sender_input() {
    let (mut context, tx) = build_test_context_with_sender_input(
  Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000],
        vec![200_0000_0000, 162_0000_0000],
        Bytes::from(
            hex::decode("5500000010000000550000005500000041000000b69c542c0ee6c4b6d8350514d876ea7d8ef563e406253e959289457204447d2c4eb4e4a993073f5e76d244d2f93f7c108652e3295a9c8d72c12477e095026b9500").unwrap()),
            0xA000000000000006,
            false,
    );
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // dump raw test tx files
    let setup = RunningSetup {
        is_lock_script:  true,
        is_output:       false,
        script_index:    0,
        native_binaries: HashMap::default(),
    };
    write_native_setup(
        "test_withdraw_with_sender_input",
        "ckb-cheque-script-sim",
        &tx,
        &context,
        &setup,
    );
}

#[test]
fn test_error_withdraw_with_no_sender_input() {
    let (mut context, tx) = build_test_context_with_sender_input(
  Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000],
        vec![200_0000_0000, 162_0000_0000],
        Bytes::from(
            hex::decode("5500000010000000550000005500000041000000b69c542c0ee6c4b6d8350514d876ea7d8ef563e406253e959289457204447d2c4eb4e4a993073f5e76d244d2f93f7c108652e3295a9c8d72c12477e095026b9500").unwrap()),
            0xA000000000000006,
            true,
    );
    let tx = context.complete_tx(tx);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(NO_MATCHED_INPUTS).input_lock_script(script_cell_index)
    );

    // dump raw test tx files
    let setup = RunningSetup {
        is_lock_script:  true,
        is_output:       false,
        script_index:    0,
        native_binaries: HashMap::default(),
    };
    write_native_setup(
        "test_error_withdraw_with_no_sender_input",
        "ckb-cheque-script-sim",
        &tx,
        &context,
        &setup,
    );
}

#[test]
fn test_error_withdraw_with_sender_input_signature() {
    let (mut context, tx) = build_test_context_with_sender_input(
        Bytes::from(hex::decode("36c329ed630d6ce750712a477543672adab57f4c").unwrap()),
        Bytes::from(hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5").unwrap()),
        vec![162_0000_0000, 200_0000_0000],
        vec![200_0000_0000, 162_0000_0000],
        Bytes::from(
            hex::decode("5500000010000000550000005500000041000000b69c542c0ee6c4b6d8350514d876ea7d")
                .unwrap(),
        ),
        0xA000000000000006,
        false,
    );
    let tx = context.complete_tx(tx);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(WITNESS_SIGNATURE_WRONG)
            .input_lock_script(script_cell_index)
    );
}

#[test]
fn test_error_withdraw_with_sender_input_since() {
    let (mut context, tx) = build_test_context_with_sender_input(
  Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000],
        vec![200_0000_0000, 162_0000_0000],
        Bytes::from(
            hex::decode("5500000010000000550000005500000041000000b69c542c0ee6c4b6d8350514d876ea7d8ef563e406253e959289457204447d2c4eb4e4a993073f5e76d244d2f93f7c108652e3295a9c8d72c12477e095026b9500").unwrap()),
        100000,
            false,
    );
    let tx = context.complete_tx(tx);

    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(WITHDRAW_CHEQUE_INPUT_SINCE_ERROR)
            .input_lock_script(script_cell_index)
    );

    // dump raw test tx files
    let setup = RunningSetup {
        is_lock_script:  true,
        is_output:       false,
        script_index:    0,
        native_binaries: HashMap::default(),
    };
    write_native_setup(
        "test_error_withdraw_with_sender_input_since",
        "ckb-cheque-script-sim",
        &tx,
        &context,
        &setup,
    );
}

#[test]
fn test_withdraw_with_sender_signature() {
    let (mut context, tx) = build_test_context_with_sender_signature(
        Bytes::from(hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5").unwrap()),
        vec![162_0000_0000],
        vec![162_0000_0000],
        0xA000000000000006,
    );
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_error_withdraw_with_sender_signature_since() {
    let (mut context, tx) = build_test_context_with_sender_signature(
        Bytes::from(hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5").unwrap()),
        vec![162_0000_0000],
        vec![162_0000_0000],
        100000,
    );
    let tx = context.complete_tx(tx);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(WITHDRAW_CHEQUE_INPUT_SINCE_ERROR)
            .input_lock_script(script_cell_index)
    );
}
