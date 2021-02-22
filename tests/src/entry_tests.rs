use super::{
    helper::{sign_tx, write_native_setup, CODE_HASH_SECP256K1_BLAKE160, TYPE, MAX_CYCLES},
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

const INVALID_ARGUMENT: i8 = 5;
const NO_MATCHED_INPUTS: i8 = 6;
const NO_MATCHED_SIGNATURE: i8 = 13;

fn build_test_context(
    sender_lock_args: Bytes,
    receiver_lock_args: Bytes,
    inputs_token: Vec<u64>,
    outputs_token: Vec<u64>,
    another_lock_args: Option<Bytes>,
    is_cheque_args_error: bool,
) -> (Context, TransactionView) {
    // deploy cheque script
    let mut context = Context::default();
    let cheque_bin: Bytes = Loader::default().load_binary("ckb-cheque-script");
    let cheque_out_point = context.deploy_cell(cheque_bin);

    // deploy always_success script
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // build lock script
    let receiver_always_success_lock_script = context
        .build_script(
            &always_success_out_point,
            Bytes::copy_from_slice(&receiver_lock_args),
        )
        .expect("script");
    let receiver_always_success_lock_hash = receiver_always_success_lock_script.calc_script_hash();

    let sender_always_success_lock_script = context
        .build_script(&always_success_out_point, sender_lock_args.clone())
        .expect("script");
    let sender_always_success_lock_hash = sender_always_success_lock_script.calc_script_hash();

    let mut cheque_lock_args = if is_cheque_args_error {
        receiver_always_success_lock_hash
            .clone()
            .as_bytes()
            .slice(0..10)
            .to_vec()
    } else {
        receiver_always_success_lock_hash
            .clone()
            .as_bytes()
            .slice(0..20)
            .to_vec()
    };
    cheque_lock_args.extend_from_slice(
        &sender_always_success_lock_hash
            .as_bytes()
            .slice(0..20)
            .to_vec(),
    );
    let cheque_script = context
        .build_script(&cheque_out_point, Bytes::copy_from_slice(&cheque_lock_args))
        .expect("script");

    let another_lock_script = match another_lock_args {
        Some(args) => context.build_script(&always_success_out_point, args),
        None => None,
    };

    let always_success_lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    let lock_script = if another_lock_script.is_none() {
        receiver_always_success_lock_script.clone()
    } else {
        another_lock_script.clone().unwrap()
    };

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
                    .lock(lock_script.clone())
                    .build(),
                token.to_le_bytes().to_vec().into(),
            )
        };
        let input = CellInput::new_builder()
            .previous_output(input_out_point)
            .build();
        inputs.push(input);
    }

    // prepare outputs
    let mut outputs = vec![];
    for index in 0..outputs_token.len() {
        let token = outputs_token.get(index).unwrap();
        let capacity = Capacity::shannons(*token);
        let output = if index == 0 {
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(lock_script.clone())
                .build()
        } else {
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(sender_always_success_lock_script.clone())
                .build()
        };
        outputs.push(output);
    }

    let cheque_script_dep = CellDep::new_builder().out_point(cheque_out_point).build();
    let outputs_data: Vec<_> = outputs_token
        .iter()
        .map(|_token| Bytes::from("0x"))
        .collect();

    let mut witnesses = vec![];
    for _ in 0..inputs.len() - 1 {
        witnesses.push(Bytes::new())
    }
    let signature = Bytes::from(
        hex::decode("550000001000000055000000550000004100000012948c423725b32094533c33f846dee105e2532250d252ee0694c1093576dedf5c48319296a650742ce3828bae387382962272856283b8842303bb547f21867101").unwrap());
    witnesses.push(signature);

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

fn build_test_context_with_signature(
    sender_lock_args: Bytes,
    receiver_lock_args: Bytes,
    inputs_token: Vec<u64>,
    outputs_token: Vec<u64>,
) -> (Context, TransactionView) {
    // deploy cheque script
    let mut context = Context::default();
    let cheque_bin: Bytes = Loader::default().load_binary("ckb-cheque-script");
    let cheque_out_point = context.deploy_cell(cheque_bin);

    // deploy always_success script
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();
    // build lock script
    let receiver_secp256k1_lock_script = Script::new_builder()
        .code_hash(CODE_HASH_SECP256K1_BLAKE160.pack())
        .args(receiver_lock_args.pack())
        .hash_type(Byte::new(TYPE))
        .build();
    let receiver_secp256k1_lock_hash = receiver_secp256k1_lock_script.calc_script_hash();

    let receiver_always_success_lock_script = context
        .build_script(
            &always_success_out_point,
            Bytes::copy_from_slice(&receiver_lock_args),
        )
        .expect("script");

    let sender_secp256k1_lock_script = Script::new_builder()
        .code_hash(CODE_HASH_SECP256K1_BLAKE160.pack())
        .args(sender_lock_args.pack())
        .hash_type(Byte::new(TYPE))
        .build();
    let sender_secp256k1_lock_hash = sender_secp256k1_lock_script.calc_script_hash();

    let mut cheque_lock_args = receiver_secp256k1_lock_hash
        .clone()
        .as_bytes()
        .slice(0..20)
        .to_vec();
    cheque_lock_args
        .extend_from_slice(&sender_secp256k1_lock_hash.as_bytes().slice(0..20).to_vec());
    let cheque_script = context
        .build_script(&cheque_out_point, Bytes::copy_from_slice(&cheque_lock_args))
        .expect("script");

    let always_success_lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

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
                    .lock(receiver_always_success_lock_script.clone())
                    .build(),
                token.to_le_bytes().to_vec().into(),
            )
        };
        let input = CellInput::new_builder()
            .previous_output(input_out_point)
            .build();
        inputs.push(input);
    }

    // prepare outputs
    let mut outputs = vec![];
    for index in 0..outputs_token.len() {
        let token = outputs_token.get(index).unwrap();
        let capacity = Capacity::shannons(*token);
        let output = if index == 0 {
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(receiver_always_success_lock_script.clone())
                .build()
        } else {
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(sender_secp256k1_lock_script.clone())
                .build()
        };
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
        .cell_dep(secp256k1_data_dep)
        .cell_dep(always_success_lock_script_dep)
        .witnesses(witnesses.pack())
        .build();
    let tx = sign_tx(tx, &Generator::random_privkey());
    (context, tx)
}

#[test]
fn test_error_cheque_with_invalid_args() {
    let (mut context, tx) = build_test_context(
        Bytes::from(hex::decode("36c329ed630d6ce750712a477543672adab5f5").unwrap()),
        Bytes::from(hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5").unwrap()),
        vec![162_0000_0000, 200_0000_0000],
        vec![200_0000_0000, 162_0000_0000],
        None,
        true,
    );
    let tx = context.complete_tx(tx);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(INVALID_ARGUMENT).input_lock_script(script_cell_index)
    );

    // dump raw test tx files
    let setup = RunningSetup {
        is_lock_script:  true,
        is_output:       false,
        script_index:    0,
        native_binaries: HashMap::default(),
    };
    write_native_setup(
        "test_error_cheque_with_invalid_args",
        "ckb-cheque-script-sim",
        &tx,
        &context,
        &setup,
    );
}

#[test]
fn test_error_claim_with_no_matched_receiver_input() {
    let (mut context, tx) = build_test_context(
        Bytes::from(hex::decode("36c329ed630d6ce750712a477543672adab57f4c").unwrap()),
        Bytes::from(hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5").unwrap()),
        vec![162_0000_0000, 200_0000_0000],
        vec![200_0000_0000, 162_0000_0000],
        Some(Bytes::from(
            hex::decode("373cc005be4edf45c829363d54799ac4f7aff569").unwrap(),
        )),
        false,
    );
    let tx = context.complete_tx(tx);

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
        "test_error_claim_with_no_matched_receiver_input",
        "ckb-cheque-script-sim",
        &tx,
        &context,
        &setup,
    );
}

#[test]
fn test_error_with_no_matched_signature() {
    let (mut context, tx) = build_test_context_with_signature(
        Bytes::from(hex::decode("23c329ed630d6ce750712a477543672adab57f4c").unwrap()),
        Bytes::from(hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5").unwrap()),
        vec![162_0000_0000, 200_0000_0000],
        vec![200_0000_0000, 162_0000_0000],
    );
    let tx = context.complete_tx(tx);

    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(NO_MATCHED_SIGNATURE).input_lock_script(script_cell_index)
    );

    // dump raw test tx files
    let setup = RunningSetup {
        is_lock_script:  true,
        is_output:       false,
        script_index:    0,
        native_binaries: HashMap::default(),
    };
    write_native_setup(
        "test_error_with_no_matched_signature",
        "ckb-cheque-script-sim",
        &tx,
        &context,
        &setup,
    );
}
