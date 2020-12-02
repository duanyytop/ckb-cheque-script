use super::*;
use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_crypto::secp::{Generator, Privkey};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionBuilder, TransactionView},
    packed::{self, *},
    prelude::*,
    H256,
};
use ckb_tool::ckb_hash::{blake2b_256, new_blake2b};
use ckb_tool::ckb_error::assert_error_eq;
use ckb_tool::ckb_script::ScriptError;

const MAX_CYCLES: u64 = 100_000_000;

fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

fn sign_tx(tx: TransactionView, key: &Privkey, is_signature_error: bool) -> TransactionView {
    const SIGNATURE_SIZE: usize = 65;
    let signature_size = if is_signature_error {
      SIGNATURE_SIZE - 2
    } else {
      SIGNATURE_SIZE
    };

    let witnesses_len = tx.inputs().len();
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(signature_size, 0);
        buf.into()
    };
    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(sig.serialize())).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    for i in 1..witnesses_len {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    signed_witnesses.push(
        message.as_bytes().pack(),
    );
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

fn build_test_context_with_receiver_cell(
    sender_lock_args: Bytes,
    receiver_lock_args: Bytes,
    inputs_token: Vec<u64>,
    outputs_token: Vec<u64>,
    signature: Bytes,
    since: u64,
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

    let mut cheque_lock_args = receiver_always_success_lock_hash.clone().as_bytes().slice(0..20).to_vec();
    cheque_lock_args.extend_from_slice(&sender_always_success_lock_hash.as_bytes().slice(0..20).to_vec());
    let cheque_script = context
            .build_script(&cheque_out_point, Bytes::copy_from_slice(&cheque_lock_args))
            .expect("script");
      
    // prepare inputs
    let mut inputs = vec![];
    for index in 0..inputs_token.len() {
        let token = inputs_token.get(index).unwrap();
        let capacity = Capacity::shannons(*token);
        let input_out_point = if index == 0 {
          context.create_cell(CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(cheque_script.clone())
                .build(), 
            token.to_le_bytes().to_vec().into())
        } else if index < inputs_token.len() - 1 {
          context.create_cell(
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(receiver_always_success_lock_script.clone())
                .build(),
            token.to_le_bytes().to_vec().into())
        } else {
          context.create_cell(
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(sender_always_success_lock_script.clone())
                .build(),
            token.to_le_bytes().to_vec().into())
        };
        let input_since = if index == 0 {
          since
        } else {
          0
        };
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
        let output = if index == 0 {
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(receiver_always_success_lock_script.clone())
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
    witnesses.push(Bytes::new());
    witnesses.push(signature);
    for _ in 2..inputs.len() {
      witnesses.push(Bytes::new())
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

fn build_test_context_with_cheque_signature(
    receiver_lock_args: Bytes,
    sender_lock_args: Bytes,
    inputs_token: Vec<u64>,
    outputs_token: Vec<u64>,
    since: u64,
    is_signature_error: bool,
) -> (Context, TransactionView) {
  // generate key pair
    let private_key = Generator::random_privkey();
    let public_key = private_key.pubkey().expect("pubkey");
    let receiver_public_hash = blake160(&public_key.serialize());

    // deploy cheque script
    let mut context = Context::default();
    let cheque_bin: Bytes = Loader::default().load_binary("ckb-cheque-script");
    let cheque_out_point = context.deploy_cell(cheque_bin);

    let secp256k1_bin: Bytes =
        fs::read("../ckb-miscellaneous-scripts/build/secp256k1_blake2b_sighash_all_dual")
            .expect("load secp256k1")
            .into();
    let secp256k1_out_point = context.deploy_cell(secp256k1_bin);
    let secp256k1_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point.clone())
        .build();

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    // deploy always_success script
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    // build lock script
    let receiver_always_success_lock_script = context
        .build_script(&always_success_out_point, receiver_lock_args)
        .expect("script");
    let sender_always_success_lock_script = context
        .build_script(&always_success_out_point, sender_lock_args)
        .expect("script");
    let sender_always_success_lock_hash = sender_always_success_lock_script.calc_script_hash();
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    let mut cheque_lock_args = receiver_public_hash.to_vec();
    cheque_lock_args.extend_from_slice(&sender_always_success_lock_hash.as_bytes().slice(0..20).to_vec());
    let cheque_script = context
            .build_script(&cheque_out_point, Bytes::copy_from_slice(&cheque_lock_args))
            .expect("script");
      
    // prepare inputs
    let mut inputs = vec![];
    for index in 0..inputs_token.len() {
        let token = inputs_token.get(index).unwrap();
        let capacity = Capacity::shannons(*token);
        let input_out_point = if index == 0 {
          context.create_cell(CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(cheque_script.clone())
                .build(), 
            token.to_le_bytes().to_vec().into())
        } else if index < inputs_token.len() - 1 {
          context.create_cell(
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(receiver_always_success_lock_script.clone())
                .build(),
            token.to_le_bytes().to_vec().into())
        } else {
          context.create_cell(
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(sender_always_success_lock_script.clone())
                .build(),
            token.to_le_bytes().to_vec().into())
        };
        let input_since = if index == 0 {
          since
        } else {
          0
        };
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
        let output = if index == 0 {
            CellOutput::new_builder()
                .capacity(capacity.pack())
                .lock(receiver_always_success_lock_script.clone())
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
      for _ in 0..inputs.len() {
        witnesses.push(Bytes::new())
      }

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(cheque_script_dep)
        .cell_dep(always_success_script_dep)
        .cell_dep(secp256k1_dep)
        .cell_dep(secp256k1_data_dep)
        .witnesses(witnesses.pack())
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(tx, &private_key, is_signature_error);
    (context, tx)
}

#[test]
fn test_claim_with_receiver_input() {
    let (mut context, tx) = build_test_context_with_receiver_cell(
  Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000, 150_0000_0000],
        vec![200_0000_0000, 312_0000_0000],
        Bytes::from(
            hex::decode("5500000010000000550000005500000041000000b69c542c0ee6c4b6d8350514d876ea7d8ef563e406253e959289457204447d2c4eb4e4a993073f5e76d244d2f93f7c108652e3295a9c8d72c12477e095026b9500").unwrap()),
            0,
    );
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_claim_with_receiver_input_signature_error() {
    let (mut context, tx) = build_test_context_with_receiver_cell(
  Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000, 150_0000_0000],
        vec![200_0000_0000, 312_0000_0000],
        Bytes::from(
            hex::decode("5500000010000000550000005500000041000000b69c542c0ee6c4b6d8350514d876").unwrap()),
            0,
    );
    let tx = context.complete_tx(tx);

    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(8).input_lock_script(script_cell_index)
    );
}

#[test]
fn test_claim_with_receiver_input_signature_empty() {
    let (mut context, tx) = build_test_context_with_receiver_cell(
  Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000, 150_0000_0000],
        vec![200_0000_0000, 312_0000_0000],
        Bytes::new(),
        0,
    );
    let tx = context.complete_tx(tx);

    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(8).input_lock_script(script_cell_index)
    );
}

#[test]
fn test_claim_with_receiver_input_capacity_error() {
    let (mut context, tx) = build_test_context_with_receiver_cell(
  Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000, 150_0000_0000],
        vec![210_0000_0000, 292_0000_0000],
        Bytes::new(),
        0,
    );
    let tx = context.complete_tx(tx);

    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(9).input_lock_script(script_cell_index)
    );
}

#[test]
fn test_claim_with_receiver_input_since_error() {
    let (mut context, tx) = build_test_context_with_receiver_cell(
  Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000, 150_0000_0000],
        vec![200_0000_0000, 312_0000_0000],
        Bytes::new(),
        100000,
    );
    let tx = context.complete_tx(tx);

    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(11).input_lock_script(script_cell_index)
    );
}

#[test]
fn test_claim_with_cheque_signature() {
    let (context, tx) = build_test_context_with_cheque_signature(
Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
  Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000, 150_0000_0000],
        vec![200_0000_0000, 312_0000_0000],
            0,
            false,
    );

    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_claim_with_cheque_error_signature() {
    let (context, tx) = build_test_context_with_cheque_signature(
Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
  Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000, 150_0000_0000],
        vec![200_0000_0000, 312_0000_0000],
            0,
            true,
    );

    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(10).input_lock_script(script_cell_index)
    );
}

#[test]
fn test_claim_with_cheque_signature_capacity_error() {
    let (context, tx) = build_test_context_with_cheque_signature(
Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
  Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000, 150_0000_0000],
        vec![200_0000_0000, 292_0000_0000],
            0,
            false,
    );

    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(9).input_lock_script(script_cell_index)
    );
}

#[test]
fn test_claim_with_cheque_signature_since_not_error() {
    let (context, tx) = build_test_context_with_cheque_signature(
Bytes::from(
            hex::decode("36c329ed630d6ce750712a477543672adab57f4c")
                .unwrap()),
  Bytes::from(
            hex::decode("f43cc005be4edf45c829363d54799ac4f7aff5a5")
                .unwrap()),
        vec![162_0000_0000, 200_0000_0000, 150_0000_0000],
        vec![200_0000_0000, 312_0000_0000],
            100000000,
            false,
    );

    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(11).input_lock_script(script_cell_index)
    );
}