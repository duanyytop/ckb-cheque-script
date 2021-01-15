use super::*;
use ckb_standalone_debugger::transaction::{
    MockCellDep, MockInfo, MockInput, MockTransaction, ReprMockTransaction,
};
use ckb_testtool::context::Context;
use ckb_tool::ckb_types::{
    core::{TransactionView, DepType},
};

use ckb_x64_simulator::RunningSetup;
use serde_json::to_string_pretty;
use std::fs;
use std::path::PathBuf;

#[allow(dead_code)]
fn create_test_folder(name: &str) -> PathBuf {
    let mut path = TX_FOLDER.clone();
    path.push(&name);
    fs::create_dir_all(&path).expect("create folder");
    path
}

#[allow(dead_code)]
fn build_mock_transaction(tx: &TransactionView, context: &Context) -> MockTransaction {
    let mock_inputs = tx
        .inputs()
        .into_iter()
        .map(|input| {
            let (output, data) = context
                .get_cell(&input.previous_output())
                .expect("get cell");
            MockInput {
                input,
                output,
                data,
                header: None,
            }
        })
        .collect();
    let mock_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|cell_dep| {
            if cell_dep.dep_type() == DepType::DepGroup.into() {
                panic!("Implement dep group support later!");
            }
            let (output, data) = context.get_cell(&cell_dep.out_point()).expect("get cell");
            MockCellDep {
                cell_dep,
                output,
                data,
                header: None,
            }
        })
        .collect();
    let mock_info = MockInfo {
        inputs: mock_inputs,
        cell_deps: mock_cell_deps,
        header_deps: vec![],
    };
    MockTransaction {
        mock_info,
        tx: tx.data(),
    }
}

#[allow(dead_code)]
pub fn write_native_setup(
    test_name: &str,
    binary_name: &str,
    tx: &TransactionView,
    context: &Context,
    setup: &RunningSetup,
) {
    let folder = create_test_folder(test_name);
    let mock_tx = build_mock_transaction(&tx, &context);
    let repr_tx: ReprMockTransaction = mock_tx.into();
    let tx_json = to_string_pretty(&repr_tx).expect("serialize to json");
    fs::write(folder.join("tx.json"), tx_json).expect("write tx to local file");
    let setup_json = to_string_pretty(setup).expect("serialize to json");
    fs::write(folder.join("setup.json"), setup_json).expect("write setup to local file");
    fs::write(
        folder.join("cmd"),
        format!(
            "CKB_TX_FILE=\"{}\" CKB_RUNNING_SETUP=\"{}\" \"{}\"",
            folder.join("tx.json").to_str().expect("utf8"),
            folder.join("setup.json").to_str().expect("utf8"),
            Loader::default().path(binary_name).to_str().expect("utf8")
        ),
    )
    .expect("write cmd to local file");
}
