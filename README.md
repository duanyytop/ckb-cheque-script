# ckb-cheque-script

[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/duanyytop/ckb-cheque-script/blob/main/COPYING)
[![Github Actions CI](https://github.com/duanyytop/ckb-cheque-script/workflows/CI/badge.svg?branch=main)](https://github.com/duanyytop/ckb-cheque-script/actions)

The lock script of cheque cell on Nervos CKB using [Capsule](https://github.com/nervosnetwork/capsule)

### Pre-requirement

- [capsule](https://github.com/nervosnetwork/capsule) >= 0.4.3
- [ckb-cli](https://github.com/nervosnetwork/ckb-cli) >= 0.35.0
- [secp256k1_blake2b_sighash_all_dual](https://github.com/nervosnetwork/ckb-miscellaneous-scripts/blob/master/c/secp256k1_blake2b_sighash_all_dual.c) which supports loaded as a shared library.

> Note: Capsule uses docker to build contracts and run tests. https://docs.docker.com/get-docker/
> and docker and ckb-cli must be accessible in the PATH in order for them to be used by Capsule.

### Getting Started

- Init submodules:

```
git submodule init && git submodule update -r --init
```

- Build the shared binary `secp256k1_blake2b_sighash_all_dual`:

```
cd ckb-miscellaneous-scripts && git submodule init && git submodule update

make all-via-docker
```

- Build contracts:

```sh
# back to repo root directory
cd .. 
capsule build
```

- Run tests

```sh
capsule test
```

### Deployment

#### 1. Update the deployment configurations

Open `deployment.toml` :

- cells describes which cells to be deployed.

  - `name`: Define the reference name used in the deployment configuration.
  - `enable_type_id` : If it is set to true means create a type_id for the cell.
  - `location` : Define the script binary path.
  - `dep_groups` describes which dep_groups to be created. Dep Group is a cell which bundles several cells as its members. When a dep group cell is used in cell_deps, it has the same effect as adding all its members into cell_deps. In our case, we don’t need dep_groups.

- `lock` describes the lock field of the new deployed cells.It is recommended to set lock to the address(an address that you can unlock) of deployer in the dev chain and in the testnet, which is easier to update the script.

#### 2. Build release version of the script

The release version of script doesn’t include debug symbols which makes the size smaller.

```sh
capsule build --release
```

#### 3. Deploy the script

```sh
capsule deploy --address <ckt1....> --fee 0.001
```

If the `ckb-cli` has been installed and `dev-chain` RPC is connectable, you will see the deployment plan:

new_occupied_capacity and total_occupied_capacity refer how much CKB to store cells and data.
txs_fee_capacity refers how much CKB to pay the transaction fee.

```
Deployment plan:
---
migrated_capacity: 0.0 (CKB)
new_occupied_capacity: 129352.0 (CKB)
txs_fee_capacity: 0.003 (CKB)
total_occupied_capacity: 129352.0 (CKB)
recipe:
  cells:
    - name: ckb-cheque-script
      index: 0
      tx_hash: "0x56353f036c04b153eaa6ef31a8637fb673b255fa62becf1c253b00aace643ae1"
      occupied_capacity: 58414.0 (CKB)
      data_hash: "0x617bfa9727d99fbc094a485d14842128f4224260b62278412f44cf2951e512ba"
      type_id: "0x17340bcdef33d40b0ddaeb1a2f5152f579c7e08088977dfb600abf44049ff173"
    - name: secp256k1_blake2b_sighash_all_dual
      index: 0
      tx_hash: "0xf15d81696d1e2fd9e1e128ca95fb8ee3263e04961323ca1e74b8809cb4529828"
      occupied_capacity: 70765.0 (CKB)
      data_hash: "0xa01d57f854cc965cd8850c06691d666f933d8389d693266273bd6c47753cf447"
      type_id: ~
  dep_groups:
    - name: dep_group
      tx_hash: "0x2ebd890517f1a54f5f1a0084bd2111203266d6c321b190232f3ceaa322ef7fd5"
      index: 0
      occupied_capacity: 173.0 (CKB)
```

#### 4. Type yes or y and input the password to unlock the account.

```
(1/3) Sending tx 56353f036c04b153eaa6ef31a8637fb673b255fa62becf1c253b00aace643ae1
(2/3) Sending tx f15d81696d1e2fd9e1e128ca95fb8ee3263e04961323ca1e74b8809cb4529828
(3/3) Sending tx 2ebd890517f1a54f5f1a0084bd2111203266d6c321b190232f3ceaa322ef7fd5
Deployment complete
```

Now the cheque script has been deployed, you can refer to this script by using `tx_hash: 2ebd890517f1a54f5f1a0084bd2111203266d6c321b190232f3ceaa322ef7fd5 index: 0` as `out_point`(your tx_hash should be another value).
