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
capsule build
```

- Run tests

```sh
capsule test
```
