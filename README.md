# TSS ECDSA CLI utility

[![Build Status](https://travis-ci.com/cryptochill/tss-ecdsa-cli.svg?branch=master)](https://travis-ci.com/cryptochill/tss-ecdsa-cli)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This project is an example usage of https://github.com/KZen-networks/multi-party-ecdsa library which is a Rust implementation of {t,n}-threshold ECDSA. 

Includes support for HD keys ([BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)). HD support based on https://github.com/trepca/multi-party-ecdsa/tree/hd-support.

## Setup

1.  Install [Rust](https://rustup.rs/) nightly ([Rocket](https://rocket.rs/v0.4/guide/getting-started/) requires the latest version of Rust nightly).

    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    rustup default nightly
    ``` 

2. Clone & build.

    ```sh
    git clone https://github.com/cryptochill/tss-ecdsa-cli.git 
    cd tss-ecdsa-cli
    cargo build --release
    ```

## Keygen

1. Run state manager:

    ```sh 
    ./target/release/tss_cli manager
    ```
   
    To run on different host/port adjust Rocket.toml or override using [env vars](https://api.rocket.rs/v0.4/rocket/config/index.html#environment-variables). 
    ```sh
    ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8008 ./target/release/tss_cli
    ```

2. Run keygen:

    ```sh
    # Syntax:
    # tss_cli keygen <keysfile> <params> (threshold/parties (t+1/n). E.g. 1/3 for 2 of 3) <manager_addr> (Optional. E.g. http://127.0.0.2:8002)
   
    # Run keygen for each party
    t=1 && n=3; for i in $(seq 1 $n)
    do
        echo "key gen for client $i out of $n"
        ./target/release/tss_cli keygen keys$i.store $t/$n &
        sleep 2
    done
    ```

## Get derived public key for path

Output will return X and Y coordinates of a public key at specified path.

```sh
# Syntax:
# tss_cli signer <keysfile> <path> address

./target/release/tss_cli signer keys1.store 0/1/2 address
# Output: {"path":"0/1/2","x":"973dba2e6c622d0d62626b5cc20e9561dd6123afca96d7b811f637900e68d99e","y":"7c1b2d91cdbfd6e9ceab48dc94aedfd021e314f4d90d18cbb8a4b40d543f85cd"}
```

## Sign message

Run as many signer parties as you configured when used keygen.

```sh
Syntax:
# tss_cli signer <keysfile> <path> sign <manager_addr> <params> (threshold/parties (t+1/n). E.g. 1/3 for 2 of 3) <message>

./target/release/tss_cli signer keys1.store 0/1/2 sign http://127.0.0.1:8001 1/2 SignMe
./target/release/tss_cli signer keys2.store 0/1/2 sign http://127.0.0.1:8001 1/2 SignMe

# If all is correct, last line of the output should be json string, something like this:
{ 
   "status":"signature_ready",
   "r":"20863a51eb7b0e0fb95480ca7c11edef79bd08e40199f91821df02982f8e5af1",
   "s":"ba8f2b6eff824796bf1812667642d9d65ec6d8dead09b7c2c157a6317947249",
   "recid":0,
   "x":"973dba2e6c622d0d62626b5cc20e9561dd6123afca96d7b811f637900e68d99e",
   "y":"7c1b2d91cdbfd6e9ceab48dc94aedfd021e314f4d90d18cbb8a4b40d543f85cd"
}
```

## Todo:

1. Make HD path optional.
2. Fix minor inconsistencies over required vs optional args, specifically manager_addr.

