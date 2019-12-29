# TSS ECDSA CLI utility

[![Build Status](https://travis-ci.com/cryptochill/tss-ecdsa-cli.svg?branch=master)](https://travis-ci.com/cryptochill/tss-ecdsa-cli)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This project is an example usage of https://github.com/KZen-networks/multi-party-ecdsa library which is a Rust implementation of {t,n}-threshold ECDSA. 

Includes support for HD keys ([BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)). HD support based on https://github.com/trepca/multi-party-ecdsa/tree/hd-support.

## Setup

1.  Install [Rust](https://rustup.rs/) nightly.

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
    # tss_cli keygen <keysfile> <params> (threshold/parties (t+1/n). E.g. 1/3 for 2 of 3)
   
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
# Output: {"path":"0/1/2","x":"...","y":"..."}
```

Sign
----

Todo

