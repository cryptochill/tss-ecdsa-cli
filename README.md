# TSS ECDSA/EdDSA CLI Utility

[![Build Status](https://travis-ci.com/cryptochill/tss-ecdsa-cli.svg?branch=master)](https://travis-ci.com/cryptochill/tss-ecdsa-cli)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This project is an example usage of https://github.com/KZen-networks/multi-party-ecdsa library which is a Rust implementation of {t,n}-threshold ECDSA.

It also supports EdDSA, based on the examples of https://github.com/HRezaei/multi-party-eddsa. 

Includes support for HD keys ([BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)). HD support based on https://github.com/trepca/multi-party-ecdsa/tree/hd-support.

## Setup

1.  Install [Rust](https://rustup.rs/).

    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ``` 

2. Clone & build.

    ```sh
    git clone https://github.com/cryptochill/tss-ecdsa-cli.git 
    cd tss-ecdsa-cli
    cargo build --release
    ```

## Keygen

1. Run state manager which is managing the communication between parties:

    ```sh 
    ./target/release/tss_cli manager
    ```
   
    To run on different host/port adjust Rocket.toml or override using [env vars](https://api.rocket.rs/v0.4/rocket/config/index.html#environment-variables). 
    ```sh
    ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8008 ./target/release/tss_cli manager
    ```

2. Run keygen:

    ```sh
    USAGE:
        tss_cli keygen [OPTIONS] <keysfile> <params>

    OPTIONS:
        -a, --addr <manager_addr>    URL to manager. E.g. --addr http://127.0.0.2:8002
        -c, --curve <curve name> Either of ecdsa (default) or eddsa. E.g. -curve eddsa
    
    ARGS:
        <keysfile>    Target keys file
        <params>      Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema.

   
    # Run keygen for each party
    t=1 && n=3; for i in $(seq 1 $n)
    do
        echo "key gen for client $i out of $n"
        ./target/release/tss_cli keygen keys_ecdsa_$i.store $t/$n -cecdsa &
        sleep 2
    done
    ```

## Get derived public key for path

Output will return X and Y coordinates of a public key at specified path.

```sh
USAGE:
    tss_cli pubkey [OPTIONS] <keysfile>

OPTIONS:
    -p, --path <path>    Derivation path
    -c, --curve <curve name> Either of ecdsa (default) or eddsa. E.g. -curve eddsa

ARGS:
    <keysfile>    Keys file

./target/release/tss_cli pubkey keys_ecdsa_1.store
# Output: {"path":"","x":"20d6d63f5baa237c747c33dd85170e186d31fa2948b3bb4615e7d08045f05614","y":"6b4ae2e5a65f750f911e92f365f8f4733949f4681efb9ebfa8d9d8fec258e96"}

./target/release/tss_cli pubkey keys_eddsa_1.store -p 0/1/2 -c eddsa
# Output: {"path":"0/1/2","x":"973dba2e6c622d0d62626b5cc20e9561dd6123afca96d7b811f637900e68d99e","y":"7c1b2d91cdbfd6e9ceab48dc94aedfd021e314f4d90d18cbb8a4b40d543f85cd"}
```

## Sign message

Run state manager and run as many signer parties as you configured when used keygen.

```sh
USAGE:
    tss_cli sign [OPTIONS] <keysfile> <params> <message>

OPTIONS:
    -a, --addr <manager_addr>    URL to manager
    -p, --path <path>            Derivation path
    -c, --curve <curve name> Either of ecdsa (default) or eddsa. E.g. -curve eddsa

ARGS:
    <keysfile>    Keys file
    <params>      Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema.
    <message>     Message to sign in hex format


./target/release/tss_cli sign keys_ecdsa_1.store -p 0/1/2 -a http://127.0.0.1:8001 1/2 SignMe -cecdsa
./target/release/tss_cli sign keys_ecdsa_2.store -p 0/1/2 -a http://127.0.0.1:8001 1/2 SignMe -cecdsa

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
