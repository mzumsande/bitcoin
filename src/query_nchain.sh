#!/bin/bash

# Number of inputs per blcok statistics
prefix="-testnet"
for ((height=5000; height<=2570000; height+=5000)); do
    hash=$(./bitcoin-cli $prefix getblockhash $height)
    block=$(./bitcoin-cli $prefix getblock $hash)
    nTx=$(echo $block | jq '.nTx')
    nChainTx=$(echo $block | jq '.nChainTx')
    # while read -r i; do
    #     stripped=$(echo "$i" | tr -d '"')
    #     tx=$(./bitcoin-cli getrawtransaction $stripped 1)
    #     #echo $tx
    #     len=$(echo $tx | jq '.vin | length')
    #     ((sum_inputs+=$len))
    # done < <(echo $block | jq '.tx | .[]')
    echo $height $nChainTx $nTx
done
