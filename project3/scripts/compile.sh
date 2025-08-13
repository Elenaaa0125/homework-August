#!/bin/bash

# Create build directory if it doesn't exist
mkdir -p build

echo "Compiling circuit..."
circom circuits/poseidon2.circom --r1cs --wasm --sym -o build

echo "Generating witness..."
node build/poseidon2_js/generate_witness.js build/poseidon2_js/poseidon2.wasm test/input.json build/witness.wtns

echo "Getting circuit info..."
snarkjs info -r build/poseidon2.r1cs

echo "Done!"
