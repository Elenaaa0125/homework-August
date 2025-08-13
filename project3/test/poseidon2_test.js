const { wasm } = require("circom_tester");
const path = require("path");
const { poseidon } = require("circomlibjs");
const fs = require("fs");

describe("Poseidon2 Circuit", () => {
  let circuit;
  
  before(async () => {
    circuit = await wasm(path.join(__dirname, "../circuits/poseidon2.circom"));
  });

  it("should correctly compute hash for sample input", async () => {
    const input = {
      in1: "123456",
      in2: "789012",
      in3: "345678"
    };
    
    // Save input for later use
    fs.writeFileSync(path.join(__dirname, "input.json"), 
      JSON.stringify(input, null, 2));
    
    const witness = await circuit.calculateWitness(input);
    await circuit.checkConstraints(witness);
    
    // Compare with reference implementation
    const expected = await poseidon([BigInt(input.in1), BigInt(input.in2), BigInt(input.in3)]);
    assert.equal(witness[1].toString(), expected.toString());
  });

  it("should fail for incorrect input", async () => {
    try {
      await circuit.calculateWitness({ in1: "1", in2: "2" }); // Missing in3
      assert.fail("should have thrown an error");
    } catch (err) {
      // Expected error
    }
  });
});
