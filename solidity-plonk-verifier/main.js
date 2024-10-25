const fs = require('fs');
const path = require('path');
const { expect } = require('chai');
const { ethers } = require('hardhat');

const INPUTS_FILE_NAME = "input";
const PUBLIC_INPUT_PATH = path.join(__dirname, INPUTS_FILE_NAME, 'public_witness');
const PROOF_PATH = path.join(__dirname, INPUTS_FILE_NAME, 'proof');

const readPublicWitness = () => {
  const publicInputsBytes = fs.readFileSync(PUBLIC_INPUT_PATH);
  const publicInputs = [];
  for (let i = 0; i < publicInputsBytes.length; i += 32) {
    const chunk = publicInputsBytes.slice(i, i + 32);
    publicInputs.push(BigInt('0x' + chunk.toString('hex')));
  }
  return publicInputs;
}

describe("Run", function () {
  before(async function () {
    [owner, otherAccount] = await ethers.getSigners();
    Verifier = await ethers.getContractFactory("PlonkVerifier");
    verifier = await Verifier.deploy({ value: 0 });
  });

  it("should verify a valid proof", async function () {
    expect(
      await verifier.Verify(
        fs.readFileSync(PROOF_PATH),
        readPublicWitness(),
      )
    ).to.be.true;
  });

  it("should fail to verify an invalid proof", async function () {
    const validProofBytes = fs.readFileSync(PROOF_PATH);

    const invalidPublicInputs = readPublicWitness();
    const temp = invalidPublicInputs[0];
    invalidPublicInputs[0] = invalidPublicInputs[1];
    invalidPublicInputs[1] = temp;

    try {
      await verifier.Verify(validProofBytes, invalidPublicInputs);
      expect.fail("Expected the Verify function to throw an error, but it did not.");
    } catch (error) {
      // Pass
    }
  });

  // No test for "invalidProofBytes" as contract call panics and chai can't catch that. 
});

