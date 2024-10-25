[gnark-plonky2-verifier](gnark-plonky2-verifier/) 

Accepts the output of a wrapped plonky2 circuit as input, and outputs a plonk proof produced by gnark. 

Place the following in [input](gnark-plonky2-verifier/input/) folder:
- `common_circuit_data.json`
- `proof_with_public_inputs.json`
- `verifier_only_circuit_data.json`


```bash
go install
go run main.go # Will output the inputs of solidity-plonk-verifier
```

<br>


This tool is also used to extract the verifier contract. Enabling `performSetupForPlonk` function in [main.go](gnark-plonky2-verifier/main.go) will download the MPC trusted setup from aztec-ignition and output the Solidity contract containing the verifying key. 

<br>



[solidity-plonk-verifier](solidity-plonk-verifier/)

Accpets the output of gnark-plonky2-verifier as input, deploys the PlonkVerifier contract, and outputs a boolean for successful on-chain verification. 

- Place the verifying contract in [contracts](solidity-plonk-verifier/contracts/) folder. 
- Place the following in [input](solidity-plonk-verifier/input/) folder: 
	- `proof` 
	- `public_witness`


```bash
npm i
npm run verify # Will deploy the verification contract and call Verify
```
