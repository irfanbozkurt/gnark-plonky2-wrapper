[gnark-plonky2-verifier](gnark-plonky2-verifier/) 

Accepts the output of a wrapped plonky2 circuit as input. Place the following in [input](gnark-plonky2-verifier/input/) file:
- `common_circuit_data.json`
- `proof_with_public_inputs.json`
- `verifier_only_circuit_data.json`


```bash
go install
go run main.go # Will output the inputs of solidity-plonk-verifier
```

<br>




[solidity-plonk-verifier](solidity-plonk-verifier/)

Accpets the output of gnark-plonky2-verifier as input. Place the following in [input](solidity-plonk-verifier/input/) file: 
- `proof` 
- `public_witness`

```bash
npm i
npm run verify # Will deploy the verification contract and call Verify
```
