package types

import (
	"testing"
)

func TestReadProofWithPublicInputs(t *testing.T) {
	ReadProofWithPublicInputs("../data/decode_block/proof_with_public_inputs.json")
}

func TestReadVerifierOnlyCircuitData(t *testing.T) {
	ReadVerifierOnlyCircuitData("../data/decode_block/verifier_only_circuit_data.json")
}
