package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

const PkFileName = "proving.key"
const VkFileName = "verifying.key"
const VerifierContractFileName = "contracts/PlonkVerifier.sol"
const ProofFileName = "proof"
const PublicWitnessFileName = "public_witness"
const fpSize = 4 * 8

func main() {
	proofSystem := flag.String("proof-system", "plonk", "proof system to benchmark")
	profileCircuit := flag.Bool("profile", true, "profile the circuit")
	saveArtifacts := flag.Bool("save", true, "save circuit artifacts")

	flag.Parse()

	fmt.Printf("Running benchmark for circuit with proof system %s\n", *proofSystem)

	commonCircuitData := types.ReadCommonCircuitData("input" + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("input" + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("input" + "/verifier_only_circuit_data.json"))

	circuit := verifier.VerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	var p *profile.Profile
	if *profileCircuit {
		p = profile.Start()
	}

	var builder frontend.NewBuilder
	if *proofSystem == "plonk" {
		builder = scs.NewBuilder
	} else if *proofSystem == "groth16" {
		builder = r1cs.NewBuilder
	} else {
		fmt.Println("Please provide a valid proof system to benchmark, we only support plonk and groth16")
		os.Exit(1)
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	if *profileCircuit {
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}

	if *proofSystem == "plonk" {
		// pk, vk := performSetupForPlonk(r1cs)
		proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("input" + "/proof_with_public_inputs.json"))
		assignment := verifier.VerifierCircuit{
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("input" + "/verifier_only_circuit_data.json")),
		}
		readKeysFromFileAndProve(r1cs, assignment)
	} else if *proofSystem == "groth16" {
		groth16Proof(r1cs, false, *saveArtifacts)
	} else {
		panic("Please provide a valid proof system to benchmark, we only support plonk and groth16")
	}
}

func performSetupForPlonk(r1cs constraint.ConstraintSystem) {
	fmt.Println("Reading the real setup")

	fSRS, err := os.Open("srs_setup")
	if err != nil {
		panic(err)
	}
	var srs kzg.SRS = kzg.NewSRS(ecc.BN254)
	_, err = srs.ReadFrom(fSRS)
	fSRS.Close()
	if err != nil {
		panic(err)
	}

	fmt.Println("Generating pk, vk from the setup")

	var vk plonk.VerifyingKey
	var pk plonk.ProvingKey
	pk, vk, err = plonk.Setup(r1cs, srs)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Saving pk, vk, and verifier contract")

	fPK, _ := os.Create(PkFileName)
	pk.WriteTo(fPK)
	fPK.Close()

	fVK, _ := os.Create(VkFileName)
	vk.WriteTo(fVK)
	fVK.Close()

	fSolidity, _ := os.Create(VerifierContractFileName)
	if err = vk.ExportSolidity(fSolidity); err != nil {
		panic(err)
	}
}

func readKeysFromFileAndProve(r1cs constraint.ConstraintSystem, assignment verifier.VerifierCircuit) {
	var pk plonk.ProvingKey = plonk.NewProvingKey(ecc.BN254)
	if _, err := os.Stat(PkFileName); err == nil {
		fPK, err := os.Open(PkFileName)
		if err != nil {
			panic(err)
		}
		defer fPK.Close()
		if _, err := pk.ReadFrom(fPK); err != nil {
			fmt.Println("Failed to read pk from file", err)
		}
	} else {
		fmt.Println("proving.key does not exist")
		os.Exit(1)
	}

	var vk plonk.VerifyingKey = plonk.NewVerifyingKey(ecc.BN254)
	if _, err := os.Stat(VkFileName); err == nil {
		fVK, err := os.Open(VkFileName)
		if err != nil {
			panic(err)
		}
		defer fVK.Close()
		if _, err := vk.ReadFrom(fVK); err != nil {
			fmt.Println("Failed to read vk from file", err)
		}
	} else {
		fmt.Println("verifying.key does not exist")
		os.Exit(1)
	}

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())

	fmt.Println("Creating proof", time.Now())
	proof, err := plonk.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Verifying proof for sanity check", time.Now())
	publicWitness, _ := witness.Public()
	if err = plonk.Verify(proof, vk, publicWitness); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Saving proof for Solidity to a file called `proof`", time.Now())
	fProof, _ := os.Create("proof")
	if _, err = fProof.Write(proof.(*plonk_bn254.Proof).MarshalSolidity()); err != nil {
		panic(err)
	}
	fProof.Close()

	fmt.Println("Saving public witness for Solidity to a file called `public_witness`", time.Now())
	bPublicWitness, err := publicWitness.MarshalBinary()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// that's quite dirty...
	// first 4 bytes -> nbPublic
	// next 4 bytes -> nbSecret
	// next 4 bytes -> nb elements in the vector (== nbPublic + nbSecret)
	fPublicWitness, _ := os.Create("public_witness")
	if _, err = fPublicWitness.Write(bPublicWitness[12:]); err != nil {
		panic(err)
	}
	fPublicWitness.Close()
}

func groth16Proof(r1cs constraint.ConstraintSystem, dummy bool, saveArtifacts bool) {
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("input" + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("input" + "/verifier_only_circuit_data.json"))
	assignment := verifier.VerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	fmt.Println("Running circuit setup", time.Now())
	if dummy {
		fmt.Println("Using dummy setup")
		pk, err = groth16.DummySetup(r1cs)
	} else {
		fmt.Println("Using real setup")
		pk, vk, err = groth16.Setup(r1cs)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if saveArtifacts {
		fPK, _ := os.Create(PkFileName)
		pk.WriteTo(fPK)
		fPK.Close()

		if vk != nil {
			fVK, _ := os.Create(VkFileName)
			vk.WriteTo(fVK)
			fVK.Close()
		}

		fSolidity, _ := os.Create(VerifierContractFileName)
		err = vk.ExportSolidity(fSolidity)
	}

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	if saveArtifacts {
		fWitness, _ := os.Create("witness")
		witness.WriteTo(fWitness)
		fWitness.Close()
	}

	fmt.Println("Creating proof", time.Now())
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if saveArtifacts {
		fProof, _ := os.Create(ProofFileName)
		proof.WriteTo(fProof)
		fProof.Close()
	}

	if vk == nil {
		fmt.Println("vk is nil, means you're using dummy setup and we skip verification of proof")
		return
	}

	fmt.Println("Verifying proof", time.Now())
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var (
		a [2]*big.Int
		b [2][2]*big.Int
		c [2]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	println("a[0] is ", a[0].String())
	println("a[1] is ", a[1].String())

	println("b[0][0] is ", b[0][0].String())
	println("b[0][1] is ", b[0][1].String())
	println("b[1][0] is ", b[1][0].String())
	println("b[1][1] is ", b[1][1].String())

	println("c[0] is ", c[0].String())
	println("c[1] is ", c[1].String())
}
