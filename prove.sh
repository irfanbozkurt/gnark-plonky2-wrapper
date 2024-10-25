#!/bin/sh

cd gnark-plonky2-verifier
go install
go run main.go
cd ..
