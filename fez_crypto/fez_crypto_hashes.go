package fez_crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// SHA256 {
type SHA256Hash struct {
	Bytes [32]byte
	Hex   string
}

func (self *SHA256Hash) Set(b []byte) {
	h := sha256.Sum256(b)
	self.Bytes = h
	self.Hex = hex.EncodeToString(h[:])
}

func (self *SHA256Hash) GenerateFingerprint(length int) (string, error) {
	if length <= 8 {
		return "error", errors.New("fez_lib/fez_crypto: Error: Fingerprint length must be at least 8.")
	}
	length = length / 2
	x := self.Hex[:length]
	y := self.Hex[(len(self.Hex) - length):]
	return x + y, nil
}

func (self *SHA256Hash) CompareFingerprints(second_fingerprint string, length int) (bool, error) {
	fp, err := self.GenerateFingerprint(length)
	if err != nil {
		return false, err
	}
	return (fp == second_fingerprint), nil
}

// }
