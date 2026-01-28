package fez_hash // import github.com/fez4devs/fez_lib/fez_hash

// Copyleft 🄯 2026 tomteb
// This module is.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/cespare/xxhash"
)

// CAVE! xxHash64 is a non-cryptographical hashing algorithm, and should be used as such. It's only used as a checksum in FEZ.
// For cryptographical purposes use SHA256.
// xxHash64 {
type XXH64Hash struct {
	Int   uint64
	Bytes []byte
	Hex   string
}

func (self *XXH64Hash) Set(b []byte) {
	num := xxhash.Sum64(b)
	hashbytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(hashbytes, num)
	self.Int = num
	self.Bytes = hashbytes
	self.Hex = hex.EncodeToString(hashbytes)
}

func (self *XXH64Hash) GenerateFingerprint(length int) (string, error) {
	if length <= 8 {
		return "error", errors.New("fez_lib/fez_crypto: Error: Fingerprint length must be at least 8.")
	}
	length = length / 2
	x := self.Hex[:length]
	y := self.Hex[(len(self.Hex) - length):]
	return x + y, nil
}

func (self *XXH64Hash) CompareFingerprints(second_fingerprint string, length int) (bool, error) {
	fp, err := self.GenerateFingerprint(length)
	if err != nil {
		return false, err
	}
	return (fp == second_fingerprint), nil
}

// }

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
