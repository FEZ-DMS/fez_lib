package fez_files

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/cespare/xxhash"
)

// very quick but NOT CRYPTOGRAPHICAL! should only be used for checksums and was therefore taken into fez_files.
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
