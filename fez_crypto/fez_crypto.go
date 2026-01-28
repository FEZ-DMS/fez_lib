package fez_crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

// AES (only uses GCM, no CBC) {
type AESKey struct {
	Key       []byte
	gcm       cipher.AEAD
	noncesize int
}

func (self *AESKey) Reload() error {
	block, err := aes.NewCipher(self.Key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	self.gcm = gcm
	self.noncesize = gcm.NonceSize()
	return nil
}

func (self *AESKey) Set(key []byte) error {
	self.Key = key
	return self.Reload()
}

func (self *AESKey) Generate() error {
	buffer := make([]byte, 32)
	_, err := rand.Read(buffer)
	if err != nil {
		return err
	}
	self.Set(buffer)
	return nil
}

func (self *AESKey) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, self.noncesize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return self.gcm.Seal(nonce, nonce, plain, nil), nil
}

func (self *AESKey) Decrypt(encrypted []byte) ([]byte, error) {
	if len(encrypted) < self.noncesize {
		return nil, errors.New("lib_fedm_std: AESKey.Decrypt: Invalid ciphertext length!")
	}
	nonce := encrypted[:self.noncesize]
	enc := encrypted[self.noncesize:]
	return self.gcm.Open(nil, nonce, enc, nil)
}

func AESQuickEncrypt(plain []byte, key []byte) ([]byte, error) {
	keyobj := AESKey{Key: key}
	err := keyobj.Reload()
	if err != nil {
		return nil, err
	}
	return keyobj.Encrypt(plain)
}

func AESQuickDecrypt(encrypted []byte, key []byte) ([]byte, error) {
	keyobj := AESKey{Key: key}
	err := keyobj.Reload()
	if err != nil {
		return nil, err
	}
	return keyobj.Decrypt(encrypted)
}

// }

// RSA {
type RSAPrivateKey struct {
	_key rsa.PrivateKey
}

func (self *RSAPrivateKey) Generate(bit_length int) error {
	prv, err := rsa.GenerateKey(rand.Reader, bit_length)
	if err != nil {
		return err
	}
	self._key = *prv
	return nil
}

func (self *RSAPrivateKey) ImportFromPEM(pem_bytes []byte) error {
	pemBlock, _ := pem.Decode(pem_bytes)
	marshalled := pemBlock.Bytes
	prv, err := x509.ParsePKCS1PrivateKey(marshalled)
	if err != nil {
		return err
	}
	self._key = *prv
	return nil
}

func (self *RSAPrivateKey) ExportToPEM() []byte {
	pemb := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(&self._key),
		},
	)
	return pemb
}

func (self *RSAPrivateKey) LoadFromPEMFile(pem_path string) error {
	pemb, err := os.ReadFile(pem_path)
	if err != nil {
		return err
	}
	return self.ImportFromPEM(pemb)
}

func (self *RSAPrivateKey) SaveAsPEMFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	pemb := self.ExportToPEM()
	_, err = file.Write(pemb)
	if err != nil {
		return err
	}
	return nil
}

func (self *RSAPrivateKey) GetPublicKey() RSAPublicKey {
	return RSAPublicKey{_key: self._key.PublicKey}
}

func (self *RSAPrivateKey) Decrypt(encrypted []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), nil, &self._key, encrypted, nil)
}

func (self *RSAPrivateKey) Sign(hash SHA256Hash) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, &self._key, crypto.SHA256, hash.Bytes[:])
}

type RSAPublicKey struct {
	_key rsa.PublicKey
}

func (self *RSAPublicKey) ImportFromPEM(pem_bytes []byte) error {
	pemBlock, _ := pem.Decode(pem_bytes)
	marshalled := pemBlock.Bytes
	pub, err := x509.ParsePKCS1PublicKey(marshalled)
	if err != nil {
		return err
	}
	self._key = *pub
	return nil
}

func (self *RSAPublicKey) ExportToPEM() []byte {
	pemb := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&self._key),
		},
	)
	return pemb
}

func (self *RSAPublicKey) LoadFromPEMFile(pem_path string) error {
	pemb, err := os.ReadFile(pem_path)
	if err != nil {
		return err
	}
	return self.ImportFromPEM(pemb)
}

func (self *RSAPublicKey) SaveAsPEMFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	pemb := self.ExportToPEM()
	_, err = file.Write(pemb)
	if err != nil {
		return err
	}
	return nil
}

func (self *RSAPublicKey) Encrypt(b []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, &self._key, b, nil)
}

func (self *RSAPublicKey) VerifySignature(hash SHA256Hash, signature []byte) (bool, error) {
	err := rsa.VerifyPKCS1v15(&self._key, crypto.SHA256, hash.Bytes[:], signature)
	return err == nil, err
}

// }
