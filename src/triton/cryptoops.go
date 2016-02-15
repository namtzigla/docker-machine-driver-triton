package triton

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/yosida95/golang-sshkey"
)

//
// Public key methods
//
func GetSshKey(path string) (sshkey.PublicKey, error) {
	// try to load ssh public key from path
	keyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return sshkey.UnmarshalPublicKey(string(keyData))

}

func GetSshKeyFingerprint(key sshkey.PublicKey) (string, error) {
	return sshkey.PrettyFingerprint(key, crypto.MD5)
}

func GetSshKeyId(path string) (string, error) {
	key, err := GetSshKey(path)
	if err != nil {
		return "", err
	}

	return GetSshKeyFingerprint(key)
}

// http://stackoverflow.com/questions/20655702/signing-and-decoding-with-rsa-sha-in-go
// loadPrivateKey loads an parses a PEM encoded private key file.
func LoadPublicKey(path string) (Unsigner, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}
	return parsePublicKey(data)
}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	return newUnsignerFromKey(rawkey)
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func LoadPrivateKey(path string, password string) (Signer, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePrivateKey(data, password)
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte, password string) (Signer, error) {
	var buf []byte
	block, _ := pem.Decode(pemBytes)

	if block == nil {
		return nil, errors.New("ssh: no key found")
	}
	// check if we have an ecrypted pem Block
	if x509.IsEncryptedPEMBlock(block) {
		if password == "" {
			fmt.Printf("Enter password:")
			fmt.Scanln(&password)

		}
		blk, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}

		buf = make([]byte, len(blk))
		copy(buf, blk)
	} else {
		buf = make([]byte, len(block.Bytes))
		copy(buf, block.Bytes)
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(buf)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
	SignToString(data []byte) (string, error)
}

// A Signer is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data []byte) ([]byte, error)
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}

func (r *rsaPrivateKey) SignToString(data []byte) (string, error) {
	if data, err := r.Sign(data); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(data), nil
	}
}

func (r *rsaPublicKey) Unsign(message []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return d, nil
	//return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}
