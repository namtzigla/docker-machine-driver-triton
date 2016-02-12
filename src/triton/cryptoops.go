package triton

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/yosida95/golang-sshkey"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
)

func MakeSSHKeyPair(pubKeyPath, privateKeyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	// generate and write private key as PEM
	privateKeyFile, err := os.Create(privateKeyPath)
	defer privateKeyFile.Close()
	if err != nil {
		return err
	}
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(pubKeyPath, ssh.MarshalAuthorizedKey(pub), 0655)
}

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
