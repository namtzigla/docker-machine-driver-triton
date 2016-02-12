package triton

import (
	"crypto"
	"github.com/yosida95/golang-sshkey"
	"io/ioutil"
)

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
