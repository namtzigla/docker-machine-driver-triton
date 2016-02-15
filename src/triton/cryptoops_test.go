package triton

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestGetSshKeyFingerprint(t *testing.T) {
	ssh_public_key_path := "../../fixup/id_rsa.pub"
	expected_fingerprint := "22:62:da:a0:33:12:70:19:db:ac:e1:66:9e:27:20:42"

	_, err := os.Stat(ssh_public_key_path)

	assert.Nil(t, err, "public key file does not exist")

	ret, err := GetSshKey(ssh_public_key_path)

	assert.Nil(t, err, "invalid public key")

	fingerprint, _ := GetSshKeyFingerprint(ret)
	assert.Equal(t, fingerprint, expected_fingerprint, "Resulted fingerprints don't match")

}

func TestGetSshKeyFingerprintWithPasswordProtectedCert(t *testing.T) {
	ssh_public_key_path := "../../fixup/pass_id_rsa.pub"
	expected_fingerprint := "25:ac:dd:f0:b2:f8:f3:9b:df:69:d7:32:5f:87:6b:e2"

	_, err := os.Stat(ssh_public_key_path)

	assert.Nil(t, err, "public key file does not exist")

	ret, err := GetSshKey(ssh_public_key_path)

	assert.Nil(t, err, "invalid public key")

	fingerprint, _ := GetSshKeyFingerprint(ret)
	assert.Equal(t, fingerprint, expected_fingerprint, "Resulted fingerprints don't match")

}

func TestEncryptMessage(t *testing.T) {
	in_data := "Mon, 15 Feb 2016 18:18:13 GMT"
	out_data := "B0qFg0BQzLALM5uVxo01bZ4NcZEc4IfWSrAtuC/5cQiYDSl/9HbhXcwpC3ylToW5d9urs8oSTSf7kAI/oqYTzy+7cFzdOs1qiwNdiz5noyQkuW9kxe3Yi1H2qolzSZj5ila1eqnDzE+sUORNl/EuO8kxMwGSs6TCMYQvV6tuo4ecnhd4M5rrYgjpZSvacQ+Ng+zgv5FYVtLs8EbyL9A/80Cc9dmDsCd9EKTOmCIgNFSQFx3K8igv8BGWpzafvlakmA6TcoJ+QdGtlslxw1wwdhP61BEUr9h4MtFj+EfO8C7LF00/9tbAUN71a7XEY6pu8cKuX1TBAppMRZjuQ9b0Fg=="
	ssh_private_key_path := "../../fixup/id_rsa"

	signer, err := LoadPrivateKey(ssh_private_key_path, "")

	assert.Nil(t, err, "Can't load private key")

	data, err := signer.SignToString([]byte(in_data))

	assert.Nil(t, err, "Error on signing the message")

	assert.Equal(t, out_data, data, "Result don't match!")
}

func TestEncryptMessageWithPasswordProtectedCert(t *testing.T) {
	in_data := "Mon, 15 Feb 2016 18:18:13 GMT"
	out_data := "OO+K8/SyEm6DYdTJUTVZWnlyZHhjqVwWQJ/qQl9lm4wmZ/qciAzGVRQSHLCj8CJbeNDoONDQV9SU6fb8hX8HBtK6RkCt0rkWy4qOJZP85hgEviiD6tmr5PLlsLM+bfJ2CeLe3gp832lbTOYI/BWIUyCA/vMYYkGFGwI+oQaDMlkU2DIDy//2A8Dx/zh210j3luCqFgEFL0RHcf5dgPUdFC8i9T9lmxkAdlHN8pX3/aOXHWh86fbPw8UZtEbZKrXaPnX1rs2lFv0Ijo3/Z1OMvrMF/LbdQ+ymrfij/Uai6o0/UP/w6Yg29P9v87YDnOWfFhN3sinP+KSE3mcKkYTNwA=="
	ssh_private_key_path := "../../fixup/pass_id_rsa"

	signer, err := LoadPrivateKey(ssh_private_key_path, "testing")

	assert.Nil(t, err, "Can't load private key")

	data, err := signer.SignToString([]byte(in_data))

	assert.Nil(t, err, "Error on signing the message")

	assert.Equal(t, out_data, data, "Result don't match!")
}
