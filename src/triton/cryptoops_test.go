package triton

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestGetSshKeyIdSignature(t *testing.T) {
	ssh_public_key_path := "../../fixup/id_rsa.pub"
	expected_fingerprint := "22:62:da:a0:33:12:70:19:db:ac:e1:66:9e:27:20:42"

	t.Log("testing GetSshKey")
	if _, err := os.Stat(ssh_public_key_path); err != nil {
		t.Logf("%+v\n", err)
		t.Skip("Can't be tested b/c the file can't be found!")
		return
	}
	ret, err := GetSshKey(ssh_public_key_path)
	if err != nil {
		t.Logf("Error returned %+v\n", err)
		t.Fail()
	}

	fingerprint, _ := GetSshKeyFingerprint(ret)
	assert.Equal(t, fingerprint, expected_fingerprint, "Resulted fingerprints don't match")

}
