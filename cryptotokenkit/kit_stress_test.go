package cryptotokenkit_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"testing"

	"github.com/elgohr/go-cryptotokenkit/cryptotokenkit"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
)

func FuzzSign(f *testing.F) {

	commonName := "FUZZ_TEST_IDENTITY_" + uuid.New().String()
	pfxBytes := createCertificate(f, commonName)

	require.NoError(f, cryptotokenkit.Import(pfxBytes, pkcs12.DefaultPassword))

	ids, err := cryptotokenkit.Identities()
	require.NoError(f, err)
	require.Greater(f, len(ids), 0)

	testCertificate := getTestCertificate(f, ids, commonName)
	defer func() {
		require.NotNil(f, testCertificate)
		require.NoError(f, testCertificate.Delete())
	}()

	certificate, err := testCertificate.Certificate()
	require.NoError(f, err)

	f.Add([]byte("input"))
	f.Fuzz(func(t *testing.T, input []byte) {
		hash := sha512.Sum512(input)
		signature, err := testCertificate.Signer().Sign(rand.Reader, hash[:], crypto.SHA512)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyPKCS1v15(certificate.PublicKey.(*rsa.PublicKey), crypto.SHA512, hash[:], signature))
	})
}
