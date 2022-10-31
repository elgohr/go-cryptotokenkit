package cryptotokenkit_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/elgohr/go-cryptotokenkit/cryptotokenkit"
	"github.com/stretchr/testify/require"
	"math/big"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"testing"
)

const TestCertificateName = "TEST_CERTIFICATE"

func TestIdentities(t *testing.T) {
	keyBytes, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: TestCertificateName,
		},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &keyBytes.PublicKey, keyBytes)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	pfxBytes, err := pkcs12.Encode(rand.Reader, keyBytes, cert, []*x509.Certificate{}, pkcs12.DefaultPassword)
	require.NoError(t, err)

	require.NoError(t, cryptotokenkit.Import(pfxBytes, pkcs12.DefaultPassword))

	ids, err := cryptotokenkit.Identities()
	require.NoError(t, err)
	require.Greater(t, len(ids), 0)

	testCertificate := getTestCertificate(t, ids)
	require.NotNil(t, testCertificate)
	defer func() {
		require.NoError(t, testCertificate.Delete())
	}()

	t.Run("rsa encryption and decryption", func(t *testing.T) {
		certificate, err := testCertificate.Certificate()
		require.NoError(t, err)
		original := "PLAINTEXT"
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, certificate.PublicKey.(*rsa.PublicKey), []byte(original))
		require.NoError(t, err)
		require.NotEqual(t, original, ciphertext)
		plaintext, err := testCertificate.Decrypter().Decrypt(rand.Reader, ciphertext, nil)
		require.NoError(t, err)
		require.Equal(t, original, string(plaintext))
	})

	t.Run("rsa encryption and failing decryption", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)
		original := "PLAINTEXT"
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &otherKey.PublicKey, []byte(original))
		require.NoError(t, err)
		require.NotEqual(t, original, ciphertext)
		plaintext, err := testCertificate.Decrypter().Decrypt(rand.Reader, ciphertext, nil)
		require.EqualError(t, err, "could not decrypt: The operation couldn’t be completed. (OSStatus error -67673 - CSSM Exception: -2147415994 CSSMERR_CSP_INVALID_DATA)")
		require.Empty(t, string(plaintext))
	})

	t.Run("rsa signing", func(t *testing.T) {
		content := []byte("PLAINTEXT")
		hash := sha256.Sum256(content)
		signature, err := testCertificate.Signer().Sign(rand.Reader, hash[:], crypto.SHA256)
		require.NoError(t, err)
		certificate, err := testCertificate.Certificate()
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyPKCS1v15(certificate.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash[:], signature))
	})
}

func getTestCertificate(t *testing.T, ids []cryptotokenkit.Identity) cryptotokenkit.Identity {
	for _, id := range ids {
		cert, err := id.Certificate()
		require.NoError(t, err)
		if cert.Subject.CommonName == TestCertificateName {
			return id
		}
	}
	return nil
}
