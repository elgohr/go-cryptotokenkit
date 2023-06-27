package cryptotokenkit_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/elgohr/go-cryptotokenkit/cryptotokenkit"
	"github.com/stretchr/testify/require"
	"math/big"
	"software.sslmate.com/src/go-pkcs12"
	"testing"
)

func FuzzSign(f *testing.F) {
	keyBytes, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(f, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "STRESS_TEST_CERTIFICATE",
		},
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &keyBytes.PublicKey, keyBytes)
	require.NoError(f, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(f, err)

	pfxBytes, err := pkcs12.Encode(rand.Reader, keyBytes, cert, []*x509.Certificate{}, pkcs12.DefaultPassword)
	require.NoError(f, err)

	require.NoError(f, cryptotokenkit.Import(pfxBytes, pkcs12.DefaultPassword))

	ids, err := cryptotokenkit.Identities()
	require.NoError(f, err)
	require.Greater(f, len(ids), 0)

	testCertificate := getTestCertificate(f, ids, "STRESS_TEST_CERTIFICATE")
	require.NotNil(f, cert)
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
