package cryptotokenkit_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/elgohr/go-cryptotokenkit/cryptotokenkit"
	"github.com/stretchr/testify/require"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"testing"
	"time"
)

const (
	TestCertificateName1 = "TEST_CERTIFICATE_1"
	TestCertificateName2 = "TEST_CERTIFICATE_2"
)

func TestIdentities(t *testing.T) {
	pfxBytes := createCertificate(t, TestCertificateName1)

	require.NoError(t, cryptotokenkit.Import(pfxBytes, pkcs12.DefaultPassword))

	ids, err := cryptotokenkit.Identities()
	require.NoError(t, err)
	require.Greater(t, len(ids), 0)

	testCertificate := getTestCertificate(t, ids, TestCertificateName1)
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

	t.Run("tls connection pkcs15", func(t *testing.T) {
		tlsCert, err := testCertificate.Certificate()
		require.NoError(t, err)
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		}))
		ts.TLS = &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate:                  [][]byte{tlsCert.Raw},
				PrivateKey:                   testCertificate.PrivateKey(),
				SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.PKCS1WithSHA1},
			}},
		}
		ts.StartTLS()
		defer ts.Close()

		certPool := x509.NewCertPool()
		certPool.AddCert(tlsCert)
		client := http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				MaxVersion: tls.VersionTLS12, // for using small key sizes in tests
			},
		}}

		res, err := client.Get(ts.URL)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		require.Equal(t, http.StatusAccepted, res.StatusCode)
	})

	t.Run("tls connection pss", func(t *testing.T) {
		tlsCert, err := testCertificate.Certificate()
		require.NoError(t, err)
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		}))
		ts.TLS = &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{tlsCert.Raw},
				PrivateKey:  testCertificate.PrivateKey(),
			}},
		}
		ts.StartTLS()
		defer ts.Close()

		certPool := x509.NewCertPool()
		certPool.AddCert(tlsCert)
		client := http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				MinVersion: tls.VersionTLS13,
			},
		}}

		res, err := client.Get(ts.URL)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		require.Equal(t, http.StatusAccepted, res.StatusCode)
	})
}

func TestMacIdentity_Equal(t *testing.T) {
	pfxBytes := createCertificate(t, TestCertificateName1)
	require.NoError(t, cryptotokenkit.Import(pfxBytes, pkcs12.DefaultPassword))

	pfxBytes = createCertificate(t, TestCertificateName2)
	require.NoError(t, cryptotokenkit.Import(pfxBytes, pkcs12.DefaultPassword))

	otherKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	ids, err := cryptotokenkit.Identities()
	require.NoError(t, err)

	testCertificate1 := getTestCertificate(t, ids, TestCertificateName1)
	require.NotNil(t, testCertificate1)
	testCertificate2 := getTestCertificate(t, ids, TestCertificateName2)
	require.NotNil(t, testCertificate2)
	defer func() {
		require.NoError(t, testCertificate1.Delete())
		require.NoError(t, testCertificate2.Delete())
	}()

	cert1, hasEqual := testCertificate1.PrivateKey().(equalizer)
	require.True(t, hasEqual)

	cert2, hasEqual := testCertificate2.PrivateKey().(equalizer)
	require.True(t, hasEqual)

	require.False(t, cert1.Equal(cert2))
	require.True(t, cert1.Equal(cert1))
	require.True(t, cert2.Equal(cert2))
	require.False(t, otherKey.Equal(cert2))
	require.False(t, cert1.Equal(otherKey))
}

func createCertificate(t require.TestingT, name string) []byte {
	keyBytes, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &keyBytes.PublicKey, keyBytes)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	pfxBytes, err := pkcs12.Encode(rand.Reader, keyBytes, cert, []*x509.Certificate{}, pkcs12.DefaultPassword)
	require.NoError(t, err)

	return pfxBytes
}

func getTestCertificate(t require.TestingT, ids []cryptotokenkit.Identity, commonName string) cryptotokenkit.Identity {
	for _, id := range ids {
		cert, err := id.Certificate()
		require.NoError(t, err)
		if cert.Subject.CommonName == commonName {
			return id
		}
	}
	return nil
}

type equalizer interface {
	Equal(x crypto.PrivateKey) bool
}
