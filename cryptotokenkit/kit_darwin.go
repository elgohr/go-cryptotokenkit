package cryptotokenkit

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"
)

// Identity is a X.509 certificate and its corresponding private key.
type Identity interface {
	// Certificate gets the identity's certificate.
	Certificate() (*x509.Certificate, error)
	// CertificateChain attempts to get the identity's full certificate chain.
	CertificateChain() ([]*x509.Certificate, error)
	// Signer gets a crypto.Signer that uses the identity's private key.
	Signer() crypto.Signer
	// Decrypter gets a crypto.Decrypter that uses the identity's private key.
	Decrypter() crypto.Decrypter
	// Delete deletes this identity from the system.
	Delete() error
	// Close any manually managed memory held by the Identity.
	Close()
}

// Identities lists existing identities from CryptoTokenKit
func Identities() ([]Identity, error) {
	query := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):      C.CFTypeRef(C.kSecClassIdentity),
		C.CFTypeRef(C.kSecReturnRef):  C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit): C.CFTypeRef(C.kSecMatchLimitAll),
	})
	if query == nilCFDictionaryRef {
		return nil, errors.New("error creating CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var absResult C.CFTypeRef
	if err := osStatusError(C.SecItemCopyMatching(query, &absResult)); err != nil {
		if err == osStatus(C.errSecItemNotFound) {
			return []Identity{}, nil
		}

		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(absResult))

	aryResult := C.CFArrayRef(absResult)

	n := C.CFArrayGetCount(aryResult)
	identRefs := make([]C.CFTypeRef, n)
	C.CFArrayGetValues(aryResult, C.CFRange{0, n}, (*unsafe.Pointer)(unsafe.Pointer(&identRefs[0])))

	idents := make([]Identity, 0, n)
	for _, identRef := range identRefs {
		idents = append(idents, newMacIdentity(C.SecIdentityRef(identRef)))
	}
	return idents, nil
}

// Import imports a new identity into CryptoTokenKit
func Import(data []byte, password string) error {
	cdata, err := bytesToCFData(data)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cdata))

	cpass := stringToCFString(password)
	defer C.CFRelease(C.CFTypeRef(cpass))

	cops := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecImportExportPassphrase): C.CFTypeRef(cpass),
	})
	if cops == nilCFDictionaryRef {
		return errors.New("error creating CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(cops))

	var cret C.CFArrayRef
	if err := osStatusError(C.SecPKCS12Import(cdata, cops, &cret)); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cret))

	return nil
}

type macIdentity struct {
	ref C.SecIdentityRef
}

func newMacIdentity(ref C.SecIdentityRef) *macIdentity {
	C.CFRetain(C.CFTypeRef(ref))
	return &macIdentity{ref: ref}
}

func (i *macIdentity) Certificate() (*x509.Certificate, error) {
	certRef, err := i.getCertRef()
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(certRef))

	return exportCertRef(certRef)
}

func (i *macIdentity) CertificateChain() ([]*x509.Certificate, error) {
	certRef, err := i.getCertRef()
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(certRef))

	policy := C.SecPolicyCreateSSL(0, nilCFStringRef)

	var trustRef C.SecTrustRef
	if err := osStatusError(C.SecTrustCreateWithCertificates(C.CFTypeRef(certRef), C.CFTypeRef(policy), &trustRef)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(trustRef))

	certs := C.CFArrayRef(C.SecTrustCopyCertificateChain(trustRef))
	defer C.CFRelease(C.CFTypeRef(certs))
	numberOfCerts := C.CFArrayGetCount(certs)
	certRefs := make([]C.CFTypeRef, numberOfCerts)
	C.CFArrayGetValues(certs, C.CFRange{0, numberOfCerts}, (*unsafe.Pointer)(unsafe.Pointer(&certRefs[0])))

	chain := []*x509.Certificate{}
	for _, ref := range certRefs {
		chainCert, err := exportCertRef(C.SecCertificateRef(ref))
		if err != nil {
			return nil, err
		}
		chain = append(chain, chainCert)
	}

	return chain, nil
}

func (i *macIdentity) Signer() crypto.Signer {
	return i
}

func (i *macIdentity) Decrypter() crypto.Decrypter {
	return i
}

func (i *macIdentity) Delete() error {
	itemList := []C.SecIdentityRef{i.ref}
	itemListPtr := (*unsafe.Pointer)(unsafe.Pointer(&itemList[0]))
	citemList := C.CFArrayCreate(nilCFAllocatorRef, itemListPtr, 1, nil)
	if citemList == nilCFArrayRef {
		return errors.New("error creating CFArray")
	}
	defer C.CFRelease(C.CFTypeRef(citemList))

	query := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):         C.CFTypeRef(C.kSecClassIdentity),
		C.CFTypeRef(C.kSecMatchItemList): C.CFTypeRef(citemList),
	})
	if query == nilCFDictionaryRef {
		return errors.New("error creating CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	return osStatusError(C.SecItemDelete(query))
}

func (i *macIdentity) Close() {
	if i.ref != nilSecIdentityRef {
		C.CFRelease(C.CFTypeRef(i.ref))
		i.ref = nilSecIdentityRef
	}
}

func (i *macIdentity) Public() crypto.PublicKey {
	cert, err := i.Certificate()
	if err != nil {
		return nil
	}

	return cert.PublicKey
}

func (i *macIdentity) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	kref, err := i.getKeyRef()
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(kref))

	cdigest, err := bytesToCFData(digest)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cdigest))

	algo, err := i.signingAlgorithm(hash)
	if err != nil {
		return nil, err
	}

	var cerr C.CFErrorRef
	csig := C.SecKeyCreateSignature(kref, algo, cdigest, &cerr)

	if err := cfErrorError(cerr); err != nil {
		defer C.CFRelease(C.CFTypeRef(cerr))
		return nil, fmt.Errorf("could not sign: %v", err)
	}

	if csig == nilCFDataRef {
		return nil, errors.New("nil signature from SecKeyCreateSignature")
	}

	defer C.CFRelease(C.CFTypeRef(csig))

	return cfDataToBytes(csig), nil
}

func (i *macIdentity) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	kref, err := i.getKeyRef()
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(kref))

	cipherText, err := bytesToCFData(msg)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cipherText))

	algo := decryptionAlgorithm(opts)

	var cerr C.CFErrorRef
	plainText := C.SecKeyCreateDecryptedData(kref, algo, cipherText, &cerr)
	if err := cfErrorError(cerr); err != nil {
		defer C.CFRelease(C.CFTypeRef(cerr))
		return nil, fmt.Errorf("could not decrypt: %w", err)
	}

	if plainText == nilCFDataRef {
		return nil, errors.New("nil plaintext from SecKeyCreateDecryptedData")
	}

	defer C.CFRelease(C.CFTypeRef(plainText))
	return cfDataToBytes(plainText), nil
}

func decryptionAlgorithm(opts crypto.DecrypterOpts) C.SecKeyAlgorithm {
	switch opts := opts.(type) {
	case *rsa.OAEPOptions:
		switch opts.Hash.HashFunc() {
		case crypto.SHA1:
			return C.kSecKeyAlgorithmRSAEncryptionOAEPSHA1
		case crypto.SHA224:
			return C.kSecKeyAlgorithmRSAEncryptionOAEPSHA224
		case crypto.SHA256:
			return C.kSecKeyAlgorithmRSAEncryptionOAEPSHA256
		case crypto.SHA384:
			return C.kSecKeyAlgorithmRSAEncryptionOAEPSHA384
		case crypto.SHA512:
			return C.kSecKeyAlgorithmRSAEncryptionOAEPSHA512
		}
	case *rsa.PKCS1v15DecryptOptions:
		return C.kSecKeyAlgorithmRSAEncryptionPKCS1
	}
	return C.kSecKeyAlgorithmRSAEncryptionPKCS1 // default
}

func (i *macIdentity) signingAlgorithm(hash crypto.Hash) (C.SecKeyAlgorithm, error) {
	crt, err := i.Certificate()
	if err != nil {
		return nilCFStringRef, err
	}
	switch crt.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA1, nil
		case crypto.SHA256:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256, nil
		case crypto.SHA384:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384, nil
		case crypto.SHA512:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512, nil
		default:
			return nilCFStringRef, errors.New("unsupported hash algorithm")
		}
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1, nil
		case crypto.SHA256:
			return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256, nil
		case crypto.SHA384:
			return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384, nil
		case crypto.SHA512:
			return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512, nil
		default:
			return nilCFStringRef, errors.New("unsupported hash algorithm")
		}
	default:
		return nilCFStringRef, errors.New("unsupported key type")
	}
}

func (i *macIdentity) getKeyRef() (C.SecKeyRef, error) {
	var keyRef C.SecKeyRef
	if err := osStatusError(C.SecIdentityCopyPrivateKey(i.ref, &keyRef)); err != nil {
		return nilSecKeyRef, err
	}
	return keyRef, nil
}

func (i *macIdentity) getCertRef() (C.SecCertificateRef, error) {
	var certRef C.SecCertificateRef
	if err := osStatusError(C.SecIdentityCopyCertificate(i.ref, &certRef)); err != nil {
		return nilSecCertificateRef, err
	}
	return certRef, nil
}

func exportCertRef(certRef C.SecCertificateRef) (*x509.Certificate, error) {
	derRef := C.SecCertificateCopyData(certRef)
	if derRef == nilCFDataRef {
		return nil, errors.New("error getting certificate from identity")
	}
	defer C.CFRelease(C.CFTypeRef(derRef))

	return x509.ParseCertificate(cfDataToBytes(derRef))
}

func stringToCFString(gostr string) C.CFStringRef {
	cstr := C.CString(gostr)
	defer C.free(unsafe.Pointer(cstr))

	return C.CFStringCreateWithCString(nilCFAllocatorRef, cstr, C.kCFStringEncodingUTF8)
}

func mapToCFDictionary(gomap map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	n := len(gomap)
	keys := make([]unsafe.Pointer, 0, n)
	values := make([]unsafe.Pointer, 0, n)

	for k, v := range gomap {
		keys = append(keys, unsafe.Pointer(k))
		values = append(values, unsafe.Pointer(v))
	}

	return C.CFDictionaryCreate(nilCFAllocatorRef, &keys[0], &values[0], C.CFIndex(n), nil, nil)
}

func cfDataToBytes(cfdata C.CFDataRef) []byte {
	nBytes := C.CFDataGetLength(cfdata)
	bytesPtr := C.CFDataGetBytePtr(cfdata)
	return C.GoBytes(unsafe.Pointer(bytesPtr), C.int(nBytes))
}

func bytesToCFData(gobytes []byte) (C.CFDataRef, error) {
	cptr := (*C.UInt8)(nil)
	clen := C.CFIndex(len(gobytes))

	if len(gobytes) > 0 {
		cptr = (*C.UInt8)(&gobytes[0])
	}

	cdata := C.CFDataCreate(nilCFAllocatorRef, cptr, clen)
	if cdata == nilCFDataRef {
		return nilCFDataRef, errors.New("error creating cfdata")
	}

	return cdata, nil
}

type osStatus C.OSStatus

func osStatusError(s C.OSStatus) error {
	if s == C.errSecSuccess {
		return nil
	}
	return osStatus(s)
}

// Error implements the error interface.
func (s osStatus) Error() string {
	return fmt.Sprintf("OSStatus %d", s)
}

// cfErrorError returns an error for a CFErrorRef unless it is nil.
func cfErrorError(cerr C.CFErrorRef) error {
	if cerr == nilCFErrorRef {
		return nil
	}
	code := int(C.CFErrorGetCode(cerr))
	if cdescription := C.CFErrorCopyDescription(cerr); cdescription != nilCFStringRef {
		defer C.CFRelease(C.CFTypeRef(cdescription))
		utf16Length := C.CFStringGetLength(cdescription)
		buf := make([]byte, utf16Length*2)
		C.CFStringGetCString(cdescription, (*C.char)(unsafe.Pointer(&buf[0])), utf16Length*2, C.kCFStringEncodingUTF8)
		return fmt.Errorf("%s", strings.TrimRight(string(buf), "\x00"))
	}
	return fmt.Errorf("CFError %d", code)
}

// work around https://golang.org/doc/go1.10#cgo
// in go>=1.10 CFTypeRefs are translated to uintptrs instead of pointers.
var (
	nilCFDictionaryRef   C.CFDictionaryRef
	nilSecCertificateRef C.SecCertificateRef
	nilCFArrayRef        C.CFArrayRef
	nilCFDataRef         C.CFDataRef
	nilCFErrorRef        C.CFErrorRef
	nilCFStringRef       C.CFStringRef
	nilSecIdentityRef    C.SecIdentityRef
	nilSecKeyRef         C.SecKeyRef
	nilCFAllocatorRef    C.CFAllocatorRef
)
