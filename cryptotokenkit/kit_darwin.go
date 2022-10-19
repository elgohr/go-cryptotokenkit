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
	"unsafe"
)

// Identity is a X.509 certificate and its corresponding private key.
type Identity interface {
	// Certificate gets the identity's certificate.
	Certificate() (*x509.Certificate, error)
	// CertificateChain attempts to get the identity's full certificate chain.
	CertificateChain() ([]*x509.Certificate, error)
	// Signer gets a crypto.Signer that uses the identity's private key.
	Signer() (crypto.Signer, error)
	// Decrypter gets a crypto.Decrypter that uses the identity's private key.
	Decrypter() (crypto.Decrypter, error)
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
	ref   C.SecIdentityRef
	kref  C.SecKeyRef
	cref  C.SecCertificateRef
	crt   *x509.Certificate
	chain []*x509.Certificate
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

	crt, err := exportCertRef(certRef)
	if err != nil {
		return nil, err
	}

	i.crt = crt

	return i.crt, nil
}

func (i *macIdentity) CertificateChain() ([]*x509.Certificate, error) {
	certRef, err := i.getCertRef()
	if err != nil {
		return nil, err
	}

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
	i.chain = chain

	return chain, nil
}

func (i *macIdentity) Signer() (crypto.Signer, error) {
	if _, err := i.Certificate(); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *macIdentity) Decrypter() (crypto.Decrypter, error) {
	if _, err := i.Certificate(); err != nil {
		return nil, err
	}
	return i, nil
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

	if i.kref != nilSecKeyRef {
		C.CFRelease(C.CFTypeRef(i.kref))
		i.kref = nilSecKeyRef
	}

	if i.cref != nilSecCertificateRef {
		C.CFRelease(C.CFTypeRef(i.cref))
		i.cref = nilSecCertificateRef
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
		return nil, err
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
	if i.kref != nilSecKeyRef {
		return i.kref, nil
	}

	var keyRef C.SecKeyRef
	if err := osStatusError(C.SecIdentityCopyPrivateKey(i.ref, &keyRef)); err != nil {
		return nilSecKeyRef, err
	}

	i.kref = keyRef

	return i.kref, nil
}

func (i *macIdentity) getCertRef() (C.SecCertificateRef, error) {
	if i.cref != nilSecCertificateRef {
		return i.cref, nil
	}

	var certRef C.SecCertificateRef
	if err := osStatusError(C.SecIdentityCopyCertificate(i.ref, &certRef)); err != nil {
		return nilSecCertificateRef, err
	}

	i.cref = certRef

	return i.cref, nil
}

func exportCertRef(certRef C.SecCertificateRef) (*x509.Certificate, error) {
	derRef := C.SecCertificateCopyData(certRef)
	if derRef == nilCFDataRef {
		return nil, errors.New("error getting certificate from identity")
	}
	defer C.CFRelease(C.CFTypeRef(derRef))

	der := cfDataToBytes(derRef)
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

func stringToCFString(gostr string) C.CFStringRef {
	cstr := C.CString(gostr)
	defer C.free(unsafe.Pointer(cstr))

	return C.CFStringCreateWithCString(nilCFAllocatorRef, cstr, C.kCFStringEncodingUTF8)
}

func mapToCFDictionary(gomap map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	var (
		n      = len(gomap)
		keys   = make([]unsafe.Pointer, 0, n)
		values = make([]unsafe.Pointer, 0, n)
	)

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
	var (
		cptr = (*C.UInt8)(nil)
		clen = C.CFIndex(len(gobytes))
	)

	if len(gobytes) > 0 {
		cptr = (*C.UInt8)(&gobytes[0])
	}

	cdata := C.CFDataCreate(nilCFAllocatorRef, cptr, clen)
	if cdata == nilCFDataRef {
		return nilCFDataRef, errors.New("error creatin cfdata")
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
		if cstr := C.CFStringGetCStringPtr(cdescription, C.kCFStringEncodingUTF8); cstr != nil {
			str := C.GoString(cstr)
			return fmt.Errorf("CFError %d (%v)", code, str)
		}
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
