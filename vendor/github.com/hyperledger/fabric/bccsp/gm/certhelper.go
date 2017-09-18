package gm

import(
	"github.com/hyperledger/fabric/bccsp/gm/sm2"
	"github.com/hyperledger/fabric/bccsp"
	"io"
	"crypto/x509"
	"crypto/rand"
	"math/big"
)

func CreateCertificateToMem(template, parent *sm2.Certificate,key bccsp.Key) ([]byte, error) {
	pk := key.(*gmsm2PrivateKey).privKey
	puk := &pk.PublicKey
	if template.PublicKey == nil{
		template.PublicKey = puk
	}
	if parent.PublicKey == nil{
		parent.PublicKey = puk
	}
	

	return sm2.CreateCertificateToMem(template,parent,puk,pk)
}


func dd(template *sm2.Certificate){

	serialNumber := make([]byte, 20)
	_, err := io.ReadFull(rand.Reader, serialNumber)
	if err != nil {
		//return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	}

	// SetBytes interprets buf as the bytes of a big-endian
	// unsigned integer. The leading byte should be masked
	// off to ensure it isn't negative.
	serialNumber[0] &= 0x7F

	template.SerialNumber = new(big.Int).SetBytes(serialNumber)
}


// X509证书格式转换为 SM2证书格式
func ParseX509Certificate2Sm2 (x509Cert *x509.Certificate) *sm2.Certificate{
	sm2cert := &sm2.Certificate{
		Raw: x509Cert.Raw,
		RawTBSCertificate: 	x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:	x509Cert.RawSubjectPublicKeyInfo,
		RawSubject: x509Cert.RawSubject,
		RawIssuer:	x509Cert.RawIssuer,

		Signature:	x509Cert.Signature,
		// SignatureAlgorithm:	{x509Cert.SignatureAlgorithm},
		
		

		//PublicKeyAlgorithm:	x509Cert.PublicKeyAlgorithm,
		PublicKey:	x509Cert.PublicKey,
		
		Version:	x509Cert.Version,
		SerialNumber:	x509Cert.SerialNumber,
		Issuer:	x509Cert.Issuer,
		Subject:	x509Cert.Subject,
		NotBefore:	x509Cert.NotBefore,
		NotAfter:	x509Cert.NotAfter,
		// KeyUsage:	x509.KeyUsage{},

		Extensions:	x509Cert.Extensions,

		ExtraExtensions:	x509Cert.ExtraExtensions,

		UnhandledCriticalExtensions:	x509Cert.UnhandledCriticalExtensions,

		// ExtKeyUsage:	x509Cert.ExtKeyUsage,
		UnknownExtKeyUsage:	x509Cert.UnknownExtKeyUsage,

		BasicConstraintsValid:	x509Cert.BasicConstraintsValid,
		IsCA:	x509Cert.IsCA,
		MaxPathLen:	x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero:	x509Cert.MaxPathLenZero,

		SubjectKeyId:	x509Cert.SubjectKeyId,
		AuthorityKeyId:	x509Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:	x509Cert.OCSPServer,
		IssuingCertificateURL:	x509Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:	x509Cert.DNSNames,
		EmailAddresses:	x509Cert.EmailAddresses,
		IPAddresses:	x509Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical:	x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:	x509Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints:	x509Cert.CRLDistributionPoints,

		PolicyIdentifiers:	x509Cert.PolicyIdentifiers,
	}
	return sm2cert
}