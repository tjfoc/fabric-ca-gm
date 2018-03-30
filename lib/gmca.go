package lib

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"net/mail"
	"time"

	"crypto"
	"crypto/rand"
	"encoding/pem"
	"io"
	"math/big"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/hyperledger-fabric-gm/bccsp"
	"github.com/tjfoc/hyperledger-fabric-gm/bccsp/gm"

	"github.com/cloudflare/cfssl/signer"
	"github.com/tjfoc/fabric-ca-gm/util"
)

//证书签名
func signCert(req signer.SignRequest, ca *CA) (cert []byte, err error) {
	/*csr := parseCertificateRequest()
	cert, err := sm2.CreateCertificateToMem(template, rootca, csr.pubkey, rootca.privkey)
	sm2Cert, err := sm2.parseCertificateFromMem(cert)

	var certRecord = certdb.CertificateRecord{
		Serial:  sm2Cert.SerialNumber.String(),
		AKI:     hex.EncodeToString(sm2Cert.AuthorityKeyId),
		CALabel: req.Label,
		Status:  "good",
		Expiry:  sm2Cert.NotAfter,
		PEM:     string(cert),
	}*/

	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, fmt.Errorf("decode error")
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("not a csr")
	}
	template, err := parseCertificateRequest(block.Bytes)
	if err != nil {
		log.Infof("xxxx gmca.go ParseCertificateRequest error:[%s]", err)
		return nil, err
	}

	certfile := ca.Config.CA.Certfile
	//certfile := req.Profile
	log.Info("^^^^^^^^^^^^^^^^^^^^^^^certifle = %s", certfile)
	rootkey, _, x509cert, err := util.GetSignerFromCertFile(certfile, ca.csp)
	if err != nil {
		return nil, err
	}

	rootca := ParseX509Certificate2Sm2(x509cert)

	cert, err = gm.CreateCertificateToMem(template, rootca, rootkey)
	clientCert, err := sm2.ReadCertificateFromMem(cert)
	log.Info("==================== Exit ParseCertificate")
	if err == nil {
		log.Infof("xxxx gmca.go signCert ok the sign cert len [%d]", len(cert))
	}

	var certRecord = certdb.CertificateRecord{
		Serial:  clientCert.SerialNumber.String(),
		AKI:     hex.EncodeToString(clientCert.AuthorityKeyId),
		CALabel: req.Label,
		Status:  "good",
		Expiry:  clientCert.NotAfter,
		PEM:     string(cert),
	}
	//aki := hex.EncodeToString(cert.AuthorityKeyId)
	//serial := util.GetSerialAsHex(cert.SerialNumber)

	err = ca.certDBAccessor.InsertCertificate(certRecord)
	if err == nil {
		log.Info("=====================error InsertCertificate!")
	}

	return
}

//生成证书
func createGmSm2Cert(key bccsp.Key, req *csr.CertificateRequest, priv crypto.Signer) (cert []byte, err error) {
	log.Infof("xxx xxx in gmca.go  createGmSm2Cert...key :%T", key)

	csrPEM, err := generate(priv, req, key)
	if err != nil {
		log.Infof("xxxxxxxxxxxxx create csr error:%s", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("sm2 csr DecodeFailed")
	}

	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("sm2 not a csr")
	}
	sm2Template, err := parseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	log.Infof("key is %T   ---%T", sm2Template.PublicKey, sm2Template)
	cert, err = gm.CreateCertificateToMem(sm2Template, sm2Template, key)
	return
}

//证书请求转换成证书  参数为  block .Bytes
func parseCertificateRequest(csrBytes []byte) (template *sm2.Certificate, err error) {
	csrv, err := sm2.ParseCertificateRequest(csrBytes)
	if err != nil {
		//err = cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
		return
	}
	err = csrv.CheckSignature()
	// if err != nil {
	// 	//err = cferr.Wrap(cferr.CSRError, cferr.KeyMismatch, err)
	// 	return
	// }
	template = &sm2.Certificate{
		Subject:            csrv.Subject,
		PublicKeyAlgorithm: csrv.PublicKeyAlgorithm,
		PublicKey:          csrv.PublicKey,
		SignatureAlgorithm: csrv.SignatureAlgorithm,
		DNSNames:           csrv.DNSNames,
		IPAddresses:        csrv.IPAddresses,
		EmailAddresses:     csrv.EmailAddresses,
	}

	fmt.Printf("^^^^^^^^^^^^^^^^^^^^^^^^^^algorithn = %v, %v\n", template.PublicKeyAlgorithm, template.SignatureAlgorithm)
	log.Infof("xxxx publicKey :%T", template.PublicKey)

	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(time.Hour * 1000)
	//log.Infof("-----------csrv = %+v", csrv)
	for _, val := range csrv.Extensions {
		// Check the CSR for the X.509 BasicConstraints (RFC 5280, 4.2.1.9)
		// extension and append to template if necessary
		if val.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			var constraints csr.BasicConstraints
			var rest []byte

			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				//return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
			} else if len(rest) != 0 {
				//return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, errors.New("x509: trailing data after X.509 BasicConstraints"))
			}

			template.BasicConstraintsValid = true
			template.IsCA = constraints.IsCA
			template.MaxPathLen = constraints.MaxPathLen
			template.MaxPathLenZero = template.MaxPathLen == 0
		}
	}
	serialNumber := make([]byte, 20)
	_, err = io.ReadFull(rand.Reader, serialNumber)
	if err != nil {
		return nil, err
	}

	// SetBytes interprets buf as the bytes of a big-endian
	// unsigned integer. The leading byte should be masked
	// off to ensure it isn't negative.
	serialNumber[0] &= 0x7F

	template.SerialNumber = new(big.Int).SetBytes(serialNumber)

	return
}

//cloudflare 证书请求 转成 国密证书请求
func generate(priv crypto.Signer, req *csr.CertificateRequest, key bccsp.Key) (csr []byte, err error) {
	log.Info("xx entry generate")
	sigAlgo := signerAlgo(priv)
	if sigAlgo == sm2.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("Private key is unavailable")
	}
	log.Info("xx begin create sm2.CertificateRequest")
	var tpl = sm2.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: sigAlgo,
	}
	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSRSm2(req.CA, &tpl)
		if err != nil {
			err = fmt.Errorf("sm2 GenerationFailed")
			return
		}
	}
	if req.SerialNumber != "" {

	}
	csr, err = gm.CreateSm2CertificateRequestToMem(&tpl, key)
	log.Info("xx exit generate")
	return
}

func signerAlgo(priv crypto.Signer) sm2.SignatureAlgorithm {
	switch pub := priv.Public().(type) {
	case *sm2.PublicKey:
		switch pub.Curve {
		case sm2.P256Sm2():
			return sm2.SM2WithSHA256
		default:
			return sm2.SM2WithSHA1
		}
	default:
		return sm2.UnknownSignatureAlgorithm
	}
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSR(reqConf *csr.CAConfig, csreq *x509.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}

	csreq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}
	return nil
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSRSm2(reqConf *csr.CAConfig, csreq *sm2.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}

	csreq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}

	return nil
}

func ParseX509Certificate2Sm2(x509Cert *x509.Certificate) *sm2.Certificate {
	sm2cert := &sm2.Certificate{
		Raw:                         x509Cert.Raw,
		RawTBSCertificate:           x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     x509Cert.RawSubjectPublicKeyInfo,
		RawSubject:                  x509Cert.RawSubject,
		RawIssuer:                   x509Cert.RawIssuer,
		Signature:                   x509Cert.Signature,
		SignatureAlgorithm:          sm2.SignatureAlgorithm(x509Cert.SignatureAlgorithm),
		PublicKeyAlgorithm:          sm2.PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
		PublicKey:                   x509Cert.PublicKey,
		Version:                     x509Cert.Version,
		SerialNumber:                x509Cert.SerialNumber,
		Issuer:                      x509Cert.Issuer,
		Subject:                     x509Cert.Subject,
		NotBefore:                   x509Cert.NotBefore,
		NotAfter:                    x509Cert.NotAfter,
		KeyUsage:                    sm2.KeyUsage(x509Cert.KeyUsage),
		Extensions:                  x509Cert.Extensions,
		ExtraExtensions:             x509Cert.ExtraExtensions,
		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,
		//ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage:    x509Cert.UnknownExtKeyUsage,
		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
		IsCA:       x509Cert.IsCA,
		MaxPathLen: x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: x509Cert.MaxPathLenZero,
		SubjectKeyId:   x509Cert.SubjectKeyId,
		AuthorityKeyId: x509Cert.AuthorityKeyId,
		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            x509Cert.OCSPServer,
		IssuingCertificateURL: x509Cert.IssuingCertificateURL,
		// Subject Alternate Name values
		DNSNames:       x509Cert.DNSNames,
		EmailAddresses: x509Cert.EmailAddresses,
		IPAddresses:    x509Cert.IPAddresses,
		// Name constraints
		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,
		// CRL Distribution Points
		CRLDistributionPoints: x509Cert.CRLDistributionPoints,
		PolicyIdentifiers:     x509Cert.PolicyIdentifiers,
	}
	for _, val := range x509Cert.ExtKeyUsage {
		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, sm2.ExtKeyUsage(val))
	}
	return sm2cert
}
