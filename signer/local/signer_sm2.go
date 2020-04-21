// Package local implements certificate signature functionality for CFSSL.
package local

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"unsafe"

	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/gmsm/sm2"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// SignerSM2 support SM2 only
type SignerSM2 struct {
	ca      *sm2.Certificate
	priv    crypto.Signer
	policy  *config.Signing
	sigAlgo sm2.SignatureAlgorithm
}

//SignerSM2 实现了singer.go中的 Signer接口

// NewSignerSM2 creates a new Signer directly from a
// private key and certificate, with optional policy.
func NewSignerSM2(priv crypto.Signer, cert *sm2.Certificate, sigAlgo sm2.SignatureAlgorithm, policy *config.Signing) (*SignerSM2, error) {
	if policy == nil {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig()}
	}

	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}

	return &SignerSM2{
		ca:      cert,
		priv:    priv,
		sigAlgo: sigAlgo,
		policy:  policy,
	}, nil
}

func NewSignerSM2FromFile(caFile, caKeyFile string, policy *config.Signing) (*SignerSM2, error) {
	log.Debug("Loading CA: ", caFile)
	ca, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	log.Debug("Loading CA key: ", caKeyFile)
	cakey, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ReadFailed, err)
	}

	parsedCa, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, err
	}

	priv, err := helpers.ParsePrivateKeyPEM(cakey)
	if err != nil {
		log.Debug("Malformed private key %v", err)
		return nil, err
	}

	return NewSignerSM2(priv, (*sm2.Certificate)(unsafe.Pointer(parsedCa)),
		signer.SignerAlgoSM2(priv), policy)
}

func (s *SignerSM2) sign(template *sm2.Certificate, profile *config.SigningProfile, serialSeq string) (cert []byte, err error) {
	var (
		derBytes []byte
	)
	err = signer.FillTemplate((*x509.Certificate)(unsafe.Pointer(template)), s.policy.Default, profile, serialSeq)
	if err != nil {
		return
	}

	serialNumber := template.SerialNumber
	var initRoot bool
	if s.ca == nil {
		if !template.IsCA {
			err = cferr.New(cferr.PolicyError, cferr.InvalidRequest)
			return
		}
		template.DNSNames = nil
		s.ca = template
		initRoot = true
		template.MaxPathLen = signer.MaxPathLen
	} else if template.IsCA {
		template.MaxPathLen = 1
		template.DNSNames = nil
	}

	switch template.PublicKey.(type) {
	case *rsa.PublicKey:
		derBytes, err = sm2.CreateCertificate(rand.Reader, template, s.ca, template.PublicKey, s.priv)

	case *ecdsa.PublicKey:
		switch template.PublicKey.(*ecdsa.PublicKey).Curve {
		case elliptic.P224():
		case elliptic.P256():
		case elliptic.P384():
		case elliptic.P521():
		case sm2.P256Sm2():
			var ecdsapub ecdsa.PublicKey
			ecdsapub.Curve = sm2.P256Sm2()
			ecdsapub.X = template.PublicKey.(*ecdsa.PublicKey).X
			ecdsapub.Y = template.PublicKey.(*ecdsa.PublicKey).Y

			derBytes, err = sm2.CreateCertificate(rand.Reader, template, s.ca, &ecdsapub, s.priv)
		}
	default:
		panic("sign publickey of cert in invalid")
	}

	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	}

	if initRoot {
		s.ca, err = sm2.ParseCertificate(derBytes)
		if err != nil {
			return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, err)
		}
	}

	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	log.Infof("signed certificate with serial number %s", serialNumber)
	return
}

// Sign signs a new certificate based on the PEM-encoded client
// certificate or certificate request with the signing profile,
// specified by profileName.
func (s *SignerSM2) Sign(req signer.SignRequest) (cert []byte, err error) {
	profile, err := signer.Profile(s, req.Profile)
	if err != nil {
		return
	}

	serialSeq := ""
	if profile.UseSerialSeq {
		serialSeq = req.SerialSeq
	}

	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, cferr.New(cferr.CSRError, cferr.DecodeFailed)
	}

	if block.Type != "CERTIFICATE REQUEST" {
		return nil, cferr.Wrap(cferr.CSRError,
			cferr.BadRequest, errors.New("not a certificate or csr"))
	}

	csrTemplate, err := signer.ParseCertificateRequestSM2(s, block.Bytes)
	if err != nil {
		return nil, err
	}

	// Copy out only the fields from the CSR authorized by policy.
	safeTemplate := sm2.Certificate{}
	// If the profile contains no explicit whitelist, assume that all fields
	// should be copied from the CSR.
	if profile.CSRWhitelist == nil {
		safeTemplate = *csrTemplate
	} else {
		if profile.CSRWhitelist.Subject {
			safeTemplate.Subject = csrTemplate.Subject
		}
		if profile.CSRWhitelist.PublicKeyAlgorithm {
			safeTemplate.PublicKeyAlgorithm = csrTemplate.PublicKeyAlgorithm
		}
		if profile.CSRWhitelist.PublicKey {
			safeTemplate.PublicKey = csrTemplate.PublicKey
		}
		if profile.CSRWhitelist.SignatureAlgorithm {
			safeTemplate.SignatureAlgorithm = csrTemplate.SignatureAlgorithm
		}
		if profile.CSRWhitelist.DNSNames {
			safeTemplate.DNSNames = csrTemplate.DNSNames
		}
		if profile.CSRWhitelist.IPAddresses {
			safeTemplate.IPAddresses = csrTemplate.IPAddresses
		}
	}

	OverrideHosts((*x509.Certificate)(unsafe.Pointer(&safeTemplate)), req.Hosts)
	safeTemplate.Subject = PopulateSubjectFromCSR(req.Subject, safeTemplate.Subject)

	// If there is a whitelist, ensure that both the Common Name and SAN DNSNames match
	if profile.NameWhitelist != nil {
		if safeTemplate.Subject.CommonName != "" {
			if profile.NameWhitelist.Find([]byte(safeTemplate.Subject.CommonName)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
			}
		}
		for _, name := range safeTemplate.DNSNames {
			if profile.NameWhitelist.Find([]byte(name)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
			}
		}
	}

	return s.sign(&safeTemplate, profile, serialSeq)
}

// Info return a populated info.Resp struct or an error.
func (s *SignerSM2) Info(req info.Req) (resp *info.Resp, err error) {
	cert, err := s.Certificate(req.Label, req.Profile)
	if err != nil {
		return
	}

	profile, err := signer.Profile(s, req.Profile)
	if err != nil {
		return
	}

	resp = new(info.Resp)
	if cert.Raw != nil {
		resp.Certificate = string(bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	}
	resp.Usage = profile.Usage
	resp.ExpiryString = profile.ExpiryString

	return
}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *SignerSM2) SigAlgo() x509.SignatureAlgorithm {
	return x509.SignatureAlgorithm(s.sigAlgo)
}

// Certificate returns the signer's certificate.
func (s *SignerSM2) Certificate(label, profile string) (*sm2.Certificate, error) {
	cert := *s.ca
	return &cert, nil
}

// SetPolicy sets the signer's signature policy.
func (s *SignerSM2) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

// Policy returns the signer's policy.
func (s *SignerSM2) Policy() *config.Signing {
	return s.policy
}
