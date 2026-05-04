package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// buildTLSConfig returns a *tls.Config or nil for plain HTTP.
//
// Three modes:
//   1. Cert+Key paths set       → load from disk
//   2. AutoSelfSigned=true     → generate ephemeral ECDSA self-signed
//                                 (cached on disk so it survives restarts)
//   3. Otherwise                → nil (plain HTTP)
func buildTLSConfig(opts Options) (*tls.Config, error) {
	if opts.TLSCert != "" && opts.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(opts.TLSCert, opts.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load cert/key: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}

	if opts.AutoSelfSigned {
		certPath := "/etc/goloom/self-signed.crt"
		keyPath := "/etc/goloom/self-signed.key"

		if _, err := os.Stat(certPath); err == nil {
			if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
				return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
			}
		}

		cert, err := generateSelfSigned(opts.Listen)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed: %w", err)
		}
		if err := persistSelfSigned(cert, certPath, keyPath); err != nil {
			opts.Logger.Printf("could not persist self-signed cert (will regenerate next boot): %v", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}

	return nil, nil
}

func generateSelfSigned(listen string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	host, _, _ := net.SplitHostPort(listen)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "goloom-admin"
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host, Organization: []string{"goloom"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:     []string{host, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func persistSelfSigned(cert tls.Certificate, certPath, keyPath string) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("empty cert")
	}
	if err := os.MkdirAll("/etc/goloom", 0700); err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}

	priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("unexpected key type %T", cert.PrivateKey)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return os.WriteFile(keyPath, keyPEM, 0600)
}
