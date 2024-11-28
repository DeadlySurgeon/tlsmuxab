package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"concepts/tlsmuxab/services"
)

func main() {
	// Setup output folders.
	setupCertFolder()

	// Create or Load Root/Intermediate certs/keys.
	intCert, intKey := rootAndIntermediate()

	// Create server/client certs/keys.
	generateServerCerts(intCert, intKey)
	generateClientCerts(intCert, intKey)
}

func generateClientCerts(parent *x509.Certificate, key crypto.PrivateKey) {
	fmt.Println("Generating Client Cert:")
	for _, name := range []string{
		"orion",
		"leo",
		"aquila",
		"aries",
		"pisces",
	} {
		fmt.Println("-", name)

		clientKey := generateKeyPair()
		clientCert := createCertTemplate(pkix.Name{CommonName: name}, false, time.Hour*24)
		clientCertBytes := createCert(clientCert, parent, &clientKey.PublicKey, key)

		writePEM("certs/clients/"+name+"-cert.pem", "CERTIFICATE", clientCertBytes)
		writeKey("certs/clients/"+name+"-key.pem", clientKey)
	}
}

func generateServerCerts(parent *x509.Certificate, key crypto.PrivateKey) {
	// servers
	fmt.Println("Generating Server Cert:")
	for _, name := range []services.Service{
		services.Alpha,
		services.Beta,
		services.Gamma,
		services.Delta,
		services.Epsilon,
	} {
		name := string(name)
		fmt.Println("-", name)

		serverKey := generateKeyPair()
		serverCert := createCertTemplate(pkix.Name{CommonName: name}, false, time.Hour*24)
		serverCertBytes := createCert(serverCert, parent, &serverKey.PublicKey, key)

		writePEM("certs/servers/"+name+"-cert.pem", "CERTIFICATE", serverCertBytes)
		writeKey("certs/servers/"+name+"-key.pem", serverKey)
	}
}

func rootAndIntermediate() (intermediate *x509.Certificate, key crypto.PrivateKey) {
	// No need to flush CA or Intermediate.
	if filesExist(
		"certs/ca/root-ca-cert.pem", "certs/ca/root-ca-key.pem",
		"certs/ca/intermediate-ca-cert.pem", "certs/ca/intermediate-ca-key.pem",
	) {
		caCertBytes, err := os.ReadFile("certs/ca/intermediate-ca-cert.pem")
		expect("failed to load intermediate cert: %v", err)
		caCertPem, _ := pem.Decode(caCertBytes)
		intermediate, err = x509.ParseCertificate(caCertPem.Bytes)
		expect("failed to decode intermediate cert: %v", err)

		caKeyBytes, err := os.ReadFile("certs/ca/intermediate-ca-key.pem")
		expect("failed to load intermediate key: %v", err)
		caKeyPem, _ := pem.Decode(caKeyBytes)
		key, err = x509.ParseECPrivateKey(caKeyPem.Bytes)
		expect("failed to decode intermediate key: %v", err)

		return
	}

	fmt.Println("Creating Root CA")
	rootKey := generateKeyPair()
	rootCertTemp := createCertTemplate(pkix.Name{CommonName: "Root CA"}, true, time.Hour*24*365)
	rootCertBytes := createCert(rootCertTemp, rootCertTemp, &rootKey.PublicKey, rootKey)

	writeKey("certs/ca/root-ca-key.pem", rootKey)
	writePEM("certs/ca/root-ca-cert.pem", "CERTIFICATE", rootCertBytes)

	fmt.Println("Creating Intermediate CA")
	intKey := generateKeyPair()
	intCertTemp := createCertTemplate(pkix.Name{CommonName: "Intermediate CA"}, true, time.Hour*24*365)
	intCertBytes := createCert(intCertTemp, rootCertTemp, &intKey.PublicKey, intKey)

	writeKey("certs/ca/intermediate-ca-key.pem", intKey)
	writePEM("certs/ca/intermediate-ca-cert.pem", "CERTIFICATE", intCertBytes)

	return intCertTemp, intKey
}

func filesExist(path ...string) bool {
	for _, p := range path {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return false
		} else if err != nil {
			panic(err)
		}
	}

	return true
}

func setupCertFolder() {
	expect("Failed to create certs/ca folder: %v", os.MkdirAll("certs/ca/", os.ModePerm))
	expect("Failed to create certs/servers folder: %v", os.MkdirAll("certs/servers/", os.ModePerm))
	expect("Failed to create certs/clients folder: %v", os.MkdirAll("certs/clients/", os.ModePerm))
}

// generateKeyPair generates a new ECDSA private key.
func generateKeyPair() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	expect("failed to generate key: %v", err)
	return key
}

// createCert creates a certificate using the given template and parent.
func createCert(template, parent *x509.Certificate, pubKey interface{}, parentPrivKey interface{}) []byte {
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, parentPrivKey)
	expect("failed to create template: %v", err)
	return cert
}

// writePEM writes a PEM-encoded block to stdout or a file.
func writePEM(location string, pemType string, data []byte) {
	block := &pem.Block{Type: pemType, Bytes: data}
	err := os.WriteFile(location, pem.EncodeToMemory(block), 0600)
	expect("failed to write file %s: %v", location, err)
}

func writeKey(location string, key *ecdsa.PrivateKey) {
	byts, err := x509.MarshalECPrivateKey(key)
	expect("failed to marshal ec private key: %v", err)
	writePEM(location, "EC PRIVATE KEY", byts)
}

// createCertTemplate creates a generic certificate template.
func createCertTemplate(subject pkix.Name, isCA bool, duration time.Duration) *x509.Certificate {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	expect("failed to create a random integer for certificate: %v", err)

	var dnsNames []string
	if !isCA {
		dnsNames = append(dnsNames, subject.CommonName, "localhost")
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		DNSNames:     dnsNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(duration),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign, // Shotgun lol
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
	}
}

func expect(s string, i ...any) {
	for _, ii := range i {
		if ii == nil {
			return
		}
	}
	panic(fmt.Sprintf(s, i...))
}
