package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	hosts        string
	validForDays int
	rootCAFile   string
	rootCAKey    string
	certFile     string
	keyFile      string
	organization string
)

func init() {
	flag.StringVar(&hosts, "hosts", "localhost", "Comma-separated hostnames and IPs to generate a certificate for")
	flag.IntVar(&validForDays, "days", 365, "Duration that certificate is valid for, in days")
	flag.StringVar(&rootCAFile, "root-ca", "rootCA.crt", "Root CA certificate file")
	flag.StringVar(&rootCAKey, "root-ca-key", "rootCA.key", "Root CA private key file")
	flag.StringVar(&certFile, "cert", "certfile.crt", "Certificate file")
	flag.StringVar(&keyFile, "key", "keyfile.key", "Private key file")
	flag.StringVar(&organization, "org", "Yo Medical Files(U) Ltd", "Organization name")
}

func validateFlags() error {
	if hosts == "" {
		return fmt.Errorf("hosts cannot be empty")
	}
	if validForDays < 1 {
		return fmt.Errorf("days must be a positive integer")
	}
	if rootCAFile == "" {
		return fmt.Errorf("root-ca cannot be empty")
	}
	if rootCAKey == "" {
		return fmt.Errorf("root-ca-key cannot be empty")
	}
	if certFile == "" {
		return fmt.Errorf("cert cannot be empty")
	}
	if keyFile == "" {
		return fmt.Errorf("key cannot be empty")
	}
	if organization == "" {
		return fmt.Errorf("org cannot be empty")
	}
	return nil
}

func main() {
	flag.Parse()

	if err := validateFlags(); err != nil {
		fmt.Printf("Error validating flags: %v\n", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := generateRootCA(rootCAFile, rootCAKey); err != nil {
		fmt.Printf("Error generating root CA: %v\n", err)
		os.Exit(1)
	}

	hostList := parseHosts(hosts)
	if err := generateCert(hostList, validForDays, organization, rootCAFile, rootCAKey, certFile, keyFile); err != nil {
		fmt.Printf("Error generating certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate and key files generated successfully:\n")
	fmt.Println("-------------------------------------------------")
	fmt.Println("Root CA cert", rootCAFile)
	fmt.Println("Root CA key", rootCAKey)

	fmt.Printf("Certificate: %s\n", certFile)
	fmt.Printf("Private Key: %s\n", keyFile)

}

func parseHosts(hosts string) []string {
	hostList := []string{}
	hostsSlice := strings.Split(hosts, ",")
	for _, h := range hostsSlice {
		hostList = append(hostList, strings.TrimSpace(h))
	}
	return hostList
}

func generateRootCA(certFile, keyFile string) error {
	// Generate RSA private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization:       []string{"Yo Medical Files(U) Ltd"},
			CommonName:         "Yo Medical Files(U) Ltd Root CA",
			Country:            []string{"UG"},
			OrganizationalUnit: []string{"Yo Medical Files(U) Ltd"},
			Province:           []string{"Kampala"},
			Locality:           []string{"Kampala"},
			StreetAddress:      []string{"Kampala Road"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return err
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write private key to file
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return nil
}

func generateCert(hosts []string, validForDays int, organization, rootCAFile, rootCAKey, certFile, keyFile string) error {
	// Load Root CA
	rootCACert, err := os.ReadFile(rootCAFile)
	if err != nil {
		return err
	}
	rootCAPrivateKey, err := os.ReadFile(rootCAKey)
	if err != nil {
		return err
	}

	// Parse root CA certificate
	rootCACertBlock, _ := pem.Decode(rootCACert)
	if rootCACertBlock == nil {
		return fmt.Errorf("failed to parse root CA certificate")
	}
	rootCA, err := x509.ParseCertificate(rootCACertBlock.Bytes)
	if err != nil {
		return err
	}

	// Parse root CA private key
	rootCAPrivateKeyBlock, _ := pem.Decode(rootCAPrivateKey)
	if rootCAPrivateKeyBlock == nil {
		return fmt.Errorf("failed to parse root CA private key")
	}

	rootCAPrivateKeyData, err := x509.ParsePKCS8PrivateKey(rootCAPrivateKeyBlock.Bytes)
	if err != nil {
		return err
	}

	// Generate RSA private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   hosts[0],
		},
		DNSNames:     hosts,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, validForDays),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
	}

	// Create signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, rootCA, &privKey.PublicKey, rootCAPrivateKeyData)
	if err != nil {
		return err
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write private key to file
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}

	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
}
