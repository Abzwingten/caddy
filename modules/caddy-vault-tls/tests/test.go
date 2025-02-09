package tests

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "testing"

    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
    "github.com/Abzwingten/caddy/modules/caddy-vault-tls"
    "github.com/hashicorp/vault/api"
    "log"
)

func TestVaultTLS(t *testing.T) {
    // Set up Vault client
    vaultAddr := "http://localhost:8200"
    vaultToken := "your-vault-token"
    role := "example-dot-com"

    config := api.DefaultConfig()
    config.Address = vaultAddr

    client, err := api.NewClient(config)
    if err != nil {
        t.Fatalf("failed to create Vault client: %v", err)
    }

    client.SetToken(vaultToken)

    // Create a CSR
    csrPEM := generateCSR(t)

    // Create a VaultProvider
    vaultProvider, err := caddyvaulttls.NewVaultProvider(vaultAddr, vaultToken, role)
    if err != nil {
        t.Fatalf("failed to create Vault provider: %v", err)
    }

    // Issue a certificate
    cert, err := vaultProvider.Issue(context.Background(), csrPEM)
    if err != nil {
        t.Fatalf("failed to issue certificate: %v", err)
    }

    // Verify the certificate
    if len(cert.Certificate) == 0 {
        t.Fatal("no certificate returned")
    }
    if len(cert.PrivateKey) == 0 {
        t.Fatal("no private key returned")
    }
}

func generateCSR(t *testing.T) []byte {
    template := x509.CertificateRequest{
        Subject: pkix.Name{
            CommonName: "example.com",
        },
        DNSNames: []string{"example.com"},
    }

    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatalf("failed to generate private key: %v", err)
    }

    csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
    if err != nil {
        t.Fatalf("failed to create CSR: %v", err)
    }

    csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
    return csrPEM
}
