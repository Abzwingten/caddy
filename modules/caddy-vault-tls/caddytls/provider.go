package caddytls

import (
    "context"
    "crypto/tls"
    "fmt"

    "github.com/caddyserver/caddy/v2/modules/caddytls"
    "github.com/hashicorp/vault/api"
)

// VaultProvider is the TLS provider for HashiCorp Vault.
type VaultProvider struct {
    VaultAddr string
    Token     string
    Role      string
    client    *api.Client
}

// NewVaultProvider creates a new VaultProvider.
func NewVaultProvider(vaultAddr, token, role string) (*VaultProvider, error) {
    config := api.DefaultConfig()
    config.Address = vaultAddr

    client, err := api.NewClient(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create Vault client: %w", err)
    }

    client.SetToken(token)

    return &VaultProvider{
        VaultAddr: vaultAddr,
        Token:     token,
        Role:      role,
        client:    client,
    }, nil
}

// Issue issues a new certificate from Vault.
func (vp *VaultProvider) Issue(ctx context.Context, csrPEM []byte) (*tls.Certificate, error) {
    data := map[string]interface{}{
        "csr":    string(csrPEM),
        "format": "pem_bundle",
    }

    secret, err := vp.client.Logical().Write(fmt.Sprintf("pki/sign/%s", vp.Role), data)
    if err != nil {
        return nil, fmt.Errorf("failed to sign CSR: %w", err)
    }

    if secret == nil || secret.Data == nil {
        return nil, fmt.Errorf("no certificate returned from Vault")
    }

    certPEM, ok := secret.Data["certificate"].(string)
    if !ok {
        return nil, fmt.Errorf("invalid certificate data from Vault")
    }

    keyPEM, ok := secret.Data["private_key"].(string)
    if !ok {
        return nil, fmt.Errorf("invalid private key data from Vault")
    }

    cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
    if err != nil {
        return nil, fmt.Errorf("failed to parse certificate and key: %w", err)
    }

    return &cert, nil
}

// Revoke revokes a certificate from Vault.
func (vp *VaultProvider) Revoke(ctx context.Context, serial string, reason int) error {
    data := map[string]interface{}{
        "serial_number": serial,
        "reason":        reason,
    }

    _, err := vp.client.Logical().Write("pki/revoke", data)
    if err != nil {
        return fmt.Errorf("failed to revoke certificate: %w", err)
    }

    return nil
}

// Challenges returns the supported challenge types.
func (vp *VaultProvider) Challenges() []caddy.Replacer {
    return nil
}

// CleanUp cleans up any resources used by the provider.
func (vp *VaultProvider) CleanUp() error {
    // No resources to clean up in this example
    return nil
}

// Interface guard
var _ caddy.TLSProvider = (*VaultProvider)(nil)
