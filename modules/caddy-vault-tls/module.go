package caddyvaulttls

import (
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "log"
    "os"

    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
    "github.com/hashicorp/vault/api"
)

// ModuleName is the name of the Caddy module.
const ModuleName = "caddy.vault_tls"

func init() {
    caddy.RegisterModule(VaultTLS{})
}

// VaultTLS is the Caddy module for issuing certificates from HashiCorp Vault.
type VaultTLS struct {
    VaultAddr string `json:"vault_addr"`
    Token     string `json:"token"`
    Role      string `json:"role"`
    client    *api.Client
}

// CaddyModule returns the Caddy module information.
func (VaultTLS) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "caddy.tls.issuance.vault",
        New: func() caddy.Module { return new(VaultTLS) },
    }
}

// Provision sets up the module.
func (v *VaultTLS) Provision(ctx caddy.Context) error {
    config := api.DefaultConfig()
    config.Address = v.VaultAddr

    client, err := api.NewClient(config)
    if err != nil {
        return fmt.Errorf("failed to create Vault client: %w", err)
    }

    if v.Token == "" {
        v.Token = os.Getenv("VAULT_TOKEN")
        if v.Token == "" {
            return fmt.Errorf("vault token not provided")
        }
    }

    client.SetToken(v.Token)
    v.client = client

    return nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (v *VaultTLS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
    if !d.Args(&v.VaultAddr, &v.Token, &v.Role) {
        return d.ArgErr()
    }
    return nil
}
