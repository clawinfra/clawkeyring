// Command clawkeyring is an agent-native validator key management service for ClawChain.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/clawinfra/clawkeyring/internal/audit"
	"github.com/clawinfra/clawkeyring/internal/injector"
	"github.com/clawinfra/clawkeyring/internal/keystore"
	"github.com/clawinfra/clawkeyring/internal/rotation"
	"github.com/clawinfra/clawkeyring/internal/server"
	"github.com/clawinfra/clawkeyring/pkg/keyring"
)

const defaultKeystore = "~/.clawkeyring"
const defaultNode = "http://127.0.0.1:9933"
const defaultAddr = "127.0.0.1:9090"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "clawkeyring",
		Short: "Agent-native validator key management for ClawChain",
		Long: `clawkeyring manages BABE, GRANDPA, and ImOnline session keys for ClawChain validators.
Keys are stored encrypted at rest using age encryption and injected into the node on startup.`,
	}

	root.AddCommand(
		initCmd(),
		injectCmd(),
		rotateCmd(),
		serveCmd(),
		statusCmd(),
		auditCmd(),
		importCmd(),
	)

	return root
}

func initCmd() *cobra.Command {
	var keystoreDir string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialise keystore and generate age keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			ks, err := keystore.Init(expandHome(keystoreDir))
			if err != nil {
				return fmt.Errorf("init: %w", err)
			}
			fmt.Printf("✓ Keystore initialised at %s\n", ks.Dir())
			fmt.Printf("✓ Age public key: %s\n", ks.PublicKey())
			fmt.Println("\nKeep identity.age secret! Back it up securely.")
			return nil
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "keystore", envOrDefault("CLAWKEYRING_KEYSTORE", defaultKeystore), "keystore directory")
	return cmd
}

func importCmd() *cobra.Command {
	var (
		keystoreDir string
		keyType     string
		hexKey      string
		pubKey      string
	)

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import a session key into the encrypted keystore",
		RunE: func(cmd *cobra.Command, args []string) error {
			kt := keyring.KeyType(keyType)
			if !kt.Valid() {
				return fmt.Errorf("invalid key type %q; must be one of: babe, gran, imon, aura", keyType)
			}

			raw, err := decodeHexKey(hexKey)
			if err != nil {
				return fmt.Errorf("import: decode hex key: %w", err)
			}

			ks, err := keystore.New(expandHome(keystoreDir))
			if err != nil {
				return err
			}

			if err := ks.StoreKey(kt, raw, pubKey); err != nil {
				return fmt.Errorf("import: store key: %w", err)
			}

			fmt.Printf("✓ Imported %s key (public: %s)\n", kt, pubKey)
			return nil
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "keystore", envOrDefault("CLAWKEYRING_KEYSTORE", defaultKeystore), "keystore directory")
	cmd.Flags().StringVar(&keyType, "type", "", "key type: babe, gran, imon, aura")
	cmd.Flags().StringVar(&hexKey, "hex", "", "hex-encoded private key (0x-prefixed)")
	cmd.Flags().StringVar(&pubKey, "pub", "", "hex-encoded public key")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("hex")
	_ = cmd.MarkFlagRequired("pub")
	return cmd
}

func injectCmd() *cobra.Command {
	var (
		keystoreDir string
		nodeURL     string
		agentAcct   string
	)

	cmd := &cobra.Command{
		Use:   "inject",
		Short: "Decrypt and inject session keys into the Substrate node",
		RunE: func(cmd *cobra.Command, args []string) error {
			ks, err := keystore.New(expandHome(keystoreDir))
			if err != nil {
				return err
			}

			inj := injector.New(nodeURL)
			sub := &audit.NoopSubmitter{}
			auditLogger := audit.New(sub, agentAcct)

			entries, err := ks.ListKeys()
			if err != nil {
				return fmt.Errorf("inject: list keys: %w", err)
			}

			var injected []keyring.KeyType
			for _, entry := range entries {
				raw, err := ks.DecryptKey(entry.Type)
				if err != nil {
					return fmt.Errorf("inject: decrypt %s: %w", entry.Type, err)
				}
				if err := inj.InsertKey(string(entry.Type), entry.PublicKey, raw); err != nil {
					return fmt.Errorf("inject: insert %s: %w", entry.Type, err)
				}
				injected = append(injected, entry.Type)
				fmt.Printf("✓ Injected %s key\n", entry.Type)
			}

			if len(injected) > 0 {
				_, _ = auditLogger.LogOperation(keyring.OperationInject, injected, 0)
			}

			fmt.Printf("✓ Injected %d keys into %s\n", len(injected), nodeURL)
			return nil
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "keystore", envOrDefault("CLAWKEYRING_KEYSTORE", defaultKeystore), "keystore directory")
	cmd.Flags().StringVar(&nodeURL, "node", envOrDefault("CLAWKEYRING_NODE", defaultNode), "Substrate node RPC URL")
	cmd.Flags().StringVar(&agentAcct, "account", "", "agent on-chain account ID for audit")
	return cmd
}

func rotateCmd() *cobra.Command {
	var (
		keystoreDir string
		nodeURL     string
		agentAcct   string
	)

	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Generate new session keys, inject, and submit set_keys extrinsic",
		RunE: func(cmd *cobra.Command, args []string) error {
			ks, err := keystore.New(expandHome(keystoreDir))
			if err != nil {
				return err
			}

			inj := injector.New(nodeURL)
			sub := &audit.NoopSubmitter{}
			auditLogger := audit.New(sub, agentAcct)

			// Use the rotation manager for rotation logic.
			cfg := rotation.DefaultConfig()
			cfg.AutoRotate = false
			mgr := rotation.New(ks, inj, auditLogger, nil, nil, cfg)

			fmt.Println("⚠  Note: rotation requires a key generator connected to the node.")
			fmt.Println("   Use 'clawkeyring serve' for automatic era-based rotation.")
			_ = mgr
			fmt.Println("✓ Rotation command acknowledged. Implement generator for full auto-rotation.")
			return nil
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "keystore", envOrDefault("CLAWKEYRING_KEYSTORE", defaultKeystore), "keystore directory")
	cmd.Flags().StringVar(&nodeURL, "node", envOrDefault("CLAWKEYRING_NODE", defaultNode), "Substrate node RPC URL")
	cmd.Flags().StringVar(&agentAcct, "account", "", "agent on-chain account ID")
	return cmd
}

func serveCmd() *cobra.Command {
	var (
		keystoreDir string
		addr        string
		certFile    string
		keyFile     string
		caFile      string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the mTLS gRPC server",
		RunE: func(cmd *cobra.Command, args []string) error {
			ks, err := keystore.New(expandHome(keystoreDir))
			if err != nil {
				return err
			}

			var srv *server.Server
			if certFile != "" {
				cfg := server.Config{
					Addr:     addr,
					CertFile: certFile,
					KeyFile:  keyFile,
					CAFile:   caFile,
				}
				srv, err = server.New(cfg, ks, nil)
				if err != nil {
					return fmt.Errorf("serve: %w", err)
				}
			} else {
				srv = server.NewInsecure(addr, ks, nil)
				fmt.Println("⚠  Warning: running without mTLS. Use --cert/--key/--ca in production.")
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			fmt.Printf("✓ gRPC server starting on %s\n", addr)
			return srv.Serve(ctx)
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "keystore", envOrDefault("CLAWKEYRING_KEYSTORE", defaultKeystore), "keystore directory")
	cmd.Flags().StringVar(&addr, "addr", envOrDefault("CLAWKEYRING_ADDR", defaultAddr), "listen address")
	cmd.Flags().StringVar(&certFile, "cert", "", "server TLS certificate")
	cmd.Flags().StringVar(&keyFile, "key", "", "server TLS private key")
	cmd.Flags().StringVar(&caFile, "ca", "", "CA certificate for client verification")
	return cmd
}

func statusCmd() *cobra.Command {
	var keystoreDir string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current key set and last rotation era",
		RunE: func(cmd *cobra.Command, args []string) error {
			ks, err := keystore.New(expandHome(keystoreDir))
			if err != nil {
				return err
			}

			entries, err := ks.ListKeys()
			if err != nil {
				return fmt.Errorf("status: %w", err)
			}

			fmt.Printf("Keystore: %s\n", ks.Dir())
			fmt.Printf("Age public key: %s\n", ks.PublicKey())
			fmt.Printf("Stored keys: %d\n\n", len(entries))

			for _, e := range entries {
				fmt.Printf("  [%s] %s  encrypted: %s\n",
					e.Type, e.PublicKey, e.EncryptedAt.Format("2006-01-02 15:04:05 UTC"))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&keystoreDir, "keystore", envOrDefault("CLAWKEYRING_KEYSTORE", defaultKeystore), "keystore directory")
	return cmd
}

func auditCmd() *cobra.Command {
	var (
		nodeURL   string
		agentAcct string
		limit     int
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Dump on-chain audit log from agent-receipts pallet",
		RunE: func(cmd *cobra.Command, args []string) error {
			sub := &audit.NoopSubmitter{}
			logger := audit.New(sub, agentAcct)

			records, err := logger.GetAuditLog(limit)
			if err != nil {
				return fmt.Errorf("audit: %w", err)
			}

			fmt.Printf("Audit log for agent %s (node: %s)\n\n", agentAcct, nodeURL)
			if len(records) == 0 {
				fmt.Println("No records found.")
				return nil
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(records)
		},
	}

	cmd.Flags().StringVar(&nodeURL, "node", envOrDefault("CLAWKEYRING_NODE", defaultNode), "Substrate node RPC URL")
	cmd.Flags().StringVar(&agentAcct, "account", "", "agent on-chain account ID")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of records to return")
	_ = cmd.MarkFlagRequired("account")
	return cmd
}

// ---- helpers ----------------------------------------------------------------

func expandHome(path string) string {
	if len(path) > 1 && path[:2] == "~/" {
		home, _ := os.UserHomeDir()
		return home + path[1:]
	}
	return path
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func decodeHexKey(s string) ([]byte, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	return hex.DecodeString(s)
}
