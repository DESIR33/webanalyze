package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rverton/webanalyze/internal/apikeys"
	"github.com/rverton/webanalyze/internal/asyncjobs"
	_ "modernc.org/sqlite"
)

func runSecretsCLI(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, `usage: webanalyze secrets <create|list|rotate|revoke> [flags]

Environment:
  WA_DB_PATH           SQLite db file (development)
  WA_DATABASE_URL      Postgres DSN (takes precedence)

`)
		return 2
	}
	sub := args[0]
	args = args[1:]
	ctx := context.Background()
	st, err := apikeys.OpenStore(ctx, os.Getenv("WA_DB_PATH"), os.Getenv("WA_DATABASE_URL"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "db: %v\n", err)
		return 1
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return 1
	}
	if err := asyncjobs.Migrate(ctx, st.DB(), st.Postgres()); err != nil {
		fmt.Fprintf(os.Stderr, "migrate jobs: %v\n", err)
		return 1
	}
	js := asyncjobs.NewStore(st.DB(), st.Postgres())

	switch sub {
	case "create":
		return secretsCreate(ctx, js, st, args)
	case "list":
		return secretsList(ctx, js, args)
	case "rotate":
		return secretsRotate(ctx, js, args)
	case "revoke":
		return secretsRevoke(ctx, js, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		return 2
	}
}

func secretsCreate(ctx context.Context, js *asyncjobs.Store, keyStore *apikeys.Store, args []string) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	keyID := fs.String("api-key-id", "", "API key id holding this secret (required)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: secrets create --api-key-id=<id>\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*keyID) == "" {
		fs.Usage()
		return 2
	}
	if _, err := keyStore.GetByID(ctx, strings.TrimSpace(*keyID)); err != nil {
		fmt.Fprintf(os.Stderr, "api key: %v\n", err)
		return 1
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	plain := hex.EncodeToString(raw)
	id, err := js.InsertWebhookSecret(ctx, strings.TrimSpace(*keyID), plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Println(plain)
	fmt.Printf("signing_secret_id=%s\n", id)
	return 0
}

func secretsList(ctx context.Context, js *asyncjobs.Store, args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	keyID := fs.String("api-key-id", "", "optional filter")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rows, err := js.ListWebhookSecrets(ctx, strings.TrimSpace(*keyID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	for _, r := range rows {
		rot := ""
		if r.RotatedAt.Valid {
			rot = r.RotatedAt.Time.UTC().Format(timeRFC3339)
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", r.ID, r.Status, r.CreatedAt.UTC().Format(timeRFC3339), rot)
	}
	return 0
}

func secretsRotate(ctx context.Context, js *asyncjobs.Store, args []string) int {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	keyID := fs.String("api-key-id", "", "required")
	oldID := fs.String("id", "", "secret id to rotate from")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: secrets rotate --api-key-id=<key> --id=<wsec_...>\n")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*keyID) == "" || strings.TrimSpace(*oldID) == "" {
		fs.Usage()
		return 2
	}
	if err := js.RotateWebhookSecret(ctx, strings.TrimSpace(*keyID), strings.TrimSpace(*oldID)); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return 1
	}
	plain := hex.EncodeToString(raw)
	newID, err := js.InsertWebhookSecret(ctx, strings.TrimSpace(*keyID), plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Println(plain)
	fmt.Printf("signing_secret_id=%s (old %s marked rotated)\n", newID, strings.TrimSpace(*oldID))
	return 0
}

func secretsRevoke(ctx context.Context, js *asyncjobs.Store, args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	keyID := fs.String("api-key-id", "", "required")
	id := fs.String("id", "", "secret id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*keyID) == "" || strings.TrimSpace(*id) == "" {
		fmt.Fprintln(os.Stderr, "usage: secrets revoke --api-key-id=<key> --id=<wsec_...>")
		return 2
	}
	if err := js.RevokeWebhookSecret(ctx, strings.TrimSpace(*keyID), strings.TrimSpace(*id)); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Println("ok")
	return 0
}
