package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rverton/webanalyze/internal/apikeys"
	_ "modernc.org/sqlite"
)

func runKeysCLI(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, `usage: webanalyze keys <create|list|rotate|revoke|show> [flags]

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

	switch sub {
	case "create":
		return keysCreate(ctx, st, args)
	case "list":
		return keysList(ctx, st, args)
	case "rotate":
		return keysRotate(ctx, st, args)
	case "revoke":
		return keysRevoke(ctx, st, args)
	case "show":
		return keysShow(ctx, st, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		return 2
	}
}

func keysCreate(ctx context.Context, st *apikeys.Store, args []string) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	owner := fs.String("owner", "", "owner label (required)")
	name := fs.String("name", "", "human-readable name (required)")
	rps := fs.Int("rps", 10, "RPS limit")
	daily := fs.Int("daily", 100_000, "daily quota")
	createdBy := fs.String("created-by", os.Getenv("USER"), "creator identity")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: keys create --owner=X --name=Y [--rps=10 --daily=100000]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*owner) == "" || strings.TrimSpace(*name) == "" {
		fs.Usage()
		return 2
	}
	plain, err := apikeys.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	h, err := apikeys.HashSecret(plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	id, err := st.InsertKey(ctx, apikeys.Prefix12(plain), h, strings.TrimSpace(*name), strings.TrimSpace(*owner), strings.TrimSpace(*createdBy), *rps, *daily)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Println(plain)
	fmt.Printf("key_id=%s prefix=%s\n", id, apikeys.Prefix12(plain))
	return 0
}

func keysList(ctx context.Context, st *apikeys.Store, args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	owner := fs.String("owner", "", "filter owner")
	status := fs.String("status", "active", "active | revoked | all")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	row, err := st.ListKeys(ctx, strings.TrimSpace(*owner), strings.TrimSpace(*status))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	for _, k := range row {
		ls := ""
		if k.LastUsedAt != nil {
			ls = k.LastUsedAt.UTC().Format(timeRFC3339)
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n", k.ID, k.Prefix, k.Name, k.Owner, k.Status, k.RPSLimit, k.DailyQuota, ls)
	}
	return 0
}

const timeRFC3339 = "2006-01-02T15:04:05Z07:00"

func keysRotate(ctx context.Context, st *apikeys.Store, args []string) int {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	id := fs.String("id", "", "key ULID")
	createdBy := fs.String("created-by", os.Getenv("USER"), "operator")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: keys rotate --id=<ulid>\n")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*id) == "" {
		fs.Usage()
		return 2
	}
	prev, err := st.GetByID(ctx, strings.TrimSpace(*id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	plain, err := apikeys.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	h, err := apikeys.HashSecret(plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	name := prev.Name + " (rotated)"
	newID, err := st.InsertKey(ctx, apikeys.Prefix12(plain), h, name, prev.Owner, strings.TrimSpace(*createdBy), prev.RPSLimit, prev.DailyQuota)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	_ = st.RevokeKey(ctx, prev.ID, "rotated; replaced by "+newID)
	fmt.Println(plain)
	fmt.Printf("new_key_id=%s old_key_id=%s\n", newID, prev.ID)
	return 0
}

func keysRevoke(ctx context.Context, st *apikeys.Store, args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	id := fs.String("id", "", "key ULID")
	reason := fs.String("reason", "", "revocation note")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*id) == "" {
		fmt.Fprintln(os.Stderr, "usage: keys revoke --id=<ulid> --reason=text")
		return 2
	}
	if err := st.RevokeKey(ctx, strings.TrimSpace(*id), strings.TrimSpace(*reason)); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Println("ok")
	return 0
}

func keysShow(ctx context.Context, st *apikeys.Store, args []string) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	id := fs.String("id", "", "key ULID")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*id) == "" {
		fmt.Fprintln(os.Stderr, "usage: keys show --id=<ulid>")
		return 2
	}
	k, err := st.GetByID(ctx, strings.TrimSpace(*id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	ls := ""
	if k.LastUsedAt != nil {
		ls = k.LastUsedAt.UTC().Format(timeRFC3339)
	}
	fmt.Printf(`id=%s
prefix=%s
name=%s
owner=%s
status=%s
rps_limit=%d
daily_quota=%d
created_at=%s
last_used_at=%s
`,
		k.ID, k.Prefix, k.Name, k.Owner, k.Status, k.RPSLimit, k.DailyQuota,
		k.CreatedAt.UTC().Format(timeRFC3339), ls)
	hashRedacted := k.Hash[:min(14, len(k.Hash))]
	fmt.Printf("hash_prefix=%s... (argon2id hash redacted)\n", hashRedacted)
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
