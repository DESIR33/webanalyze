package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rverton/webanalyze/internal/apikeys"
	"github.com/rverton/webanalyze/internal/asyncjobs"
	_ "modernc.org/sqlite"
)

func runJobsCLI(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, `usage: webanalyze jobs <cancel|show> [flags]

Environment:
  WA_DB_PATH           SQLite db file
  WA_DATABASE_URL      Postgres DSN

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
	case "cancel":
		return jobsCancel(ctx, js, args)
	case "show":
		return jobsShow(ctx, js, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		return 2
	}
}

func jobsCancel(ctx context.Context, js *asyncjobs.Store, args []string) int {
	fs := flag.NewFlagSet("cancel", flag.ContinueOnError)
	id := fs.String("id", "", "job id job_...")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*id) == "" {
		fmt.Fprintln(os.Stderr, "usage: jobs cancel --id=job_...")
		return 2
	}
	j, err := js.GetJob(ctx, strings.TrimSpace(*id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if j.Status == asyncjobs.StatusQueued {
		if err := js.MarkCancelledQueued(ctx, j.ID, time.Now().UTC()); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		fmt.Println("cancelled (queued)")
		return 0
	}
	if j.Status == asyncjobs.StatusRunning {
		_ = js.MarkCancelRunningUndeliverable(ctx, j.ID)
		fmt.Println("marked non-deliverable (running)")
		return 0
	}
	fmt.Fprintf(os.Stderr, "job not in cancellable state: %s\n", j.Status)
	return 1
}

func jobsShow(ctx context.Context, js *asyncjobs.Store, args []string) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	id := fs.String("id", "", "job id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*id) == "" {
		fmt.Fprintln(os.Stderr, "usage: jobs show --id=job_...")
		return 2
	}
	j, err := js.GetJob(ctx, strings.TrimSpace(*id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Printf("id=%s\napi_key_id=%s\nstatus=%s\nattempts=%d\ndelivery=%s\nsubmitted=%s\n",
		j.ID, j.APIKeyID, j.Status, j.Attempts, j.DeliveryStatus, j.SubmittedAt.UTC().Format(timeRFC3339))
	return 0
}
