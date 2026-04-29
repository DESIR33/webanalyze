package apikeys

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// BootstrapFromEnv inserts the first API key from plaintext WA_BOOTSTRAP_API_KEY when the table is empty.
func BootstrapFromEnv(ctx context.Context, st *Store, plaintext, owner, name, createdBy string) error {
	if strings.TrimSpace(plaintext) == "" {
		return nil
	}
	n, err := st.CountKeys(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if err := ValidateFormat(plaintext); err != nil {
		return fmt.Errorf("WA_BOOTSTRAP_API_KEY: %w", err)
	}
	hash, err := HashSecret(plaintext)
	if err != nil {
		return err
	}
	pref := Prefix12(plaintext)
	_, err = st.InsertKey(ctx, pref, hash, name, owner, createdBy, 20, 200_000)
	return err
}

// ErrBootstrapEmpty is returned when there are no keys and bootstrap env is absent.
var ErrBootstrapEmpty = errors.New("no api keys and bootstrap not configured")
