package keystore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

const DBFileName = "totally_not_my_privateKeys.db"

type DBStore struct {
	db *sql.DB
}

type KeyRow struct {
	KID       int64
	Private   *rsa.PrivateKey
	ExpiresAt time.Time
}

func NewDBStore(dbPath string) (*DBStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	s := &DBStore{db: db}
	if err := s.initSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.ensureSeedKeys(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *DBStore) Close() error { return s.db.Close() }

func (s *DBStore) initSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)`)
	return err
}

// Ensure at least:
// - 1 expired key (exp <= now)
// - 1 valid key (exp >= now + 1 hour)
func (s *DBStore) ensureSeedKeys(ctx context.Context) error {
	now := time.Now().UTC().Unix()

	var validCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys WHERE exp > ?`, now).Scan(&validCount); err != nil {
		return err
	}
	if validCount == 0 {
		// valid for 24h (>= 1h requirement)
		if _, err := s.insertGeneratedKey(ctx, now+24*3600); err != nil {
			return err
		}
	}

	var expiredCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys WHERE exp <= ?`, now).Scan(&expiredCount); err != nil {
		return err
	}
	if expiredCount == 0 {
		// expired 24h ago
		if _, err := s.insertGeneratedKey(ctx, now-24*3600); err != nil {
			return err
		}
	}

	return nil
}

func (s *DBStore) insertGeneratedKey(ctx context.Context, expUnix int64) (int64, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return 0, err
	}

	// Serialize to PKCS#1 PEM stored in BLOB
	der := x509.MarshalPKCS1PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	res, err := s.db.ExecContext(ctx, `INSERT INTO keys(key, exp) VALUES(?, ?)`, pemBytes, expUnix)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetSigningKey returns one key from DB depending on expired flag.
func (s *DBStore) GetSigningKey(ctx context.Context, expired bool) (KeyRow, error) {
	now := time.Now().UTC().Unix()

	var row *sql.Row
	if expired {
		row = s.db.QueryRowContext(ctx, `SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1`, now)
	} else {
		row = s.db.QueryRowContext(ctx, `SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1`, now)
	}

	var kid int64
	var keyBytes []byte
	var expUnix int64
	if err := row.Scan(&kid, &keyBytes, &expUnix); err != nil {
		return KeyRow{}, err
	}

	priv, err := parseRSAPrivateKeyPEM(keyBytes)
	if err != nil {
		return KeyRow{}, err
	}

	return KeyRow{KID: kid, Private: priv, ExpiresAt: time.Unix(expUnix, 0).UTC()}, nil
}

// GetValidKeys returns all keys with exp > now.
func (s *DBStore) GetValidKeys(ctx context.Context) ([]KeyRow, error) {
	now := time.Now().UTC().Unix()

	rows, err := s.db.QueryContext(ctx, `SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []KeyRow
	for rows.Next() {
		var kid int64
		var keyBytes []byte
		var expUnix int64
		if err := rows.Scan(&kid, &keyBytes, &expUnix); err != nil {
			return nil, err
		}
		priv, err := parseRSAPrivateKeyPEM(keyBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, KeyRow{KID: kid, Private: priv, ExpiresAt: time.Unix(expUnix, 0).UTC()})
	}
	return out, rows.Err()
}

func parseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
