package db

import (
	"database/sql"
	"time"
)

// Session account types. AccountID is the account's primary key in its table:
// new_org_users.email for users, new_admins.did for admins (admin rows often
// have no email).
const (
	SessionAccountUser  = "user"
	SessionAccountAdmin = "admin"
)

// SessionRecord is one login. Only the SHA-256 hash of the session token is
// stored, so a leaked sessions table hands out no usable tokens.
type SessionRecord struct {
	TokenHash   string
	AccountType string
	AccountID   string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
}

func (d *DB) CreateSession(tokenHash, accountType, accountID, ip, userAgent string, expiresAt time.Time) error {
	_, err := d.conn.Exec(`
		INSERT INTO sessions (token_hash, account_type, account_id, ip, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		tokenHash, accountType, accountID, ip, userAgent, expiresAt,
	)
	return err
}

// GetActiveSession returns the session for tokenHash, or sql.ErrNoRows when
// it does not exist or has expired.
func (d *DB) GetActiveSession(tokenHash string) (*SessionRecord, error) {
	s := &SessionRecord{}
	err := d.conn.QueryRow(`
		SELECT token_hash, account_type, account_id, created_at, last_seen_at, expires_at
		FROM sessions WHERE token_hash = $1 AND expires_at > NOW()`,
		tokenHash,
	).Scan(&s.TokenHash, &s.AccountType, &s.AccountID, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// TouchSession bumps last_seen_at, at most once every 5 minutes per session
// so busy dashboards don't write on every request.
func (d *DB) TouchSession(tokenHash string) error {
	_, err := d.conn.Exec(`
		UPDATE sessions SET last_seen_at = NOW()
		WHERE token_hash = $1 AND last_seen_at < NOW() - INTERVAL '5 minutes'`,
		tokenHash,
	)
	return err
}

func (d *DB) DeleteSession(tokenHash string) error {
	_, err := d.conn.Exec(`DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteAccountSessions revokes every session of one account, except
// exceptTokenHash when it is non-empty (keeps the caller's own session alive).
func (d *DB) DeleteAccountSessions(accountType, accountID, exceptTokenHash string) (int64, error) {
	res, err := d.conn.Exec(`
		DELETE FROM sessions
		WHERE account_type = $1 AND account_id = $2 AND token_hash <> $3`,
		accountType, accountID, exceptTokenHash,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) DeleteExpiredSessions() error {
	_, err := d.conn.Exec(`DELETE FROM sessions WHERE expires_at <= NOW()`)
	return err
}

// renameUserSessions keeps an org user's sessions attached after their email
// (the user's account ID) changes. Runs inside the email-update transaction.
func renameUserSessions(tx *sql.Tx, currentEmail, newEmail string) error {
	_, err := tx.Exec(
		`UPDATE sessions SET account_id = $1 WHERE account_type = $2 AND account_id = $3`,
		newEmail, SessionAccountUser, currentEmail,
	)
	return err
}

// EnsureAdmin creates the new_admins row for an admin the admin server has
// just authenticated, on their first dashboard login. An existing row for the
// DID is left untouched, so concurrent first logins are safe.
func (d *DB) EnsureAdmin(did, orgID, apiKey, name string) error {
	_, err := d.conn.Exec(
		`INSERT INTO new_admins (did, organization_id, api_key, name, email)
		 VALUES ($1, $2, $3, $4, '') ON CONFLICT (did) DO NOTHING`,
		did, orgID, apiKey, name,
	)
	return err
}

// SetAdminName records the admin server username an admin just logged in
// with. It is what /update-password and /reset-password send to the admin
// server, so it is refreshed on every login: rows made by scripts/add_admin.py
// have none, and older rows may hold a display name set before admin names
// became read-only.
func (d *DB) SetAdminName(did, name string) error {
	_, err := d.conn.Exec(
		`UPDATE new_admins SET name = $1 WHERE did = $2 AND COALESCE(name, '') <> $1`, name, did,
	)
	return err
}
