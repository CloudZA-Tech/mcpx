-- One identity secret per server. Keep the newest if duplicates exist (from concurrent
-- rotations before this index), then let the database enforce it.
DELETE FROM credentials a
USING credentials b
WHERE a.credential_type = 'identity_secret'
  AND b.credential_type = 'identity_secret'
  AND a.server_id = b.server_id
  AND (a.created_at, a.id) < (b.created_at, b.id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_one_identity_secret
    ON credentials (server_id)
    WHERE credential_type = 'identity_secret';
