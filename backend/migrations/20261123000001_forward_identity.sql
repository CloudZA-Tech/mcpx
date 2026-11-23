-- Opt-in per server: MCPx forwards a signed caller identity (X-MCPX-Identity) on every proxied
-- call, signed with the server's own secret (credential_type 'identity_secret').
ALTER TABLE servers ADD COLUMN forward_identity BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN servers.forward_identity IS 'Send a signed X-MCPX-Identity header (caller email, org role) to this server';
