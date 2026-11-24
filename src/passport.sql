-- Passport 006: application-owned identity registry, no automatic email matching.
CREATE SCHEMA passport;
CREATE TABLE passport.members (
 app text NOT NULL, issuer text NOT NULL, subject text NOT NULL, principal uuid NOT NULL,
 scopes text[] NOT NULL, active boolean NOT NULL DEFAULT true,
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 PRIMARY KEY(app,issuer,subject)
);
CREATE TABLE passport.sessions (
 app text NOT NULL, token_hash text NOT NULL CHECK(token_hash ~ '^[A-Za-z0-9_-]{43}$'),
 issuer text NOT NULL, subject text NOT NULL, membership_revision integer NOT NULL,
 expires_at timestamptz NOT NULL, revoked_at timestamptz,
 PRIMARY KEY(app,token_hash),
 FOREIGN KEY(app,issuer,subject) REFERENCES passport.members(app,issuer,subject)
);
CREATE TABLE passport.flows (
 app text NOT NULL, state_hash text NOT NULL, browser_hash text NOT NULL,
 sealed text NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz,
 PRIMARY KEY(app,state_hash)
);
CREATE TABLE passport.invitations (
 app text NOT NULL, code_hash text NOT NULL, issuer text NOT NULL, subject text NOT NULL,
 principal uuid NOT NULL, scopes text[] NOT NULL, invited_by uuid NOT NULL,
 expires_at timestamptz NOT NULL, consumed_at timestamptz,
 PRIMARY KEY(app,code_hash)
);
CREATE FUNCTION passport.accept_invitation(p_app text,p_hash text,p_issuer text,p_subject text) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE inv passport.invitations%ROWTYPE;
BEGIN
 SELECT * INTO inv FROM passport.invitations WHERE app=p_app AND code_hash=p_hash AND issuer=p_issuer AND subject=p_subject AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO passport.members(app,issuer,subject,principal,scopes) VALUES(inv.app,inv.issuer,inv.subject,inv.principal,inv.scopes) ON CONFLICT DO NOTHING;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE passport.invitations SET consumed_at=clock_timestamp() WHERE app=p_app AND code_hash=p_hash;
 RETURN true;
END;
$$;
