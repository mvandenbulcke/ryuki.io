-- Login-CSRF / session-swapping defense for the OIDC auth-code flow.
--
-- `binding` is a per-browser CSRF token: the login-initiation handler stores it
-- here AND sets it as the HttpOnly `oidc_login_csrf` cookie on the initiating
-- browser. The callback handler redeems a state only when that cookie matches
-- this column, so a `state` an attacker obtained from their own flow cannot be
-- replayed in a victim's browser to mint a session for the attacker's account.
--
-- DEFAULT '' lets any in-flight (pre-migration) rows satisfy NOT NULL; they
-- expire within 10 minutes and the empty binding will never match a real cookie.
ALTER TABLE oidc_login_states
    ADD COLUMN IF NOT EXISTS binding TEXT NOT NULL DEFAULT '';
