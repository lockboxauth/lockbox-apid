module impractical.co/auth/cmd/authd

replace (
	// TODO: use real versions of these
	impractical.co/auth/accounts v0.0.0 => ../../accounts
	impractical.co/auth/clients v0.0.0 => ../../clients
	impractical.co/auth/grants v0.0.0 => ../../grants
	impractical.co/auth/hmac v0.0.0 => ../../hmac
	impractical.co/auth/oauth2 v0.0.0 => ../../oauth2
	impractical.co/auth/scopes v0.0.0 => ../../scopes
	impractical.co/auth/sessions v0.0.0 => ../../sessions
	impractical.co/auth/tokens v0.0.0 => ../../tokens
	impractical.co/googleid v0.0.0 => ../../../googleid
)

require (
	github.com/coreos/go-oidc v2.0.0+incompatible
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	impractical.co/auth/accounts v0.0.0
	impractical.co/auth/clients v0.0.0
	impractical.co/auth/grants v0.0.0
	impractical.co/auth/oauth2 v0.0.0
	impractical.co/auth/scopes v0.0.0
	impractical.co/auth/sessions v0.0.0
	impractical.co/auth/tokens v0.0.0
	yall.in v0.0.1
)
