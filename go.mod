module lockbox.dev/cmd/authd

// TODO: use real versions of these
replace (
	impractical.co/googleid v0.0.0 => ../../../impractical.co/googleid
	lockbox.dev/accounts v0.0.0 => ../../accounts
	lockbox.dev/clients v0.0.0 => ../../clients
	lockbox.dev/grants v0.0.0 => ../../grants
	lockbox.dev/hmac v0.0.0 => ../../hmac
	lockbox.dev/oauth2 v0.0.0 => ../../oauth2
	lockbox.dev/scopes v0.0.0 => ../../scopes
	lockbox.dev/sessions v0.0.0 => ../../sessions
	lockbox.dev/tokens v0.0.0 => ../../tokens
)

require (
	github.com/coreos/go-oidc v2.0.0+incompatible
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	lockbox.dev/accounts v0.0.0
	lockbox.dev/clients v0.0.0
	lockbox.dev/grants v0.0.0
	lockbox.dev/oauth2 v0.0.0
	lockbox.dev/scopes v0.0.0
	lockbox.dev/sessions v0.0.0
	lockbox.dev/tokens v0.0.0
	yall.in v0.0.1
)
