package main

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	oidc "github.com/coreos/go-oidc"
	jwt "github.com/dgrijalva/jwt-go"
	yall "yall.in"
	"yall.in/colour"

	"lockbox.dev/accounts"
	accountsv1 "lockbox.dev/accounts/apiv1"
	accountsPostgres "lockbox.dev/accounts/storers/postgres"
	clientsPostgres "lockbox.dev/clients/storers/postgres"
	"lockbox.dev/cmd/lockbox-apid/apiv1"
	"lockbox.dev/grants"
	grantsPostgres "lockbox.dev/grants/storers/postgres"
	"lockbox.dev/oauth2"
	"lockbox.dev/scopes"
	scopesv1 "lockbox.dev/scopes/apiv1"
	scopesPostgres "lockbox.dev/scopes/storers/postgres"
	"lockbox.dev/sessions"
	"lockbox.dev/tokens"
	tokensPostgres "lockbox.dev/tokens/storers/postgres"
)

func pathOrContents(in string) (string, error) {
	if _, err := os.Stat(in); err == nil {
		contents, err := ioutil.ReadFile(in)
		if err != nil {
			return string(contents), err
		}
		return string(contents), nil
	}
	return in, nil
}

func main() {
	ctx := context.Background()
	log := yall.New(colour.New(os.Stdout, yall.Debug))

	// TODO: vault integration, pull postgres connstring, JWT private key out of Vault

	connString := os.Getenv("PG_DB")
	if connString == "" {
		log.Error("PG_DB must be set")
		os.Exit(1)
	}
	pg, err := sql.Open("postgres", connString)

	privateKeyStr := os.Getenv("JWT_PRIVATE_KEY")
	if privateKeyStr == "" {
		log.Error("JWT_PRIVATE_KEY must be set to the path or contents of the RSA private key to sign JWTs with.")
		os.Exit(1)
	}
	privateKeyStr, err = pathOrContents(privateKeyStr)
	if err != nil {
		log.WithError(err).Error("Error loading private key")
		os.Exit(1)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyStr))
	if err != nil {
		log.WithError(err).Error("Error parsing private key")
		os.Exit(1)
	}

	googleClientIDsStr := os.Getenv("GOOGLE_CLIENT_IDS")
	if googleClientIDsStr == "" {
		log.Error("GOOGLE_CLIENT_IDS must be set to the client IDs to accept Google ID tokens for, comma separated")
		os.Exit(1)
	}
	googleClientIDs := strings.Split(googleClientIDsStr, ",")

	sess := sessions.Dependencies{
		JWTPrivateKey: privateKey,
		JWTPublicKey:  privateKey.Public().(*rsa.PublicKey),
		ServiceID:     "https://test.lockbox.dev",
	}

	acctsv1 := accountsv1.APIv1{
		Dependencies: accounts.Dependencies{
			Storer: accountsPostgres.NewStorer(ctx, pg),
		},
		Log:      log,
		Sessions: sess,
	}

	scopsv1 := scopesv1.APIv1{
		Log: log,
		Dependencies: scopes.Dependencies{
			Storer: scopesPostgres.NewStorer(ctx, pg),
		},
	}

	oauthProvider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		log.WithError(err).Error("Error setting up Google ID token provider")
		os.Exit(1)
	}

	oauth := oauth2.Service{
		GoogleIDVerifier: oauthProvider.Verifier(&oidc.Config{
			SkipClientIDCheck: true,
		}),
		GoogleClients:  googleClientIDs,
		TokenExpiresIn: 3600,
		Accounts:       acctsv1.Dependencies,
		Clients:        clientsPostgres.NewStorer(ctx, pg),
		Scopes:         scopsv1.Dependencies,
		Grants: grants.Dependencies{
			Storer: grantsPostgres.NewStorer(ctx, pg),
		},
		Refresh: tokens.Dependencies{
			Storer:        tokensPostgres.NewStorer(ctx, pg),
			JWTPrivateKey: privateKey,
			JWTPublicKey:  privateKey.Public().(*rsa.PublicKey),
			ServiceID:     "https://id-test.impractical.services",
		},
		Log: log,
	}

	v1 := apiv1.APIv1{
		Accounts: acctsv1,
		Scopes:   scopsv1,
		OAuth2:   oauth,
		Log:      log,
		Sessions: sess,
	}
	http.Handle("/", v1.Server(""))
	err = http.ListenAndServe(":12345", nil)
	if err != nil {
		log.WithError(err).Error("error starting server")
	}
}
