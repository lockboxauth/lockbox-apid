package main

import (
	"context"
	"crypto/rsa"
	"database/sql"
	hTmpl "html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	textTmpl "text/template"
	"time"

	oidc "github.com/coreos/go-oidc"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mailgun/mailgun-go"
	"impractical.co/credentials/envvar"
	yall "yall.in"
	"yall.in/colour"

	"lockbox.dev/accounts"
	accountsv1 "lockbox.dev/accounts/apiv1"
	accountsPostgres "lockbox.dev/accounts/storers/postgres"
	clientsv1 "lockbox.dev/clients/apiv1"
	clientsPostgres "lockbox.dev/clients/storers/postgres"
	"lockbox.dev/cmd/lockbox-apid/apiv1"
	"lockbox.dev/grants"
	grantsPostgres "lockbox.dev/grants/storers/postgres"
	"lockbox.dev/hmac"
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

	// TODO: use gcp.Credentials instead, for encrypted credentials stored in GCP
	connString, err := envvar.Credentials{}.Get(ctx, "PG_DB")
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	pg, err := sql.Open("postgres", string(connString))
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	privateKeyInput, err := envvar.Credentials{}.Get(ctx, "JWT_PRIVATE_KEY")
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	privateKeyStr, err := pathOrContents(string(privateKeyInput))
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

	mailgunAPIKey := os.Getenv("MAILGUN_API_KEY")
	if mailgunAPIKey == "" {
		log.Error("MAILGUN_API_KEY must be set to an API key for Mailgun")
		os.Exit(1)
	}

	hmacSecret := os.Getenv("CLIENTS_SECRET")
	if hmacSecret == "" {
		log.Error("CLIENTS_SECRET must be set to a secret key for client registration")
		os.Exit(1)
	}

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

	clients1 := clientsv1.APIv1{
		Storer: clientsPostgres.NewStorer(ctx, pg),
		Log:    log,
		Signer: hmac.Signer{
			MaxSkew: time.Hour,
			OrgKey:  "LOCKBOXTEST",
			Key:     "lockbox-test",
			Secret:  []byte(hmacSecret),
		},
	}

	oauthProvider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		log.WithError(err).Error("Error setting up Google ID token provider")
		os.Exit(1)
	}

	plainTextTmpl := textTmpl.Must(textTmpl.New("body").Parse(`Please click this link to log in: {{.Code}}`))
	htmlTmpl := hTmpl.Must(hTmpl.New("body").Parse(`<html><body><p>Please click this link to log in <a href="{{.Code}}">{{.Code}}</a>.</p></body></html>`))
	oauth := oauth2.Service{
		GoogleIDVerifier: oauthProvider.Verifier(&oidc.Config{
			SkipClientIDCheck: true,
		}),
		GoogleClients:  googleClientIDs,
		TokenExpiresIn: 3600,
		Accounts:       acctsv1.Dependencies,
		Clients:        clients1.Storer,
		Grants: grants.Dependencies{
			Storer: grantsPostgres.NewStorer(ctx, pg),
		},
		Refresh: tokens.Dependencies{
			Storer:        tokensPostgres.NewStorer(ctx, pg),
			JWTPrivateKey: privateKey,
			JWTPublicKey:  privateKey.Public().(*rsa.PublicKey),
			ServiceID:     "https://test.lockbox.dev",
		},
		Scopes:   scopsv1.Dependencies,
		Sessions: sess,
		Log:      log,
		Emailer: oauth2.Mailgun{
			From:          "lockbox.dev testing <test@mg.lockbox.dev>",
			Subject:       "Your lockbox.dev login link",
			PlainTextTmpl: plainTextTmpl,
			HTMLTmpl:      htmlTmpl,
			Client:        mailgun.NewMailgun("mg.lockbox.dev", mailgunAPIKey),
		},
	}

	v1 := apiv1.APIv1{
		Accounts: acctsv1,
		Clients:  clients1,
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
