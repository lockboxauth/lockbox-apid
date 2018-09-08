package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"

	"impractical.co/auth/accounts"
	accountsv1 "impractical.co/auth/accounts/apiv1"
	accountsStorers "impractical.co/auth/accounts/storers"

	"impractical.co/auth/scopes"
	scopesv1 "impractical.co/auth/scopes/apiv1"
	scopesStorers "impractical.co/auth/scopes/storers"

	"impractical.co/auth/authd/apiv1"

	"impractical.co/auth/sessions"

	yall "yall.in"
	"yall.in/colour"
)

func main() {
	ctx := context.Background()
	log := yall.New(colour.New(os.Stdout, yall.Debug))

	connString := os.Getenv("PG_DB")
	if connString == "" {
		log.Error("PG_DB must be set")
		os.Exit(1)
	}
	pg, err := sql.Open("postgres", connString)

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Error("JWT_SECRET must be set")
		os.Exit(1)
	}

	acctsv1 := accountsv1.APIv1{
		Dependencies: accounts.Dependencies{
			Storer: accountsStorers.NewPostgres(ctx, pg),
		},
		Log: log,
		Sessions: sessions.Dependencies{
			JWTSecret: jwtSecret,
		},
	}

	scopsv1 := scopesv1.APIv1{
		Log: log,
		Dependencies: scopes.Dependencies{
			Storer: scopesStorers.NewPostgres(ctx, pg),
		},
	}

	v1 := apiv1.APIv1{
		Accounts: acctsv1,
		Scopes:   scopsv1,
	}
	http.Handle("/v1/", v1.Server("/v1"))
	err = http.ListenAndServe(":12345", nil)
	if err != nil {
		log.WithError(err).Error("error starting server")
	}
}
