package apiv1

import (
	"net/http"
	"strings"

	accountsv1 "impractical.co/auth/accounts/apiv1"
	scopesv1 "impractical.co/auth/scopes/apiv1"
)

type APIv1 struct {
	Accounts accountsv1.APIv1
	Scopes   scopesv1.APIv1
}

func (a APIv1) Server(baseURL string) http.Handler {
	mux := http.NewServeMux()
	baseURL = strings.TrimSuffix(baseURL, "/")

	accountsHandler := a.Accounts.Server(baseURL + "/accounts")
	mux.Handle(baseURL+"/accounts/", accountsHandler)
	mux.Handle(baseURL+"/accounts", accountsHandler)

	scopesHandler := a.Scopes.Server(baseURL + "/scopes")
	mux.Handle(baseURL+"/scopes/", scopesHandler)
	mux.Handle(baseURL+"/scopes", scopesHandler)

	return mux
}
