package apiv1

import (
	"net/http"
	"strings"

	"darlinggo.co/trout/v2"
	accountsv1 "lockbox.dev/accounts/apiv1"
	clientsv1 "lockbox.dev/clients/apiv1"
	"lockbox.dev/oauth2"
	scopesv1 "lockbox.dev/scopes/apiv1"
	"lockbox.dev/sessions"
	yall "yall.in"
)

type APIv1 struct {
	Accounts accountsv1.APIv1
	Clients  clientsv1.APIv1
	OAuth2   oauth2.Service
	Scopes   scopesv1.APIv1
	Sessions sessions.Dependencies
	Log      *yall.Logger
}

func (a APIv1) logInRequest(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := a.Log.WithRequest(r)
		r = r.WithContext(yall.InContext(r.Context(), log))
		h.ServeHTTP(w, r)
	})
}

func (a APIv1) tokenInContext(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := yall.FromContext(r.Context())
		auth := r.Header.Get("Authorization")
		if auth != "" && strings.HasPrefix(auth, "Bearer ") {
			tok, err := a.Sessions.TokenFromRequest(r)
			if tok != nil {
				log = log.WithField("jwt.id", tok.ID).
					WithField("jwt.created_from",
						tok.CreatedFrom).
					WithField("jwt.scopes", tok.Scopes).
					WithField("jwt.profile_id",
						tok.ProfileID).
					WithField("jwt.client_id",
						tok.ClientID).
					WithField("jwt.created_at",
						tok.CreatedAt)
				ctx := yall.InContext(r.Context(), log)
				ctx = sessions.InContext(ctx, tok)
				r = r.WithContext(ctx)
			} else if err != nil {
				log.WithError(err).
					Error("error reading access token")
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (a APIv1) Server(baseURL string) http.Handler {
	var router trout.Router
	router.SetPrefix(baseURL)

	accountsHandler := a.Accounts.Server(baseURL + "/accounts/v1")
	router.Prefix("/accounts/v1/").Handler(accountsHandler)

	scopesHandler := a.Scopes.Server(baseURL + "/scopes/v1")
	router.Prefix("/scopes/v1/").Handler(scopesHandler)

	oauth2Handler := a.OAuth2.Server(baseURL + "/oauth2/v1")
	router.Prefix("/oauth2/v1/").Handler(oauth2Handler)

	clientsHandler := a.Clients.Server(baseURL + "/clients/v1")
	router.Prefix("/clients/v1/").Handler(clientsHandler)

	return a.logInRequest(a.tokenInContext(router))
}
