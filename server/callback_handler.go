package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/astaxie/beego/session"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

func callbackHandler(sessionManager *session.Manager, config *authConfig) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// set context with http client configured to skipSSL
		ctx := getContext(true)

		// Instantiating the OAuth2 package to exchange the Code for a Token
		conf := &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.CallbackURL,
			Scopes:       []string{"openid", "test.access", "test.admin"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.Domain + "/oauth/authorize",
				TokenURL: config.Domain + "/oauth/token",
			},
		}

		// Getting the Code that we got from Auth0
		e := r.URL.Query().Get("error")
		if len(e) > 0 {
			authError := errors.New(e)
			http.Error(w, authError.Error(), http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		if len(code) == 0 {
			authError := errors.New("Did not receive authcode from IdP")
			http.Error(w, authError.Error(), http.StatusInternalServerError)
			return
		}

		// Exchanging the code for a token
		token, err := conf.Exchange(ctx, code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Getting now the User information
		client := conf.Client(ctx, token)
		resp, err := client.Get(config.Domain + "/userinfo")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Reading the body
		raw, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Unmarshalling the JSON of the Profile
		var profile map[string]interface{}
		if err := json.Unmarshal(raw, &profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Saving the information to the session.
		session, _ := sessionManager.SessionStart(w, r)
		defer session.SessionRelease(w)

		jsonToken, err := tokenToJSON(token)
		if err != nil {
			fmt.Println("ERROR MARHSALING TOKEN TO JSON!")
		}
		session.Set("token", jsonToken)
		session.Set("profile", profile)

		// Redirect to logged in page
		http.Redirect(w, r, "/protected/user", http.StatusMovedPermanently)

	}
}

func getContext(skipSSL bool) (ctx context.Context) {
	ctx = oauth2.NoContext
	if !skipSSL {
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: tr})
	return
}
