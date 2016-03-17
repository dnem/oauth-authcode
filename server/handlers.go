package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"text/template"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/astaxie/beego/session"
)

var homeTemplate = `
<html>
  <head>
    <title>OAuth Authcode Sample</title>
  </head>
  <body>
    <h2>Welcome to the OAuth Authcode Home Page</h2>
    <p>We don't know who you are.  Please <a href="{{.Domain}}/oauth/authorize?client_id={{.ClientID}}&redirect_uri={{.CallbackURL}}&response_type=code">log in</a>.
  </body>
</html>
`

func homeHandler(config *authConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t := template.Must(template.New("html").Parse(homeTemplate))
		t.Execute(w, config)
	}
}

func accessHandler(sessionManager *session.Manager) http.HandlerFunc {

	//TODO: Check scope

	return func(w http.ResponseWriter, r *http.Request) {

		session, _ := sessionManager.SessionStart(w, r)
		defer session.SessionRelease(w)

		// Getting the profile from the session
		profile := session.Get("profile")

		//TODO: Do something compelling with profile data (html template?)
		fmt.Fprintf(w, "USER DATA: %+v", profile)
	}
}

func adminHandler(sessionManager *session.Manager) http.HandlerFunc {

	//TODO: Check scope

	return func(w http.ResponseWriter, r *http.Request) {

		session, _ := sessionManager.SessionStart(w, r)
		defer session.SessionRelease(w)

		// Getting the profile from the session
		profile := session.Get("profile")

		//TODO: Do something compelling with profile data (html template?)
		fmt.Fprintf(w, "USER DATA: %+v", profile)
	}
}

func callbackHandler(sessionManager *session.Manager, config *authConfig) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("\nCALLBACK INVOKED BY IdP: %+v\n\n", r)

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		ctx := oauth2.NoContext
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: tr})

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
		// We're using https://github.com/astaxie/beego/tree/master/session
		// The GlobalSessions variable is initialized in another file
		// Check https://github.com/auth0/auth0-golang/blob/master/examples/regular-web-app/app/app.go
		session, _ := sessionManager.SessionStart(w, r)
		defer session.SessionRelease(w)

		session.Set("id_token", token.Extra("id_token"))
		session.Set("access_token", token.AccessToken)
		session.Set("profile", profile)

		// Redirect to logged in page
		http.Redirect(w, r, "/protected/access", http.StatusMovedPermanently)

	}
}
