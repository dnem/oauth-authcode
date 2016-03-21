package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"golang.org/x/oauth2"

	"github.com/astaxie/beego/session"
	"github.com/cloudfoundry-community/go-cfenv"
	"github.com/cloudnativego/cf-tools"
)

type authConfig struct {
	ClientID     string
	ClientSecret string
	Domain       string
	CallbackURL  string
	TokenKeyURL  string
	tokenKey     string
	Errors       []error
}

type keyObject struct {
	// Alg is the encryption algorithm
	Alg string `json:"alg"`
	// Value is the actual pem-encoded key used to parse JWT tokens
	Value string `json:"value"`
	// Kty
	Kty string `json:"kty,omitempty"`
	// Use
	Use string `json:"use,omitempty"`
	// N
	N string `json:"n,omitempty"`
	// E
	E string `json:"e,omitempty"`
}

func initOAuthConfig(appEnv *cfenv.App) (config *authConfig) {
	config = &authConfig{}

	authClientID, err := cftools.GetVCAPServiceProperty("sso", "client_id", appEnv)
	config.appendError(err)
	authSecret, err := cftools.GetVCAPServiceProperty("sso", "client_secret", appEnv)
	config.appendError(err)
	authDomain, err := cftools.GetVCAPServiceProperty("sso", "auth_domain", appEnv)
	config.appendError(err)

	authCallback := os.Getenv("AUTH_CALLBACK")
	if len(authCallback) == 0 {
		err = errors.New("Could not retrieve callback url from environment.")
		config.appendError(err)
	}

	tokenKeyURL := fmt.Sprintf("%s/token_key", authDomain)

	config.ClientID = authClientID
	config.ClientSecret = authSecret
	config.Domain = authDomain
	config.CallbackURL = authCallback
	config.TokenKeyURL = tokenKeyURL

	return
}

func (ac *authConfig) appendError(err error) {
	if err != nil {
		ac.Errors = append(ac.Errors, err)
	}
}

func (ac *authConfig) hasErrors() bool {
	if len(ac.Errors) > 0 {
		return true
	}
	return false
}

func (ac *authConfig) getTokenKey() (key string, err error) {
	if len(ac.tokenKey) == 0 {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Get(ac.TokenKeyURL)
		defer resp.Body.Close()
		if err != nil {
			return "", err
		}

		payload, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("ERROR RETRIEVING TOKEN_KEY!")
			return "", err
		}

		ko := &keyObject{}
		err = json.Unmarshal(payload, ko)
		if err != nil {
			fmt.Println("ERROR PARSING TOKEN_KEY!")
			return "", err
		}

		fmt.Printf("RETRIEVED KEY: %s\n", ko.Value)
		if len(ko.Value) == 0 {
			fmt.Println("RETRIEVED TOKEN KEY IS EMPTY!")
			return "", err
		}
		ac.tokenKey = ko.Value
	}

	return ac.tokenKey, nil
}

func tokenToJSON(token *oauth2.Token) (string, error) {
	if d, err := json.Marshal(token); err != nil {
		return "", err
	} else {
		return string(d), nil
	}
}

func tokenFromJSON(jsonStr string) (*oauth2.Token, error) {
	var token oauth2.Token
	if err := json.Unmarshal([]byte(jsonStr), &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func tokenFromSession(sm *session.Manager, w http.ResponseWriter, r *http.Request) (token *oauth2.Token, err error) {
	session, _ := sm.SessionStart(w, r)
	defer session.SessionRelease(w)

	jsonToken := session.Get("token")
	token, err = tokenFromJSON(jsonToken.(string))
	if err != nil {
		fmt.Printf("Error retrieving token from session: %s\n", err)
		return nil, err
	}

	return token, nil
}
