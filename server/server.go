package server

import (
	"log"
	"os"

	"github.com/astaxie/beego/session"
	"github.com/cloudfoundry-community/go-cfenv"
	"github.com/cloudnativego/cf-tools"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

type authConfig struct {
	ClientID     string
	ClientSecret string
	Domain       string
	CallbackURL  string
}

//NewServer configures and returns a Negroni server
func NewServer(appEnv *cfenv.App) *negroni.Negroni {
	// HACK handle these failures for realzies
	authClientID, _ := cftools.GetVCAPServiceProperty("sso", "client_id", appEnv)
	authSecret, _ := cftools.GetVCAPServiceProperty("sso", "client_secret", appEnv)
	authDomain, _ := cftools.GetVCAPServiceProperty("sso", "auth_domain", appEnv)
	authCallback := os.Getenv("AUTH_CALLBACK")
	if len(authCallback) == 0 {
		log.Fatal("Could not retrieve callback url from environment.")
		os.Exit(1)
	}

	config := &authConfig{
		ClientID:     authClientID,
		ClientSecret: authSecret,
		Domain:       authDomain,
		CallbackURL:  authCallback,
	}

	//TODO: Update to use externalized sessions (e.g. Redis)
	//Currently, this form of session management will fail if mulitple instances of the app are running.
	sessionManager, _ := session.NewManager("memory", `{"cookieName":"gosessionid","gclifetime":3600}`)
	go sessionManager.GC()

	n := negroni.Classic()
	router := mux.NewRouter()

	// Public Routes
	router.HandleFunc("/", homeHandler(config))
	router.HandleFunc("/callback", callbackHandler(sessionManager, config))

	// Protected Routes
	secure := mux.NewRouter()
	secure.HandleFunc("/protected/access", accessHandler(sessionManager))
	secure.HandleFunc("/protected/admin", adminHandler(sessionManager))

	router.PathPrefix("/protected").Handler(negroni.New(
		negroni.HandlerFunc(isAuthenticated(sessionManager)),
		negroni.Wrap(secure),
	))

	n.UseHandler(router)
	return n
}
