package server

import (
	"log"
	"os"

	"github.com/astaxie/beego/session"
	"github.com/cloudfoundry-community/go-cfenv"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

//NewServer configures and returns a Negroni server
func NewServer(appEnv *cfenv.App) *negroni.Negroni {

	// set up the authConfig object which contains key values from SSO tile
	config := initOAuthConfig(appEnv)
	if config.hasErrors() {
		for _, err := range config.Errors {
			log.Fatalf("OAuth Configuration Error: %s\n", err)
		}
		os.Exit(1)
	}

	//HACK: Current implementation does not scale in cloud environment. Update to use externalized sessions (e.g. Redis)
	sessionManager, _ := session.NewManager("memory", `{"cookieName":"gosessionid","gclifetime":3600}`)
	go sessionManager.GC()

	n := negroni.Classic()
	router := mux.NewRouter()

	// Public Routes
	router.HandleFunc("/", homeHandler(config))
	router.HandleFunc("/unauthorized", unauthorizedHandler())
	router.HandleFunc("/callback", callbackHandler(sessionManager, config))

	// Protected Routes
	secure := mux.NewRouter()
	secure.HandleFunc("/protected/user", userHandler(sessionManager, config))
	secure.HandleFunc("/protected/access", accessHandler(sessionManager, config))
	secure.HandleFunc("/protected/admin", adminHandler(sessionManager, config))
	secure.HandleFunc("/protected/backing", backingServiceHandler(sessionManager, config))

	router.PathPrefix("/protected").Handler(negroni.New(
		negroni.HandlerFunc(isAuthenticated(sessionManager)),
		negroni.Wrap(secure),
	))

	n.UseHandler(router)
	return n
}
