package server

// TODO: (STRETCH) Call backing service passing the JWT and get a return value.

import (
	"bytes"
	"fmt"
	"net/http"
	"text/template"

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

func unauthorizedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		buf := bytes.NewBufferString(`
			<html>
				<head>
					<title>Unauthorized</title>
				</head>
				<body>
					<h2>Unauthorized</h2>
					<p>You are unauthorized to access page.</p>
				</body>
			</html>`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(buf.Bytes())
	}
}

func accessHandler(sessionManager *session.Manager, config *authConfig) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		token, err := tokenFromSession(sessionManager, w, r)
		if err != nil {
			fmt.Println("NO TOKEN IN REQUEST")
			http.Redirect(w, r, "/unauthorized", http.StatusMovedPermanently)
			return
		}

		accessToken, err := parseToken(token.AccessToken, config)
		if err != nil {
			fmt.Printf("Error Parsing Token: %s\n", err)
		}

		if hasScope(accessToken, "test.access", "test.admin") {
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			buf := bytes.NewBufferString(`
<html>
  <head>
    <title>Access Page</title>
  </head>
  <body>
    <h2>You have successfully reached the Access Page</h2>
    <p>This page requires either the <code>test.access</code> or <code>test.admin</code> scope.</p>
    <hr/>
    <p>Visit the <a href="/protected/admin">Admin Page</a>.</p>
  </body>
</html>`)
			w.Write(buf.Bytes())
		} else {
			http.Redirect(w, r, "/unauthorized", http.StatusMovedPermanently)
		}
	}
}

func adminHandler(sessionManager *session.Manager, config *authConfig) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		token, err := tokenFromSession(sessionManager, w, r)
		if err != nil {
			fmt.Println("NO TOKEN IN REQUEST")
			http.Redirect(w, r, "/unauthorized", http.StatusUnauthorized)
		}

		accessToken, err := parseToken(token.AccessToken, config)
		if err != nil {
			fmt.Printf("Error Parsing Token: %v", err)
		}

		if hasScope(accessToken, "test.admin") {
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			buf := bytes.NewBufferString(`
<html>
  <head>
    <title>Admin Page</title>
  </head>
  <body>
    <h2>You have successfully reached the Admin Page</h2>
    <p>This page requires the <code>test.admin</code> scope.</p>
    <hr/>
    <p>Visit the <a href="/protected/access">Access Page</a>.</p>
  </body>
</html>`)
			w.Write(buf.Bytes())
		} else {
			http.Redirect(w, r, "/unauthorized", http.StatusMovedPermanently)
		}
	}
}
