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
			fmt.Printf("NO TOKEN IN REQUEST: %s\n", err)
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
    <p>Return to the <a href="/protected/user">User Page</a>.</p>
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
			fmt.Printf("NO TOKEN IN REQUEST: %s\n", err)
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
    <p>Return to the <a href="/protected/user">User Page</a>.</p>
  </body>
</html>`)
			w.Write(buf.Bytes())
		} else {
			http.Redirect(w, r, "/unauthorized", http.StatusMovedPermanently)
		}
	}
}

func userHandler(sessionManager *session.Manager, config *authConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userTemplate = `
		<html>
		<head>
		<title>OAuth Authcode User Page</title>
		</head>
		<body>
		<h2>Welcome to the OAuth Authcode Profile Page</h2>
		<table>
			{{.ProfileData}}
		</table>
		<hr/>
    <p>Visit the <a href="/protected/access">Access Page</a>.</p>
    <p>Visit the <a href="/protected/admin">Admin Page</a>.</p>

		</body>
		</html>
		`

		// token, err := tokenFromSession(sessionManager, w, r)
		// if err != nil {
		// 	fmt.Printf("NO TOKEN IN REQUEST: %s\n", err)
		// 	http.Redirect(w, r, "/unauthorized", http.StatusUnauthorized)
		// }
		session, _ := sessionManager.SessionStart(w, r)
		defer session.SessionRelease(w)

		// var profile map[string]interface{}
		// if err := json.Unmarshal([]byte(session.Get("profile")), &profile); err != nil {
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// 	return
		// }

		profile := session.Get("profile").(map[string]interface{})

		type ud struct {
			ProfileData string
		}
		userData := &ud{}
		for k, v := range profile {
			userData.ProfileData += fmt.Sprintf("<tr><td>%s</td><td>%s</td></tr>", k, v.(string))
		}

		t := template.Must(template.New("user").Parse(userTemplate))
		t.Execute(w, *userData)

	}
}
