package server

// TODO: (STRETCH) Call backing service passing the JWT and get a return value.

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
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
					<hr/>
			    <p>Return to the <a href="/protected/user">User Page</a>.</p>
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
		<h3>Profile Data</h3>
		<table>
			{{.ProfileData}}
		</table>
		<h3>Scopes</h3>
		<ul>
			{{.Scopes}}
		</ul>
		<hr/>
    <p>Visit the <a href="/protected/access">Access Page</a>.</p>
    <p>Visit the <a href="/protected/admin">Admin Page</a>.</p>
		<p>Invoke a secured <a href="/protected/backing">Backing Service</a>.</p>
		</body>
		</html>
		`

		type userData struct {
			ProfileData string
			Scopes      string
		}
		ud := &userData{}

		// Scopes
		token, err := tokenFromSession(sessionManager, w, r)
		if err != nil {
			fmt.Printf("NO TOKEN IN REQUEST: %s\n", err)
			http.Redirect(w, r, "/unauthorized", http.StatusUnauthorized)
		}
		accessToken, err := parseToken(token.AccessToken, config)
		if err != nil {
			fmt.Printf("Error Parsing Token: %v", err)
		}

		scopes := accessToken.Claims["scope"]
		a := scopes.([]interface{})
		for _, scope := range a {
			ud.Scopes += fmt.Sprintf("<li>%s</li>", scope)
		}

		// Profile Data
		session, _ := sessionManager.SessionStart(w, r)
		defer session.SessionRelease(w)
		profile := session.Get("profile").(map[string]interface{})

		for k, v := range profile {
			ud.ProfileData += fmt.Sprintf("<tr><td>%s</td><td>%s</td></tr>", k, v.(string))
		}

		t := template.Must(template.New("user").Parse(userTemplate))
		t.Execute(w, ud)

	}
}

func backingServiceHandler(sessionManager *session.Manager, config *authConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userTemplate = `
		<html>
		<head>
		<title>Invoke Backing Service</title>
		</head>
		<body>
		<h2>Results from backing service:</h2>
		<blockquote>
			{{.Payload}}
		</blockquote>
		<hr/>
    <p>Return to the <a href="/protected/user">User Page</a>.</p>
		</body>
		</html>
		`
		token, err := tokenFromSession(sessionManager, w, r)
		if err != nil {
			fmt.Printf("NO TOKEN IN REQUEST: %s\n", err)
			http.Redirect(w, r, "/unauthorized", http.StatusUnauthorized)
		}
		tokenHeader := fmt.Sprintf("BEARER %s", token.AccessToken)

		type serviceData struct {
			Payload string
		}
		sd := &serviceData{
			Payload: "--- not replaced ---",
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		req, _ := http.NewRequest("GET", "https://oauth-backing-service.apps.pcf.local/api/hello", nil)
		req.Header.Set("Authorization", tokenHeader)
		resp, err := client.Do(req)
		defer resp.Body.Close()
		if err != nil {
			http.Error(w, "COULD NOT ACCESS BACKING SERVICE", http.StatusInternalServerError)
		}

		payload, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("ERROR MAKING SERVICE CALL!")
		}

		sd.Payload = bytes.NewBuffer(payload).String()

		t := template.Must(template.New("service").Parse(userTemplate))
		t.Execute(w, sd)
	}
}
