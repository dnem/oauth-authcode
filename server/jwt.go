package server

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

func parseToken(token string, config *authConfig) (t *jwt.Token, err error) {
	tokenKey, err := config.getTokenKey()
	if err != nil {
		return nil, err
	}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		return []byte(tokenKey), nil
	}

	t, err = jwt.Parse(token, keyFunc)
	if err != nil {
		return nil, err
	}

	if !t.Valid {
		err = errors.New("Token is not valid")
		return nil, err
	}

	return t, nil
}

func hasScope(token *jwt.Token, desiredScopes ...string) bool {
	scopeFound := false

	scopes := token.Claims["scope"]
	a := scopes.([]interface{})

	for _, scope := range a {
		for _, desiredScope := range desiredScopes {
			if scope.(string) == desiredScope {
				scopeFound = true
				break
			}
		}
	}
	return scopeFound
}
