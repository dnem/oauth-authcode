package server

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

const uaaKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuJUnh3aUG+1R16lqjxfH\nQwnsaIs2nc8ELJYDXhRR9JldVp9hE018DfAG0S3eWP2ltDuFojs38mBq0bx2YMau\nKeJuCIuKH58IAdjFQA+/6PJBlv9RSPnYxjKhB+rXO+uYI112UNnqs3ZT1gW+obGy\nreq5yHjfSga1Uq2RhM70Bb9Mjw7Z6ebH2vh9kQTSvonViYf2oE59a3N9+osv770d\nFGwo8umEFU3xaASm+fF5ev6g0/k+E+Hu/PtNOzR5zFfyGpjKH8wHFY/Q9qoYrIES\nLIhT72H/YY5x4bjEuIdj0bF5vGwHEMiW08wTu2x3Uzv8lpqRwZKhmJ+rLp9LNIEG\n7wIDAQAB\n-----END PUBLIC KEY-----\n"

func parseToken(token string) (t *jwt.Token, err error) {
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		return []byte(uaaKey), nil
	}

	t, err = jwt.Parse(token, keyFunc)
	if err != nil {
		return nil, err
	}

	if t.Valid {
		return t, err
	} else {
		err = errors.New("Token is not valid")
		return nil, err
	}
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
