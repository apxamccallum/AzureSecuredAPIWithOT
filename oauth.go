package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/viper"
)

type jwksCache struct {
	jwks    jwk.Set
	fetched time.Time
	mutex   sync.RWMutex
}

var cache jwksCache

// fetchJWKS retrieves JWKS from the Azure AD endpoint or from the cache if it's still valid.
func fetchJWKS(url string) (jwk.Set, error) {
	cache.mutex.RLock()
	// Check if JWKS is still valid, let's say cache validity is 24 hours
	if cache.jwks != nil && time.Since(cache.fetched) < 24*time.Hour {
		defer cache.mutex.RUnlock()
		return cache.jwks, nil
	}
	cache.mutex.RUnlock()

	// Lock for writing since we need to update the cache
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Double check if another goroutine hasn't already updated the cache
	if cache.jwks != nil && time.Since(cache.fetched) < 24*time.Hour {
		return cache.jwks, nil
	}

	// Fetch new JWKS from the URL
	set, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKs: %v", err)
	}

	// Update the cache
	cache.jwks = set
	cache.fetched = time.Now()

	return set, nil
}

// FetchPublicKey retrieves the public key from the JWKS, using cache when appropriate.
func FetchPublicKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("expecting JWT header to have string kid")
	}

	jwks, err := fetchJWKS(viper.GetString("jwkurl"))
	if err != nil {
		return nil, err
	}

	key, found := jwks.LookupKeyID(keyID)
	if !found {
		return nil, fmt.Errorf("no key found matching kid: %s", keyID)
	}

	var pubkey interface{}
	if err := key.Raw(&pubkey); err != nil {
		return nil, fmt.Errorf("failed to create public key: %v", err)
	}
	return pubkey, nil
}

type CustomClaims struct {
	Roles  []string `json:"roles"` // Ensure your token uses "roles" claim
	Scopes string   `json:"scp"`   // Azure AD uses "scp" to list scopes
	jwt.RegisteredClaims
}

// ValidateTokenAndScope validates a JWT token and checks for required scopes.
func validateTokenAndScope(tokenStr string) (*jwt.Token, error) {
	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, FetchPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	// Check if token claims are valid and contain the required scope
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		// Validate issuer
		expectedIssuer := viper.GetString("expectedissuer")
		if claims.Issuer != expectedIssuer {
			return nil, fmt.Errorf("invalid issuer: expected %s, got %s", expectedIssuer, claims.Issuer)
		}

		// Validate audience
		// Audience can be either a single string or an array of strings
		expectedAudience := viper.GetString("expectedaudience")
		validAudience := false
		for _, aud := range claims.Audience {
			if aud == expectedAudience {
				validAudience = true
				break
			}
		}
		if !validAudience {
			return nil, fmt.Errorf("invalid audience: expected %s", expectedAudience)
		}

		// Validate expiration and not before
		now := jwt.TimeFunc()
		if !claims.VerifyExpiresAt(now, true) {
			return nil, fmt.Errorf("token has expired")
		}
		if !claims.VerifyNotBefore(now, true) {
			return nil, fmt.Errorf("token not valid yet")
		}

		// Check if the required scope is present in the scope claim
		requiredScope := viper.GetString("scope")
		validScope := false
		scopes := strings.Split(claims.Scopes, " ")
		for _, scope := range scopes {
			if scope == requiredScope {
				validScope = true
				break
			}
		}
		if !validScope {
			return nil, fmt.Errorf("expected scope: %s, got: %s", requiredScope, claims.Scopes)
		}

		// validRole := false
		// // Check if the required role is present in the roles claim
		// for _, role := range claims.Roles {
		// 	requiredRole := viper.GetString("requiredrole")
		// 	if role == requiredRole {
		// 		validRole = true
		// 		break
		// 	}
		// }
		// if !validRole {
		// 	return nil, fmt.Errorf("required role not present")
		// }
	}

	return token, nil
}
