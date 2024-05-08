package main

import (
	"AzureSecuredAPIWithOT/configs"
	"AzureSecuredAPIWithOT/helpers/pages"
	"AzureSecuredAPIWithOT/logger"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/viper"
)

func main() {
	configs.InitializeViper()

	logger.InitializeZapCustomLogger()

	InitializeOAuthMicrosoft()

	// Routes for the application
	http.HandleFunc("/", HandleMain)
	http.HandleFunc("/login-ms", HandleMicrosoftLogin)
	http.HandleFunc("/callback-ms", CallBackFromMicrosoft)
	http.HandleFunc("/protected-ms", middleware(ProtectedRoute))
	http.HandleFunc("/logout-ms", LogoutRoute)

	logger.Log.Info("Started running on http://localhost:" + viper.GetString("port"))
	log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), nil))
}

func HandleMain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pages.IndexPage))
}

func middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := verifyToken(r)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(pages.UnAuthorizedPage))
			logger.Log.Info(err.Error())
			return
		}

		next(w, r)
	}
}

func extractToken(r *http.Request) string {
	token := cookieToken(r)
	if token == "" {
		return headerToken(r)
	}

	return token
}

func cookieToken(r *http.Request) string {
	accessCookie, err := r.Cookie("access_token")
	if err != nil {
		return ""
	}

	return accessCookie.Value
}

func headerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func verifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := extractToken(r)
	if tokenString == "" {
		return nil, fmt.Errorf("no token provided")
	}

	keySet, err := jwk.Fetch(r.Context(), viper.GetString("microsoft.jwkurl"))
	if err != nil {
		return nil, fmt.Errorf("could not fetch JWK: %v", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwa.RS256.String() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		keys, ok := keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key %v not found", kid)
		}

		publickey := &rsa.PublicKey{}
		err = keys.Raw(publickey)
		if err != nil {
			return nil, fmt.Errorf("could not parse pubkey")
		}

		return publickey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("jwt.Parse(): %w", err)
	}
	return token, nil
}
