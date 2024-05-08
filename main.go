package main

import (
	"AzureSecuredAPIWithOT/configs"
	"AzureSecuredAPIWithOT/helpers/pages"
	"AzureSecuredAPIWithOT/logger"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
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

func HandleMain(w http.ResponseWriter, _ *http.Request) {
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

	token, err := validateTokenAndScope(tokenString)

	if err != nil {
		return nil, fmt.Errorf("jwt.Parse(): %w", err)
	}
	return token, nil
}
