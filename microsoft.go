package main

import (
	"AzureSecuredAPIWithOT/helpers/pages"
	"AzureSecuredAPIWithOT/logger"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

var store = sessions.NewCookieStore([]byte("your-secret-key"))

var (
	oauthConfMs        = &oauth2.Config{}
	oauthStateStringMs = ""
)

func InitializeOAuthMicrosoft() {
	oauthConfMs.Scopes = []string{viper.GetString("api") + viper.GetString("scope")}
	oauthConfMs.ClientID = viper.GetString("clientID")
	oauthConfMs.ClientSecret = viper.GetString("clientSecret")
	oauthConfMs.Endpoint = microsoft.AzureADEndpoint(viper.GetString("tenant"))
	oauthStateStringMs = viper.GetString("oauthStateString")
}

func HandleMicrosoftLogin(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Host, "azure") {
		oauthConfMs.RedirectURL = "https://" + r.Host + "/callback-ms"
	} else {
		oauthConfMs.RedirectURL = "http://" + r.Host + "/callback-ms"
	}
	handleLogin(w, r, oauthConfMs, oauthStateStringMs)
}

func handleLogin(w http.ResponseWriter, r *http.Request, oauthConf *oauth2.Config, oauthStateString string) {
	// Generate and store state in session
	state := generateState()
	session, _ := store.Get(r, "oauth-session")
	session.Values["state"] = state
	session.Save(r, w)

	// Generate a new verifier
	verifier := oauth2.GenerateVerifier()
	session.Values["verifier"] = verifier
	session.Save(r, w)

	// Generate the authorization URL with the stored state and verifier
	authUrl := oauthConf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	logger.Log.Info(authUrl)

	// Redirect user to the authorization URL
	http.Redirect(w, r, authUrl, http.StatusTemporaryRedirect)
}

func CallBackFromMicrosoft(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Callback-ms..")
	session, _ := store.Get(r, "oauth-session")

	state, _ := session.Values["state"].(string)

	requestState := r.FormValue("state")
	if requestState != state {
		logger.Log.Info("invalid oauth state, expected " + oauthStateStringMs + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		logger.Log.Warn("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		return
		// User has denied access...
		// http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	verifier, _ := session.Values["verifier"].(string)
	token, err := oauthConfMs.Exchange(context.Background(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		logger.Log.Error("oauthConfMs.Exchange() failed with " + err.Error() + "\n")
		return
	}
	logger.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
	logger.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
	logger.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token.AccessToken,
		Expires:  time.Now().Add(time.Hour * 24),
		HttpOnly: false,
	})

	tokenJson, err := json.Marshal(token)
	if err != nil {
		logger.Log.Error("Error in Marshalling the token")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pages.CallBackHeaderPage))
	w.Write(tokenJson)
	w.Write([]byte(pages.CallBackFooterPage))

}

func ProtectedRoute(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte(pages.SecureArea))
}

func LogoutRoute(writer http.ResponseWriter, request *http.Request) {
	cookie := &http.Cookie{
		Name:   "access_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(writer, cookie)
	http.Redirect(writer, request, "/", http.StatusTemporaryRedirect)
}

func generateState() string {
	b := make([]byte, 16) // Generates a random 16-byte state
	_, err := rand.Read(b)
	if err != nil {
		return "" // Handle error appropriately
	}
	return base64.URLEncoding.EncodeToString(b)
}
