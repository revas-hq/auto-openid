package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/oklog/ulid/v2"
)

func main() {
	bu := os.Getenv("BASE_URL")
	if bu == "" {
		bu = "http://localhost:8080"
		log.Printf("defaulting to base url %s", bu)
	}
	baseURL, err := url.Parse(bu)
	if err != nil {
		log.Fatal(err)
	}

	nonceCache := &sync.Map{}

	r := mux.NewRouter()
	r.HandleFunc("/{dash}/authorize", NewAuthorizeHandlerFunc(nonceCache))
	r.HandleFunc("/{dash}/oauth/token", NewTokenHandlerFunc(baseURL, nonceCache))
	r.HandleFunc("/{dash}/verify", NewVerifyHandlerFunc())
	r.HandleFunc("/{dash}/.well-known/jwks.json", NewJWKSHandlerFunc())
	r.HandleFunc("/{dash}/.well-known/openid-configuration", NewDiscoveryHandlerFunc(baseURL))

	http.Handle("/", r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("defaulting to port %s", port)
	}

	log.Printf("listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func getIssuer(baseURL *url.URL, r *http.Request) *url.URL {
	dash := mux.Vars(r)["dash"]
	dashPath, err := url.Parse(dash)
	if err != nil {
		log.Fatal(err)
	}
	issuer := baseURL.ResolveReference(dashPath)
	return issuer
}

func NewDiscoveryHandlerFunc(baseURL *url.URL) http.HandlerFunc {
	discoveryTemplate := template.Must(template.ParseFiles("openid-configuration.json"))
	return func(w http.ResponseWriter, r *http.Request) {
		dash := mux.Vars(r)["dash"]
		dashPath, err := url.Parse(dash)
		if err != nil {
			log.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		issuer := baseURL.ResolveReference(dashPath)
		err = discoveryTemplate.Execute(w, struct {
			Issuer string
		}{
			Issuer: issuer.String(),
		})
		if err != nil {
			log.Fatal(err)
		}
	}
}

func NewJWKSHandlerFunc() http.HandlerFunc {
	jwksJson, err := ioutil.ReadFile("jwks.json")
	if err != nil {
		log.Fatal(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(jwksJson)
	}
}

func NewAuthorizeHandlerFunc(nonceCache *sync.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()

		values := r.URL.Query()
		redirectURI := values.Get("redirect_uri")
		nonceCache.Store(code, values.Get("nonce"))

		u, _ := url.Parse(redirectURI)
		v := u.Query()
		v.Add("code", code)
		v.Add("state", values.Get("state"))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}

func NewTokenHandlerFunc(baseURL *url.URL, nonceCache *sync.Map) http.HandlerFunc {
	privatePem, err := ioutil.ReadFile("private.pem")
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(privatePem)
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		code := r.Form.Get("code")

		user := mux.Vars(r)["dash"]
		user = strings.Replace(user, "-dot-", ".", -1)
		user = strings.Replace(user, "-at-", "@", -1)

		h := fnv.New32a()
		h.Write([]byte(mux.Vars(r)["dash"]))
		sub := fmt.Sprintf("%v", h.Sum32())

		issuer := getIssuer(baseURL, r)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"https://auth.revas.app/email":          user,
			"https://auth.revas.app/email_verified": true,
			"iss":                                   issuer.String() + "/",
			"sub":                                   sub,
			"aud": []string{
				"https://api.revas.app",
				"https://revas-os.eu.auth0.com/userinfo",
			},
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
			"azp":   "EuF4nRe3111vAMZKdYMxGdKD3Qzl1WbI",
			"scope": "openid profile email offline_access",
		})
		token.Header["kid"] = "01G3C03T53EN3PGS6DAPMHV3FG"
		signed, err := token.SignedString(privateKey)
		if err != nil {
			log.Fatal(err)
		}

		nonce, _ := nonceCache.Load(code)

		idtoken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss":   issuer.String() + "/",
			"sub":   sub,
			"aud":   "client",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
			"email": user,
			"nonce": nonce,
		})
		idtoken.Header["kid"] = "01G3C03T53EN3PGS6DAPMHV3FG"
		idsigned, err := idtoken.SignedString(privateKey)
		if err != nil {
			log.Fatal(err)
		}

		json.NewEncoder(w).Encode(struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int64  `json:"expires_in"`
			IDToken      string `json:"id_token"`
		}{
			AccessToken:  signed,
			TokenType:    "Bearer",
			RefreshToken: "8xLOxBtZp8",
			ExpiresIn:    time.Now().Add(time.Hour).Unix(),
			IDToken:      idsigned,
		})
	}
}

func NewVerifyHandlerFunc() http.HandlerFunc {
	publicPem, err := ioutil.ReadFile("public.pem")
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(publicPem)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		h = strings.ReplaceAll(h, "Bearer", "")
		h = strings.ReplaceAll(h, "bearer", "")
		token, err := jwt.Parse(h, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			log.Fatal(err)
		}
		json.NewEncoder(w).Encode(token)
	}
}
