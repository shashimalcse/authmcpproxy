package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/yaml.v2"
)

type Config struct {
	AuthServerBaseURL string            `yaml:"auth_server_base_url"`
	MCPServerBaseURL  string            `yaml:"mcp_server_base_url"`
	MCPPaths          []string          `yaml:"mcp_paths"`
	ListenAddress     string            `yaml:"listen_address"`
	TimeoutSeconds    int               `yaml:"timeout_seconds"`
	PathMapping       map[string]string `yaml:"path_mapping"`
	JWKSURL           string            `yaml:"jwks_url"`
}

type JWKS struct {
	Keys []json.RawMessage `json:"keys"`
}

var publicKeys map[string]*rsa.PublicKey

func loadConfig() (*Config, error) {
	f, err := os.Open("config.yaml")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	return &cfg, err
}

func addCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
}

func fetchJWKS(jwksURL string) error {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	publicKeys = make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		var parsedKey struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Kty string `json:"kty"`
		}
		err := json.Unmarshal(key, &parsedKey)
		if err != nil {
			continue
		}
		if parsedKey.Kty != "RSA" {
			continue
		}
		pubKey, err := parseRSAPublicKey(parsedKey.N, parsedKey.E)
		if err == nil {
			publicKeys[parsedKey.Kid] = pubKey
		}
	}
	return nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := jwt.DecodeSegment(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := jwt.DecodeSegment(eStr)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func validateJWT(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return errors.New("missing or invalid Authorization header")
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if kid, ok := token.Header["kid"].(string); ok {
			if pubKey, exists := publicKeys[kid]; exists {
				return pubKey, nil
			}
		}
		return nil, errors.New("invalid kid or key not found")
	})
	if err != nil || !token.Valid {
		return errors.New("invalid token")
	}
	return nil
}

func proxyHandler(cfg *Config) http.HandlerFunc {
	authBase, err := url.Parse(cfg.AuthServerBaseURL)
	if err != nil {
		log.Fatalf("Invalid auth server URL: %v", err)
	}
	mcpBase, err := url.Parse(cfg.MCPServerBaseURL)
	if err != nil {
		log.Fatalf("Invalid MCP server URL: %v", err)
	}

	authPaths := map[string]bool{
		"/authorize": true,
		"/token":     true,
		"/.well-known/oauth-authorization-server": true,
	}

	mcpPaths := make(map[string]bool)
	for _, p := range cfg.MCPPaths {
		mcpPaths[p] = true
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			addCORS(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var targetURL *url.URL
		if authPaths[r.URL.Path] {
			targetURL = authBase
		} else if mcpPaths[r.URL.Path] {
			if err := validateJWT(r); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			targetURL = mcpBase
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		addCORS(w)

		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				mappedPath := r.URL.Path
				if rewrite, ok := cfg.PathMapping[r.URL.Path]; ok {
					mappedPath = rewrite
				}

				basePath := strings.TrimRight(targetURL.Path, "/")
				req.URL.Scheme = targetURL.Scheme
				req.URL.Host = targetURL.Host
				req.URL.Path = basePath + mappedPath
				req.URL.RawQuery = r.URL.RawQuery
				req.Host = targetURL.Host

				log.Printf("Proxying %s → %s%s?%s", r.URL.Path, req.URL.Host, req.URL.Path, req.URL.RawQuery)
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("Proxy error: %v", err)
				http.Error(w, "Proxy error", http.StatusBadGateway)
			},
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.TimeoutSeconds)*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		proxy.ServeHTTP(w, r)
	}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := fetchJWKS(cfg.JWKSURL); err != nil {
		log.Fatalf("Failed to fetch JWKS: %v", err)
	}

	mux := http.NewServeMux()

	// Register MCP paths
	for _, path := range cfg.MCPPaths {
		mux.HandleFunc(path, proxyHandler(cfg))
	}

	// Register all paths from mapping
	for path := range cfg.PathMapping {
		mux.HandleFunc(path, proxyHandler(cfg))
	}

	// Default common paths
	defaultPaths := []string{"/authorize", "/token", "/.well-known/oauth-authorization-server"}
	for _, path := range defaultPaths {
		if _, exists := cfg.PathMapping[path]; !exists {
			mux.HandleFunc(path, proxyHandler(cfg))
		}
	}

	srv := &http.Server{
		Addr:         cfg.ListenAddress,
		Handler:      mux,
		ReadTimeout:  time.Duration(cfg.TimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
	}

	go func() {
		log.Printf("Proxy server started on %s", cfg.ListenAddress)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("Server stopped")
}
