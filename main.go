package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	AuthServerBaseURL string            `yaml:"auth_server_base_url"`
	ListenAddress     string            `yaml:"listen_address"`
	TimeoutSeconds    int               `yaml:"timeout_seconds"`
	PathMapping       map[string]string `yaml:"path_mapping"`
}

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

func proxyHandler(cfg *Config) http.HandlerFunc {
	targetURL, err := url.Parse(cfg.AuthServerBaseURL)
	if err != nil {
		log.Fatalf("Invalid auth server URL: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			addCORS(w)
			w.WriteHeader(http.StatusNoContent)
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

	mux := http.NewServeMux()

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
