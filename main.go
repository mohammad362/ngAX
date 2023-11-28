package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/h2non/bimg"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Config struct {
	HostMappings map[string]string `mapstructure:"host_mappings"`
	WebP         struct {
		Quality      int  `mapstructure:"quality"`
		Lossless     bool `mapstructure:"lossless"`
		NearLossless int  `mapstructure:"near_lossless"`
	} `mapstructure:"webp"`
	Cache struct {
		ExpirationMinutes      int    `mapstructure:"expiration_minutes"`
		CleanupIntervalMinutes int    `mapstructure:"cleanup_interval_minutes"`
		CacheEnabled           bool   `mapstructure:"cache_enabled"`
		NoCacheHeader          string `mapstructure:"nocache_header"`
	} `mapstructure:"cache"`
	Concurrency struct {
		MaxGoroutines int `mapstructure:"max_goroutines"`
	} `mapstructure:"concurrency"`
	HTTPClient struct {
		TimeoutSeconds        int `mapstructure:"timeout_seconds"`
		DialTimeoutSeconds    int `mapstructure:"dial_timeout_seconds"`
		KeepAlive             int `mapstructure:"keep_alive"`
		TLSHandshakeTimeout   int `mapstructure:"TLS_handshake_timeout"`
		ResponseHeaderTimeout int `mapstructure:"response_header_timeout"`
		ExpectContinueTimeout int `mapstructure:"expect_continue_timeout"`
	} `mapstructure:"http_client"`
	AllowedHosts []string `mapstructure:"allowed_hosts"`
}

var (
	config     Config
	imgCache   *lru.Cache
	logger     *logrus.Logger
	httpClient *http.Client
	semaphore  chan struct{}
)

func init() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		logrus.Fatalf("Error reading config file: %v", err)
	}

	if err := viper.Unmarshal(&config); err != nil {
		logrus.Fatalf("Unable to decode into struct: %v", err)
	}

	var err error
	imgCache, err = lru.New(128) // Adjust the size as needed
	if err != nil {
		logrus.Fatalf("Failed to create LRU cache: %v", err)
	}

	logger = logrus.New()
	logger.Out = os.Stdout
	logger.Level = logrus.DebugLevel
	logger.Formatter = &logrus.JSONFormatter{}

	httpClient = &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   time.Duration(config.HTTPClient.DialTimeoutSeconds) * time.Second,
				KeepAlive: time.Duration(config.HTTPClient.KeepAlive) * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   time.Duration(config.HTTPClient.TLSHandshakeTimeout) * time.Second,
			ResponseHeaderTimeout: time.Duration(config.HTTPClient.ResponseHeaderTimeout) * time.Second,
			ExpectContinueTimeout: time.Duration(config.HTTPClient.ExpectContinueTimeout) * time.Second,
			MaxConnsPerHost:       0,
			MaxIdleConnsPerHost:   0,
			MaxIdleConns:          100,
		},
		Timeout: time.Second * time.Duration(config.HTTPClient.TimeoutSeconds),
	}
	logger.Info("Timeout:", time.Duration(config.HTTPClient.TimeoutSeconds))

	semaphore = make(chan struct{}, config.Concurrency.MaxGoroutines)
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/{image:.*}", handleRequest)
	router.HandleFunc("/health", healthCheckHandler)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	go func() {
		logger.Info("Server started at http://localhost:8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	gracefulShutdown(srv)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Get the host from the request header
	remoteHost := r.Host

	if remoteHost == "" {
		// Handle the case where no host is provided, for example:
		// remoteHost = "default-host.com"
		// Or return an error response
		http.Error(w, "Host header is missing", http.StatusBadRequest)
		return
	}

	if !isAllowedHost(remoteHost) {
		logger.Warn("Unauthorized access attempt from host: ", remoteHost)
		http.Error(w, "Host not allowed", http.StatusForbidden)
		return
	}

	// Build the imageURL using the host from the request header
	imageURL := "https://" + remoteHost + r.URL.Path

	nocacheHeader := r.Header.Get(config.Cache.NoCacheHeader)
	if config.Cache.CacheEnabled && nocacheHeader != "true" {
		// Check the cache first
		if cachedImage, found := imgCache.Get(imageURL); found {
			// Log cache miss
			logger.Info("Cache hit for URL: ", imageURL)

			// Serve the cached image
			w.Header().Set("Content-Type", "image/webp")
			w.Header().Set("Content-Length", strconv.Itoa(len(cachedImage.([]byte))))
			w.Write(cachedImage.([]byte))
			return
		}
	}

	// Log cache miss
	logger.Info("Cache miss for URL: ", imageURL)

	semaphoreWaitStart := time.Now()
	logger.Info("Waiting for semaphore slot")

	// Acquire a slot in the semaphore to limit concurrency
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	semaphoreWaitDuration := time.Since(semaphoreWaitStart)
	logger.WithFields(logrus.Fields{
		"semaphoreWaitDuration": semaphoreWaitDuration,
	}).Info("Semaphore slot acquired")

	requestStartTime := time.Now()

	defer func() {
		<-semaphore
		requestDuration := time.Since(requestStartTime)
		logger.WithFields(logrus.Fields{
			"requestDuration":       requestDuration,
			"semaphoreWaitDuration": semaphoreWaitDuration,
		}).Info("Request processed and semaphore slot released")
	}()

	// Convert the image to WebP format
	convertToWebP(imageURL, w)
}

func convertToWebP(imageURL string, w http.ResponseWriter) {
	fetchStartTime := time.Now()

	resp, err := httpClient.Get(imageURL)
	if err != nil {
		// Log the error with detailed information
		logger.WithFields(logrus.Fields{"url": imageURL, "error": err.Error()}).Error("Error fetching image")
		http.Error(w, fmt.Sprintf("Error fetching image: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Check if the response from the remote host is successful
	if resp.StatusCode != http.StatusOK {
		// Log the HTTP error with the status code and status
		logger.WithFields(logrus.Fields{"url": imageURL, "status": resp.Status}).Error("HTTP error from remote host")
		http.Error(w, fmt.Sprintf("HTTP error from remote host: %s", resp.Status), resp.StatusCode)
		return
	}

	contentType := resp.Header.Get("Content-Type")
	if !isSupportedImageFormat(contentType) {
		errMsg := "Unsupported image format"
		logger.WithFields(logrus.Fields{"contentType": contentType, "error": errMsg}).Error()
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Error reading image body: %v", err)
		logger.WithFields(logrus.Fields{"error": errMsg}).Error()
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	fetchDuration := time.Since(fetchStartTime)
	logger.WithFields(logrus.Fields{"fetchDuration": fetchDuration}).Info("Image fetched")

	processStartTime := time.Now()

	options := bimg.Options{
		Quality: config.WebP.Quality,
		// Assume Lossless is a valid field; remove or modify if not
		Lossless: config.WebP.Lossless,
		// Removed NearLossless and OutputFormat as they might not be valid
		Type: bimg.WEBP,
	}

	newImage, err := bimg.NewImage(body).Process(options)
	if err != nil {
		errMsg := fmt.Sprintf("Error converting image: %v", err)
		logger.WithFields(logrus.Fields{"error": errMsg}).Error()
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	compressionRate := float64(len(newImage)) / float64(len(body)) * 100
	processDuration := time.Since(processStartTime)
	logger.WithFields(logrus.Fields{
		"processDuration":  processDuration,
		"fetchDuration":    fetchDuration,
		"compression_rate": fmt.Sprintf("%.2f%%", compressionRate),
	}).Info("Image processed and served")

	imgCache.Add(imageURL, newImage)

	w.Header().Set("Content-Type", "image/webp")
	w.Header().Set("Content-Length", strconv.Itoa(len(newImage)))
	w.Write(newImage)
}

func isSupportedImageFormat(contentType string) bool {
	supportedFormats := []string{"jpeg", "jpg", "png", "gif", "bmp"}
	for _, format := range supportedFormats {
		if strings.Contains(contentType, format) {
			return true
		}
	}
	return false
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func gracefulShutdown(srv *http.Server) {
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	<-stopChan
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server gracefully stopped")
}

// Helper function to check if a host is in the allowed list
func isAllowedHost(host string) bool {
	for _, allowedHost := range config.AllowedHosts {
		if host == allowedHost {
			return true
		}
	}
	return false
}
