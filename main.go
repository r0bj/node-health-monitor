package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	ver string = "0.12"
)

var (
	requestTimeout = kingpin.Flag("request-timeout", "Request to the node health endpoint timeout in seconds").Default("3").Envar("REQUEST_TIMEOUT").Int()
	cacheDuration  = kingpin.Flag("cache-duration", "Node health cache duration in seconds").Default("5").Envar("CACHE_DURATION").Int()
	listenAddress  = kingpin.Flag("web.listen-address", "Address to listen on for web interface").Default(":8080").String()
	urlPort        = kingpin.Flag("url-port", "Port to send health requests").Default("8080").Envar("URL_PORT").String()
	urlPath        = kingpin.Flag("url-path", "URL path to send health requests").Default("/health").Envar("URL_PATH").String()
	urlScheme      = kingpin.Flag("url-scheme", "URL scheme to use for health checks (e.g., http, https)").Default("http").Envar("URL_SCHEME").Enum("http", "https")
	verbose        = kingpin.Flag("verbose", "Verbose mode").Short('v').Bool()
)

var (
	nodeHealthStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_health_monitor_status",
		Help: "Node health monitor status",
	}, []string{"node"})

	cacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "node_health_monitor_cache_hits_total",
		Help: "Total number of cache hits for node health checks",
	}, []string{"node"})

	cacheMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "node_health_monitor_cache_misses_total",
		Help: "Total number of cache misses for node health checks",
	}, []string{"node"})

	healthCheckDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "node_health_monitor_check_duration_seconds",
		Help: "Duration of node health checks in seconds",
	}, []string{"node"})

	totalHealthChecks = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "node_health_monitor_total_checks",
		Help: "Total number of node health checks performed",
	}, []string{"node"})
)

// Config holds the configuration parameters for the health monitor.
type Config struct {
	URLScheme string
	URLPort   string
	URLPath   string
}

// buildHealthURL constructs the health check URL for a given node.
func buildHealthURL(node, scheme, port, pathStr string) (string, error) {
	// Safely join the host and port.
	hostPort := net.JoinHostPort(node, port)

	// Ensure the path is properly cleaned to prevent double slashes
	cleanPath := pathStr
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	cleanPath = path.Clean(cleanPath)

	// Construct the URL using the net/url package.
	u := &url.URL{
		Scheme: scheme,
		Host:   hostPort,
		Path:   cleanPath,
	}

	// Validate the constructed URL.
	if _, err := u.Parse(u.String()); err != nil {
		return "", fmt.Errorf("Invalid health URL: %w", err)
	}

	return u.String(), nil
}

// handleHealth returns an HTTP handler function for the /health/<node> endpoint.
func handleHealth(c *cache.Cache, cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Expected path: /health/<node>
		parts := strings.Split(req.URL.Path, "/")
		if len(parts) < 3 || parts[2] == "" {
			http.Error(w, "Node name is required", http.StatusBadRequest)
			return
		}
		node := parts[2]

		// Increment total health checks counter
		totalHealthChecks.WithLabelValues(node).Inc()

		// Check if the node's health status is cached
		if cachedStatus, found := c.Get(node); found {
			cacheHits.WithLabelValues(node).Inc()
			status, ok := cachedStatus.(int)
			if ok {
				if status == 1 {
					fmt.Fprintf(w, "HEALTHY\n")
				} else {
					http.Error(w, "UNHEALTHY", http.StatusServiceUnavailable)
				}
				return
			}
			// If type assertion fails, treat as cache miss
			cacheMisses.WithLabelValues(node).Inc()
		} else {
			cacheMisses.WithLabelValues(node).Inc()
		}

		// Construct the health check URL using the configuration
		healthURL, err := buildHealthURL(node, *urlScheme, *urlPort, *urlPath)
		if err != nil {
			slog.Error("Failed to build health URL", "node", node, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Create an HTTP client with a timeout
		client := &http.Client{
			Timeout: time.Second * time.Duration(*requestTimeout),
		}

		// Start measuring health check duration
		startTime := time.Now()
		defer func() {
			duration := time.Since(startTime).Seconds()
			healthCheckDuration.WithLabelValues(node).Observe(duration)
		}()

		// Send the HTTP GET request to the node's health endpoint
		resp, err := client.Get(healthURL)
		if err != nil {
			// Log the error and update the metric as unhealthy
			slog.Info("Failed to reach node health endpoint", "node", node, "error", err)
			nodeHealthStatus.WithLabelValues(node).Set(0)
			c.Set(node, 0, cache.DefaultExpiration)
			http.Error(w, "UNHEALTHY", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		// Check the response status code
		if resp.StatusCode == http.StatusOK {
			// Node is healthy
			nodeHealthStatus.WithLabelValues(node).Set(1)
			c.Set(node, 1, cache.DefaultExpiration)
			fmt.Fprintf(w, "HEALTHY\n") // 200 OK is implicit
		} else {
			// Node is unhealthy
			slog.Info("Node health check returned non-200 status", "node", node, "status", resp.StatusCode)
			nodeHealthStatus.WithLabelValues(node).Set(0)
			c.Set(node, 0, cache.DefaultExpiration)
			http.Error(w, "UNHEALTHY", http.StatusServiceUnavailable)
		}
	}
}

// handleHealthz is a simple health check endpoint for the monitor itself.
func handleHealthz(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "OK\n")
}

// startHTTPServer starts the HTTP server to handle health and metrics endpoints.
func startHTTPServer(ctx context.Context, c *cache.Cache, cfg Config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/", handleHealth(c, cfg))
	mux.HandleFunc("/healthz", handleHealthz)
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    *listenAddress,
		Handler: mux,
	}

	// Shutdown the server gracefully when context is done
	go func() {
		<-ctx.Done()
		slog.Info("Shutting down HTTP server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Error shutting down HTTP server", "error", err)
		}
	}()

	slog.Info("Starting HTTP server", "address", *listenAddress)
	return server.ListenAndServe()
}

func main() {
	var loggingLevel = new(slog.LevelVar)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: loggingLevel}))
	slog.SetDefault(logger)

	kingpin.Version(ver)
	kingpin.Parse()

	if *verbose {
		loggingLevel.Set(slog.LevelDebug)
	}

	// Create a configuration struct
	cfg := Config{
		URLScheme: *urlScheme,
		URLPort:   *urlPort,
		URLPath:   *urlPath,
	}

	slog.Info("Program started", "version", ver)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Initialize the cache with the specified cache duration and a cleanup interval
	healthCache := cache.New(time.Duration(*cacheDuration)*time.Second, 10*time.Second)

	// Start the HTTP server
	if err := startHTTPServer(ctx, healthCache, cfg); err != nil && err != http.ErrServerClosed {
		slog.Error("HTTP server encountered an error", "error", err)
		os.Exit(1)
	}

	slog.Info("Program gracefully stopped")
}
