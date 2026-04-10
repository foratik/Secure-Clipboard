package middleware

import (
	"net/http"
	"strings"
)

// CORS returns middleware that adds permissive Cross-Origin headers.
// allowedOrigins may contain "*" for wildcard or a list of specific origins.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	wildcard := len(allowedOrigins) == 1 && allowedOrigins[0] == "*"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			allowed := wildcard || containsOrigin(allowedOrigins, origin)
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Request-ID")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func containsOrigin(list []string, origin string) bool {
	for _, o := range list {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}
