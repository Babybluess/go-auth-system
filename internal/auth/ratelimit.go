package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	loginLimiters   = make(map[string]*ipLimiter)
	loginLimitersMu sync.Mutex
)

func init() {
	go func() {
		for {
			time.Sleep(time.Minute)
			loginLimitersMu.Lock()
			for ip, l := range loginLimiters {
				if time.Since(l.lastSeen) > time.Hour {
					delete(loginLimiters, ip)
				}
			}
			loginLimitersMu.Unlock()
		}
	}()
}

func getLoginLimiter(ip string) *rate.Limiter {
	loginLimitersMu.Lock()
	defer loginLimitersMu.Unlock()
	l, ok := loginLimiters[ip]
	if !ok {
		// 5 burst, then 1 token per 10 seconds (~6/min steady-state after burst)
		l = &ipLimiter{limiter: rate.NewLimiter(rate.Every(10*time.Second), 5)}
		loginLimiters[ip] = l
	}
	l.lastSeen = time.Now()
	return l.limiter
}

// LoginRateLimit limits /login to a burst of 5 requests, then 1 per 10 seconds per IP.
func LoginRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		if !getLoginLimiter(ip).Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "too many login attempts, please try again later"})
			return
		}

		next.ServeHTTP(w, r)
	})
}
