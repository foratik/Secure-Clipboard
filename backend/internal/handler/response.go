package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/foratik/secure-clipboard/backend/internal/middleware"
	"github.com/foratik/secure-clipboard/backend/internal/service"
)

// errorBody is the standard JSON error envelope.
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeJSON serialises v as JSON and sets the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Encoding failures are unrecoverable at this point; just log.
		slog.Error("encoding JSON response", "error", err)
	}
}

// writeError maps a service-layer error to an HTTP status + JSON body.
func writeError(w http.ResponseWriter, r *http.Request, err error, log *slog.Logger) {
	switch {
	case errors.Is(err, service.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorBody{"CLIP_NOT_FOUND", "clip not found"})

	case errors.Is(err, service.ErrExpired):
		writeJSON(w, http.StatusGone, errorBody{"CLIP_EXPIRED", "this clip has expired"})

	case errors.Is(err, service.ErrWrongPassword):
		writeJSON(w, http.StatusUnauthorized, errorBody{"WRONG_PASSWORD", "incorrect password"})

	case errors.Is(err, service.ErrNotProtected):
		writeJSON(w, http.StatusBadRequest, errorBody{"NOT_PASSWORD_PROTECTED", "this clip is not password-protected"})

	case errors.Is(err, service.ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, errorBody{"INVALID_REQUEST", err.Error()})

	default:
		reqID := middleware.GetRequestID(r.Context())
		log.ErrorContext(r.Context(), "internal error",
			"request_id", reqID,
			"error", err,
		)
		writeJSON(w, http.StatusInternalServerError, errorBody{"INTERNAL_ERROR", "an unexpected error occurred"})
	}
}
