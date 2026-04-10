package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/foratik/secure-clipboard/backend/internal/model"
	"github.com/foratik/secure-clipboard/backend/internal/service"
)

// ClipHandler exposes the clip CRUD operations over HTTP.
type ClipHandler struct {
	svc     *service.ClipService
	log     *slog.Logger
	maxBody int64
}

// NewClipHandler creates a ClipHandler.
func NewClipHandler(svc *service.ClipService, log *slog.Logger, maxBodyBytes int64) *ClipHandler {
	return &ClipHandler{svc: svc, log: log, maxBody: maxBodyBytes}
}

// ---- POST /api/v1/clips ----

// CreateClip handles clip creation.
//
//	POST /api/v1/clips
//	Content-Type: application/json
//
//	{
//	  "content":            "your secret text",
//	  "password":           "optional passphrase",
//	  "duration":           "1h",
//	  "is_one_time":        false,
//	  "is_client_encrypted": false
//	}
func (h *ClipHandler) CreateClip(w http.ResponseWriter, r *http.Request) {
	var req model.CreateClipRequest
	if err := h.decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{"INVALID_REQUEST", err.Error()})
		return
	}

	resp, err := h.svc.CreateClip(r.Context(), &req)
	if err != nil {
		writeError(w, r, err, h.log)
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// ---- GET /api/v1/clips/{code} ----

// GetClip retrieves a clip by its 6-digit code.
//
//	GET /api/v1/clips/{code}
//
// Possible outcomes:
//   - 200 OK + { content }           — server-decrypted content
//   - 200 OK + { payload }           — client-encrypted blob (browser decrypts)
//   - 200 OK + { requires_password } — password-protected; use /unlock
//   - 404 Not Found
//   - 410 Gone (expired)
func (h *ClipHandler) GetClip(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	code = strings.TrimSpace(code)

	resp, err := h.svc.GetClip(r.Context(), code)
	if err != nil {
		writeError(w, r, err, h.log)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ---- POST /api/v1/clips/{code}/unlock ----

// UnlockClip submits a password for a password-protected clip.
//
//	POST /api/v1/clips/{code}/unlock
//	Content-Type: application/json
//
//	{ "password": "passphrase" }
func (h *ClipHandler) UnlockClip(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(chi.URLParam(r, "code"))

	var req model.UnlockClipRequest
	if err := h.decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{"INVALID_REQUEST", err.Error()})
		return
	}

	resp, err := h.svc.UnlockClip(r.Context(), code, req.Password)
	if err != nil {
		writeError(w, r, err, h.log)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ---- POST /api/v1/clips/{code}/consume ----

// ConsumeClip marks a one-time client-encrypted clip as consumed.
// Called by the browser after it has successfully decrypted the payload.
//
//	POST /api/v1/clips/{code}/consume
func (h *ClipHandler) ConsumeClip(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(chi.URLParam(r, "code"))

	if err := h.svc.ConsumeClip(r.Context(), code); err != nil {
		writeError(w, r, err, h.log)
		return
	}

	writeJSON(w, http.StatusOK, model.ConsumeResponse{OK: true})
}

// ---- helpers ----

func (h *ClipHandler) decodeBody(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, h.maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}
