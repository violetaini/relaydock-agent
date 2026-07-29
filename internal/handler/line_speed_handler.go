package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/violetaini/relaydock-agent/internal/linespeed"
)

type lineSpeedService interface {
	Status(context.Context) linespeed.Status
	Install(context.Context, bool) (linespeed.Status, error)
	Remove(context.Context) (linespeed.Status, error)
	Run(context.Context) (linespeed.Result, error)
}

// LineSpeedHandler exposes the optional speedtest-cli lifecycle and test RPCs.
type LineSpeedHandler struct {
	manage  *ManageHandler
	service lineSpeedService
}

func NewLineSpeedHandler(manage *ManageHandler, service *linespeed.Service) *LineSpeedHandler {
	return newLineSpeedHandler(manage, service)
}

func newLineSpeedHandler(manage *ManageHandler, service lineSpeedService) *LineSpeedHandler {
	return &LineSpeedHandler{manage: manage, service: service}
}

type lineSpeedStatusResponse struct {
	Success bool `json:"success"`
	linespeed.Status
}

type lineSpeedRunResponse struct {
	Success bool             `json:"success"`
	Result  linespeed.Result `json:"result"`
}

type lineSpeedInstallRequest struct {
	AcceptLicense bool `json:"accept_license"`
}

func (h *LineSpeedHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if !h.validate(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, lineSpeedStatusResponse{
		Success: true,
		Status:  h.service.Status(r.Context()),
	})
}

func (h *LineSpeedHandler) HandleInstall(w http.ResponseWriter, r *http.Request) {
	if !h.validate(w, r, http.MethodPost) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request lineSpeedInstallRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "Installation requires accept_license: true")
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid installation request")
		return
	}
	if !request.AcceptLicense {
		writeError(w, http.StatusBadRequest, linespeed.ErrLicenseNotAccepted.Error())
		return
	}
	status, err := h.service.Install(r.Context(), request.AcceptLicense)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, lineSpeedStatusResponse{Success: true, Status: status})
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func (h *LineSpeedHandler) HandleRemove(w http.ResponseWriter, r *http.Request) {
	if !h.validate(w, r, http.MethodPost) {
		return
	}
	status, err := h.service.Remove(r.Context())
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, lineSpeedStatusResponse{Success: true, Status: status})
}

func (h *LineSpeedHandler) HandleRun(w http.ResponseWriter, r *http.Request) {
	if !h.validate(w, r, http.MethodPost) {
		return
	}
	result, err := h.service.Run(r.Context())
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, lineSpeedRunResponse{Success: true, Result: result})
}

func (h *LineSpeedHandler) validate(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return false
	}
	// Installing software and consuming line bandwidth are privileged operations.
	// Unlike legacy read-only child endpoints, never allow these routes with an empty token.
	if h.manage == nil || h.manage.configToken == "" || !h.manage.authenticate(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return false
	}
	if h.service == nil {
		writeError(w, http.StatusServiceUnavailable, "Line speed test service unavailable")
		return false
	}
	return true
}

func (h *LineSpeedHandler) writeServiceError(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	switch {
	case errors.Is(err, linespeed.ErrBusy), errors.Is(err, linespeed.ErrNotInstalled), errors.Is(err, linespeed.ErrNotManaged):
		statusCode = http.StatusConflict
	case errors.Is(err, linespeed.ErrLicenseNotAccepted):
		statusCode = http.StatusBadRequest
	case errors.Is(err, linespeed.ErrUnsupported):
		statusCode = http.StatusNotImplemented
	case errors.Is(err, context.DeadlineExceeded):
		statusCode = http.StatusGatewayTimeout
	case errors.Is(err, context.Canceled):
		statusCode = http.StatusRequestTimeout
	}
	writeError(w, statusCode, err.Error())
}
