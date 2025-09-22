package worker

import (
	"encoding/gob"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/messages"
	"github.com/crowdsecurity/crowdsec-spoa/internal/api/types"
	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/ban"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	log "github.com/sirupsen/logrus"
)

type WorkerClient struct {
	conn    net.Conn
	mutex   sync.Mutex
	encoder *gob.Encoder
	decoder *gob.Decoder
	// Connection management
	socketPath  string
	workerName  string
	maxRetries  int
	retryDelay  time.Duration
	isConnected bool
}

// connect establishes a connection to the API server
func (w *WorkerClient) connect() error {
	if w.isConnected {
		return nil
	}

	conn, err := net.Dial("unix", w.socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to socket %s: %w", w.socketPath, err)
	}

	w.conn = conn
	w.encoder = gob.NewEncoder(conn)
	w.decoder = gob.NewDecoder(conn)
	w.isConnected = true

	// Connection established successfully

	log.Debugf("Connected to API server at %s", w.socketPath)
	return nil
}

// disconnect closes the connection
func (w *WorkerClient) disconnect() {
	if w.conn != nil {
		w.conn.Close()
		w.conn = nil
		w.encoder = nil
		w.decoder = nil
		w.isConnected = false

		// Connection closed

		log.Debug("Disconnected from API server")
	}
}

// sendRequest sends a typed request and returns the response with retry logic
func (w *WorkerClient) sendRequest(cmd messages.APICommand, data interface{}) (*types.APIResponse, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	var lastErr error

	for attempt := 0; attempt <= w.maxRetries; attempt++ {
		// Ensure we have a connection
		if err := w.connect(); err != nil {
			lastErr = err
			if attempt < w.maxRetries {
				log.Warnf("Connection attempt %d failed: %v, retrying in %v", attempt+1, err, w.retryDelay)
				time.Sleep(w.retryDelay)
				continue
			}
			break
		}

		// Try to send the request
		req := messages.APIRequest{
			Command: cmd,
			Data:    data,
		}

		if err := w.encoder.Encode(req); err != nil {
			log.Warnf("Encode error on attempt %d: %v", attempt+1, err)
			w.disconnect()
			lastErr = err
			if attempt < w.maxRetries {
				time.Sleep(w.retryDelay)
				continue
			}
			break
		}

		// Try to read the response
		var response types.APIResponse
		if err := w.decoder.Decode(&response); err != nil {
			log.Warnf("Decode error on attempt %d: %v - connection likely closed by server", attempt+1, err)
			w.disconnect()
			lastErr = err
			if attempt < w.maxRetries {
				time.Sleep(w.retryDelay)
				continue
			}
			break
		}

		// Success
		return &response, nil
	}

	return nil, fmt.Errorf("failed to send request after %d attempts, last error: %w", w.maxRetries+1, lastErr)
}

func (w *WorkerClient) GetIP(ip string) (remediation.Remediation, error) {
	response, err := w.sendRequest(messages.GetIP, messages.IPRequest{IP: ip})
	if err != nil {
		return remediation.Allow, err
	}

	if !response.Success {
		return remediation.Allow, response.Error
	}

	rem, err := types.GetData[remediation.Remediation](response)
	if err != nil {
		return remediation.Allow, err
	}

	return rem, nil
}

func (w *WorkerClient) GetCN(cn string, ip string) (remediation.Remediation, error) {
	response, err := w.sendRequest(messages.GetCN, messages.CNRequest{
		CountryCode: cn,
		IP:          ip,
	})
	if err != nil {
		return remediation.Allow, err
	}

	if !response.Success {
		return remediation.Allow, response.Error
	}

	rem, err := types.GetData[remediation.Remediation](response)
	if err != nil {
		return remediation.Allow, err
	}

	return rem, nil
}

func (w *WorkerClient) GetGeoIso(ip string) (string, error) {
	response, err := w.sendRequest(messages.GetGeoIso, messages.GeoRequest{IP: ip})
	if err != nil {
		return "", err
	}

	if !response.Success {
		return "", response.Error
	}

	iso, err := types.GetData[string](response)
	if err != nil {
		return "", err
	}

	return iso, nil
}

func (w *WorkerClient) GetHost(h string) (*host.Host, error) {
	response, err := w.sendRequest(messages.GetHosts, messages.HostsRequest{Host: h})
	if err != nil {
		return nil, err
	}

	if !response.Success {
		return nil, response.Error
	}

	hostResp, err := types.GetData[*types.HostResponse](response)
	if err != nil {
		return nil, err
	}

	// Convert HostResponse to host.Host
	result := &host.Host{
		Host: hostResp.Host,
		Captcha: captcha.Captcha{
			SiteKey:             hostResp.CaptchaSiteKey,
			Provider:            hostResp.CaptchaProvider,
			FallbackRemediation: hostResp.CaptchaFallbackRemediation,
		},
		Ban: ban.Ban{
			ContactUsURL: hostResp.BanContactUsURL,
		},
		AppSec: appsec.AppSec{
			AlwaysSend: hostResp.AppSecAlwaysSend,
		},
	}

	return result, nil
}

func (w *WorkerClient) GetHostCookie(h string, ssl string) (http.Cookie, error) {
	sslBool := ssl == "true"
	response, err := w.sendRequest(messages.GetHostCookie, messages.HostCookieRequest{
		Host: h,
		SSL:  sslBool,
	})
	if err != nil {
		return http.Cookie{}, err
	}

	if !response.Success {
		return http.Cookie{}, response.Error
	}

	cookie, err := types.GetData[http.Cookie](response)
	if err != nil {
		return http.Cookie{}, err
	}

	return cookie, nil
}

func (w *WorkerClient) GetHostSessionKey(h, s, k string) (string, error) {
	response, err := w.sendRequest(messages.GetHostSession, messages.HostSessionRequest{
		Host: h,
		UUID: s,
		Key:  k,
	})
	if err != nil {
		return "", err
	}

	if !response.Success {
		return "", response.Error
	}

	key, err := types.GetData[string](response)
	if err != nil {
		return "", err
	}

	return key, nil
}

func (w *WorkerClient) ValHostCookie(h, cookie string) (string, error) {
	response, err := w.sendRequest(messages.ValHostCookie, messages.HostCookieValidationRequest{
		Host:   h,
		Cookie: cookie,
	})
	if err != nil {
		return "", err
	}

	if !response.Success {
		return "", response.Error
	}

	uuid, err := types.GetData[string](response)
	if err != nil {
		return "", err
	}

	return uuid, nil
}

func (w *WorkerClient) ValHostCaptcha(host, uuid, captcha string) (bool, error) {
	response, err := w.sendRequest(messages.ValHostCaptcha, messages.HostCaptchaValidationRequest{
		Host:     host,
		UUID:     uuid,
		Response: captcha,
	})
	if err != nil {
		return false, err
	}

	if !response.Success {
		return false, response.Error
	}

	valid, err := types.GetData[bool](response)
	if err != nil {
		return false, err
	}

	return valid, nil
}

func (w *WorkerClient) SetHostSessionKey(h, s, k, v string) (bool, error) {
	response, err := w.sendRequest(messages.SetHostSession, messages.HostSessionRequest{
		Host:  h,
		UUID:  s,
		Key:   k,
		Value: v,
	})
	if err != nil {
		return false, err
	}

	if !response.Success {
		return false, response.Error
	}

	set, err := types.GetData[bool](response)
	if err != nil {
		return false, err
	}

	return set, nil
}

func (w *WorkerClient) DeleteHostSessionKey(h, s, k string) (bool, error) {
	response, err := w.sendRequest(messages.DelHostSession, messages.HostSessionRequest{
		Host: h,
		UUID: s,
		Key:  k,
	})
	if err != nil {
		return false, err
	}

	if !response.Success {
		return false, response.Error
	}

	deleted, err := types.GetData[bool](response)
	if err != nil {
		return false, err
	}

	return deleted, nil
}

// Close gracefully closes the worker client connection
func (w *WorkerClient) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.conn != nil {
		err := w.conn.Close()
		w.conn = nil
		w.encoder = nil
		w.decoder = nil
		w.isConnected = false
		return err
	}
	return nil
}

func NewWorkerClient(path string, workerName string) (*WorkerClient, error) {
	// Register gob types before creating the client
	messages.RegisterGobTypes()

	client := &WorkerClient{
		socketPath:  path,
		workerName:  workerName,
		maxRetries:  3,
		retryDelay:  100 * time.Millisecond,
		isConnected: false,
	}

	// Connection will be established lazily on first use

	return client, nil
}
