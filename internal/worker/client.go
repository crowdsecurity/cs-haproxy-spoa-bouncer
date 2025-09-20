package worker

import (
	"encoding/gob"
	"net"
	"net/http"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/messages"
	"github.com/crowdsecurity/crowdsec-spoa/internal/api/types"
	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/ban"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
)

type WorkerClient struct {
	conn    net.Conn
	mutex   sync.Mutex
	encoder *gob.Encoder
	decoder *gob.Decoder
}

// sendRequest sends a typed request and returns the response
func (w *WorkerClient) sendRequest(cmd messages.APICommand, data interface{}) (*types.APIResponse, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	req := messages.APIRequest{
		Command: cmd,
		Data:    data,
	}

	if err := w.encoder.Encode(req); err != nil {
		return nil, err
	}

	var response types.APIResponse
	if err := w.decoder.Decode(&response); err != nil {
		return nil, err
	}

	return &response, nil
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

func (w *WorkerClient) GetHostUnsetCookie(h string, ssl string) (http.Cookie, error) {
	sslBool := ssl == "true"
	response, err := w.sendRequest(messages.GetHostUnsetCookie, messages.HostCookieRequest{
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

func NewWorkerClient(path string) (*WorkerClient, error) {
	// Register gob types before creating the client
	messages.RegisterGobTypes()

	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	encoder := gob.NewEncoder(c)
	decoder := gob.NewDecoder(c)
	return &WorkerClient{
		conn:    c,
		encoder: encoder,
		decoder: decoder,
	}, nil
}
