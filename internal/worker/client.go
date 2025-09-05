package worker

import (
	"encoding/gob"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/types"
	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/ban"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
)

var (
	// gobTypesRegistered ensures gob types are registered only once
	gobTypesRegistered sync.Once
)

// registerGobTypes registers custom types for gob encoding
// This function is safe to call multiple times as it uses sync.Once
func registerGobTypes() {
	gobTypesRegistered.Do(func() {
		// Register types that will be sent as interface{} through gob
		gob.Register(&types.HostResponse{})
		gob.Register(http.Cookie{})
		gob.Register(remediation.Remediation(0)) // Register remediation.Remediation type
	})
}

const (
	headerLength = 52
	lengthIndex  = 0
	lengthSize   = 16
	verbIndex    = 16
	verbSize     = 4
	commandIndex = 20
	commandSize  = 16
	submodIndex  = 36
	submodSize   = 16
)

type WorkerClient struct {
	conn    net.Conn
	mutex   sync.Mutex
	decoder *gob.Decoder
}

func (w *WorkerClient) write(_b []byte) error {
	_, err := w.conn.Write(_b)
	if err != nil {
		return err
	}
	return nil
}

func (w *WorkerClient) joinArgsBytes(args []string) []byte {
	totalLength := 0
	for _, a := range args {
		totalLength += len(a) + 1
	}
	totalLength--

	_b := make([]byte, totalLength)
	offset := 0
	for i, a := range args {
		copy(_b[offset:], a)
		offset += len(a)
		if i < len(args)-1 {
			_b[offset] = 0
			offset++
		}
	}
	return _b
}

func (w *WorkerClient) formatHeaderBytes(verb, command, submodule string, args []string) []byte {
	_jd := w.joinArgsBytes(args)
	_dl := len(_jd)
	_b := make([]byte, headerLength+_dl)
	copy(_b[lengthIndex:lengthIndex+lengthSize], strconv.Itoa(_dl))
	copy(_b[verbIndex:verbIndex+verbSize], verb)
	copy(_b[commandIndex:commandIndex+commandSize], command)
	copy(_b[submodIndex:submodIndex+submodSize], submodule)
	copy(_b[headerLength:], _jd)
	return _b
}

func (w *WorkerClient) executeCommand(verb, command, submodule string, args ...string) error {
	return w.write(w.formatHeaderBytes(verb, command, submodule, args))
}

func (w *WorkerClient) get(command, submodule string, args ...string) error {
	return w.executeCommand("get", command, submodule, args...)
}

func (w *WorkerClient) set(command, submodule string, args ...string) error {
	return w.executeCommand("set", command, submodule, args...)
}

func (w *WorkerClient) val(command, submodule string, args ...string) error {
	return w.executeCommand("val", command, submodule, args...)
}

func (w *WorkerClient) del(command, submodule string, args ...string) error {
	return w.executeCommand("del", command, submodule, args...)
}

func (w *WorkerClient) decode(i interface{}) error {
	if err := w.decoder.Decode(i); err != nil {
		return err
	}
	return nil
}

// decodeResponse decodes an APIResponse and extracts the data or returns the error
func (w *WorkerClient) decodeResponse() (*types.APIResponse, error) {
	var response types.APIResponse
	if err := w.decode(&response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (w *WorkerClient) GetIP(ip string) (remediation.Remediation, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.get("ip", "", ip); err != nil {
		return remediation.Allow, err
	}

	response, err := w.decodeResponse()
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.get("cn", "", cn, ip); err != nil {
		return remediation.Allow, err
	}

	response, err := w.decodeResponse()
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.get("geo", "iso", ip); err != nil {
		return "", err
	}

	response, err := w.decodeResponse()
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.get("hosts", "", h); err != nil {
		return nil, err
	}

	response, err := w.decodeResponse()
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.get("host", "cookie", h, ssl); err != nil {
		return http.Cookie{}, err
	}

	response, err := w.decodeResponse()
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.get("host", "session", h, s, k); err != nil {
		return "", err
	}

	response, err := w.decodeResponse()
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.val("host", "cookie", h, cookie); err != nil {
		return "", err
	}

	response, err := w.decodeResponse()
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.val("host", "captcha", host, uuid, captcha); err != nil {
		return false, err
	}

	response, err := w.decodeResponse()
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.set("host", "session", h, s, k, v); err != nil {
		return false, err
	}

	response, err := w.decodeResponse()
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.del("host", "session", h, s, k); err != nil {
		return false, err
	}

	response, err := w.decodeResponse()
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
	registerGobTypes()

	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	wGob := gob.NewDecoder(c)
	return &WorkerClient{conn: c, decoder: wGob}, nil
}
