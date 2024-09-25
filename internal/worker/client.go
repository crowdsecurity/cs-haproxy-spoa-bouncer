package worker

import (
	"encoding/gob"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	log "github.com/sirupsen/logrus"
)

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
	n, err := w.conn.Write(_b)
	if err != nil {
		return err
	}
	log.Debugf("wrote %d bytes", n)
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
		log.Errorf("error decoding: %s", err)
		return err
	}
	return nil
}

func (w *WorkerClient) GetIP(ip string) (remediation.Remediation, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.get("ip", "", ip); err != nil {
		return remediation.Allow, err
	}

	var rem remediation.Remediation
	if err := w.decode(&rem); err != nil {
		return remediation.Allow, err
	}

	return rem, nil
}

func (w *WorkerClient) GetCN(cn string) (remediation.Remediation, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.get("cn", "", cn); err != nil {
		return remediation.Allow, err
	}

	var rem remediation.Remediation
	if err := w.decode(&rem); err != nil {
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

	var iso string
	if err := w.decode(&iso); err != nil {
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

	var hStruct *host.Host
	if err := w.decode(&hStruct); err != nil {
		return nil, err
	}

	if hStruct != nil && hStruct.Host == "" {
		return nil, errors.New("host not found")
	}

	return hStruct, nil
}

func (w *WorkerClient) GetHostCookie(h string, ssl string) (http.Cookie, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.get("host", "cookie", h, ssl); err != nil {
		return http.Cookie{}, err
	}

	var cookie http.Cookie
	if err := w.decode(&cookie); err != nil {
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

	var key string
	if err := w.decode(&key); err != nil {
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

	var uuid string
	if err := w.decode(&uuid); err != nil {
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

	var valid bool
	if err := w.decode(&valid); err != nil {
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

	var set bool
	if err := w.decode(&set); err != nil {
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

	var deleted bool
	if err := w.decode(&deleted); err != nil {
		return false, err
	}

	return deleted, nil
}

func NewWorkerClient(path string) (*WorkerClient, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	wGob := gob.NewDecoder(c)
	return &WorkerClient{conn: c, decoder: wGob}, nil
}
