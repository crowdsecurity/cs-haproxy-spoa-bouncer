package worker

import (
	"encoding/gob"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	log "github.com/sirupsen/logrus"
)

type WorkerClient struct {
	conn    net.Conn
	mutex   *sync.Mutex
	decoder *gob.Decoder
}

func (w *WorkerClient) write(_b []byte) error {
	n, err := w.conn.Write(_b)
	if err != nil {
		return err
	}
	log.Info("wrote ", n, " bytes")
	return nil
}

func (w *WorkerClient) joinArgsBytes(args []string) []byte {
	_b := make([]byte, 0)
	for _, a := range args {
		_b = append(_b, []byte(a)...)
		_b = append(_b, 0)
	}
	return _b
}

/*
First 52 bytes of the message are the header:
0 - 16: length of data as string
16 - 20: verb // get, set, val, help so 4 bytes max
20 - 36: command
36 - 52: submodule
52 - 52+dl: data
*/
func (w *WorkerClient) formatHeaderBytes(verb, command, submodule string, args []string) []byte {
	_jd := w.joinArgsBytes(args)
	_dl := len(_jd)
	_b := make([]byte, 52+_dl)
	copy(_b[0:16], strconv.Itoa(_dl))
	copy(_b[16:20], verb)
	copy(_b[20:36], command)
	copy(_b[36:52], submodule)
	copy(_b[52:], _jd)
	return _b
}

func (w *WorkerClient) get(command, submodule string, args ...string) error {
	return w.write(w.formatHeaderBytes("get", command, submodule, args))
}

func (w *WorkerClient) set(command, submodule string, args ...string) error {
	return w.write(w.formatHeaderBytes("set", command, submodule, args))
}

func (w *WorkerClient) val(command, submodule string, args ...string) error {
	return w.write(w.formatHeaderBytes("val", command, submodule, args))
}

func (w *WorkerClient) del(command, submodule string, args ...string) error {
	return w.write(w.formatHeaderBytes("del", command, submodule, args))
}

func (w *WorkerClient) decode(i interface{}) {
	if err := w.decoder.Decode(i); err != nil {
		log.Errorf("error decoding: %s", err)
	} else {
		log.Info("decoded: ", i)
	}
}

// GetIP returns the remediation for a given IP checks both the ip and the range
func (w *WorkerClient) GetIP(ip string) remediation.Remediation {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("ip", "", ip)

	remediation := remediation.Allow

	w.decode(&remediation)

	return remediation
}

// GetCN returns the remediation for a given CN
func (w *WorkerClient) GetCN(cn string) remediation.Remediation {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	remediation := remediation.Allow
	w.get("cn", "", cn)

	w.decode(&remediation)

	return remediation
}

// GetGeoIso returns the iso code for a given IP
func (w *WorkerClient) GetGeoIso(ip string) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("geo", "iso", ip)
	iso := ""
	w.decode(&iso)
	return iso
}

// GetHost return the first host matching the string
func (w *WorkerClient) GetHost(h string) *host.Host {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("hosts", "", h)
	var hStruct *host.Host
	w.decode(&hStruct)
	return hStruct
}

// GetHostCookie returns a new random cookie for a given host
func (w *WorkerClient) GetHostCookie(h string, ssl string) http.Cookie {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("host", "cookie", h, ssl)
	cookie := http.Cookie{}
	w.decode(&cookie)
	return cookie
}

func (w *WorkerClient) GetHostSessionKey(h, s, k string) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("host", "session", h, s, k)
	key := ""
	w.decode(&key)
	return key
}

func (w *WorkerClient) ValHostCookie(h, cookie string) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.val("host", "cookie", h, cookie)
	uuid := ""
	w.decode(&uuid)
	return uuid
}

func (w *WorkerClient) ValHostCaptcha(host, uuid, captcha string) bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.val("host", "captcha", host, uuid, captcha)
	valid := false
	w.decode(&valid)
	return valid
}

func (w *WorkerClient) SetHostSessionKey(h, s, k, v string) bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.set("host", "session", h, s, k, v)
	set := false
	w.decode(&set)
	return set
}

func (w *WorkerClient) DeleteHostSessionKey(h, s, k string) bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.del("host", "session", h, s, k)
	deleted := false
	w.decode(&deleted)
	return deleted
}

func NewWorkerClient(path string) *WorkerClient {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil
	}
	wGob := gob.NewDecoder(c)
	return &WorkerClient{conn: c, mutex: &sync.Mutex{}, decoder: wGob}
}
