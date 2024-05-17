package worker

import (
	"encoding/gob"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
)

type WorkerClient struct {
	conn  net.Conn
	mutex *sync.Mutex
}

func makeHeaderBytes(s string) []byte {
	_b := make([]byte, 16)
	for i, c := range s {
		_b[i] = byte(c)
	}
	return _b
}

func (w *WorkerClient) get(verb, command, submodule string, args ...string) {
	_jd := strings.Join(args, " ")
	_dl := len(_jd)
	_b := make([]byte, 64+_dl)
	_l := makeHeaderBytes(strconv.Itoa(_dl))
	_v := makeHeaderBytes(verb)
	_c := makeHeaderBytes(command)
	_s := makeHeaderBytes(submodule)
	copy(_b[0:16], _l)
	copy(_b[16:32], _v)
	copy(_b[32:48], _c)
	copy(_b[48:64], _s)
	copy(_b[64:64+_dl], []byte(_jd))
	w.conn.Write(_b)
}

func (w *WorkerClient) GetIP(ip string) remediation.Remediation {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("get", "ip", "", ip)

	remediation := remediation.Allow
	rDec := gob.NewDecoder(w.conn)
	rDec.Decode(&remediation)

	return remediation
}

func (w *WorkerClient) GetCN(cn string) remediation.Remediation {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	remediation := remediation.Allow
	w.get("get", "cn", "", cn)

	rDec := gob.NewDecoder(w.conn)
	rDec.Decode(&remediation)

	return remediation
}

func (w *WorkerClient) GetGeoIso(ip string) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("get", "geo", "iso", ip)
	iso := ""
	isoDec := gob.NewDecoder(w.conn)
	isoDec.Decode(&iso)
	return iso
}

func (w *WorkerClient) GetHost(h string) *host.Host {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("get", "hosts", "", h)
	hDec := gob.NewDecoder(w.conn)
	var hStruct *host.Host
	hDec.Decode(hStruct)
	return hStruct
}

func (w *WorkerClient) GetHostCookie(h string, ssl string) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("get", "host", "cookie", h, ssl)
	cookie := ""
	cookieDec := gob.NewDecoder(w.conn)
	cookieDec.Decode(&cookie)
	return cookie
}

func NewWorkerClient(path string) *WorkerClient {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil
	}
	return &WorkerClient{conn: c, mutex: &sync.Mutex{}}
}
