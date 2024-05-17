package worker

import (
	"encoding/gob"
	"net"
	"strconv"
	"strings"
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
	n, err := w.conn.Write(_b)
	if err != nil {
		log.Errorf("error writing to socket: %s", err)
		return
	}
	log.Info("wrote ", n, " bytes")
}

func (w *WorkerClient) GetIP(ip string) remediation.Remediation {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("get", "ip", "", ip)

	remediation := remediation.Allow

	err := w.decoder.Decode(&remediation)
	if err != nil {
		log.Errorf("error decoding: %s", err)
	}

	return remediation
}

func (w *WorkerClient) GetCN(cn string) remediation.Remediation {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	remediation := remediation.Allow
	w.get("get", "cn", "", cn)

	err := w.decoder.Decode(&remediation)
	if err != nil {
		log.Errorf("error decoding: %s", err)
	}

	return remediation
}

func (w *WorkerClient) GetGeoIso(ip string) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("get", "geo", "iso", ip)
	iso := ""
	w.decoder.Decode(&iso)
	return iso
}

func (w *WorkerClient) GetHost(h string) *host.Host {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("get", "hosts", "", h)
	var hStruct *host.Host
	w.decoder.Decode(&hStruct)
	return hStruct
}

func (w *WorkerClient) GetHostCookie(h string, ssl string) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("get", "host", "cookie", h, ssl)
	cookie := ""
	w.decoder.Decode(&cookie)
	return cookie
}

func NewWorkerClient(path string) *WorkerClient {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil
	}
	wGob := gob.NewDecoder(c)
	return &WorkerClient{conn: c, mutex: &sync.Mutex{}, decoder: wGob}
}
