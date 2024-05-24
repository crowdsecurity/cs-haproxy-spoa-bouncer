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

func (w *WorkerClient) write(_b []byte) error {
	n, err := w.conn.Write(_b)
	if err != nil {
		return err
	}
	log.Info("wrote ", n, " bytes")
	return nil
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
	_jd := strings.Join(args, " ")
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

func (w *WorkerClient) GetIP(ip string) remediation.Remediation {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("ip", "", ip)

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
	w.get("cn", "", cn)

	err := w.decoder.Decode(&remediation)
	if err != nil {
		log.Errorf("error decoding: %s", err)
	}

	return remediation
}

func (w *WorkerClient) GetGeoIso(ip string) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("geo", "iso", ip)
	iso := ""
	w.decoder.Decode(&iso)
	return iso
}

func (w *WorkerClient) GetHost(h string) *host.Host {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("hosts", "", h)
	var hStruct *host.Host
	w.decoder.Decode(&hStruct)
	return hStruct
}

func (w *WorkerClient) GetHostCookie(h string, ssl string) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.get("host", "cookie", h, ssl)
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
