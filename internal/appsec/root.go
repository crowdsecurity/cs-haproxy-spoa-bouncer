package appsec

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

type AppsecRequest struct {
	headers       *http.Header
	body          []byte
	method        string
	httpValidated bool
	tcpValidated  bool
	httpChan      chan<- *http.Request
	url           string
	timeout       time.Duration
	logger        *log.Entry
}

type AppsecConfig struct {
	Enabled        bool       `yaml:"enabled"`
	AppsecUrl      string     `yaml:"appsec_url"`
	logger         *log.Entry `yaml:"-"`
	AppsecRequests map[string]*AppsecRequest
	httpChan       <-chan *http.Request
	ApiKey         string
}

// idempotent function, can be called multiple times
func (a *AppsecRequest) Isready() bool {
	return a.httpValidated && a.tcpValidated
}

func (a *AppsecRequest) GenerateHTTPRequest() *http.Request {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, a.method, a.url, bytes.NewReader(a.body))
	if err != nil {
		a.logger.Errorf("failed to create request: %v", err)
		return nil
	}
	req.Header = *a.headers
	return req
}

func (a *AppsecRequest) ValidateHTTP() {
	a.httpValidated = true
	if a.tcpValidated {
		a.httpChan <- a.GenerateHTTPRequest()
	}
}

func (a *AppsecRequest) ValidateTCP() {
	a.tcpValidated = true
	if a.httpValidated {
		a.httpChan <- a.GenerateHTTPRequest()
	}
}

func (a *AppsecRequest) AddHeaders(header *http.Header) {
	if a.headers != nil {
		a.headers = &http.Header{}
	}
	for key, values := range *header {
		for _, value := range values {
			a.headers.Add(key, value)
		}
	}
}

func (a *AppsecRequest) SetMethod(method string) {
	a.method = method
}

func (a *AppsecRequest) SetBody(body []byte) {
	a.body = body
}

func (a *AppsecConfig) Init(logger *log.Entry) error {
	a.InitLogger(logger)

	if a.Enabled && a.AppsecUrl == "" {
		a.logger.Errorf("appsec is enabled but no appsec_url is set")
		return fmt.Errorf("appsec is enabled but no appsec_url is set")
	}

	if !a.Enabled {
		a.logger.Warnf("appsec is disabled")
		return nil
	}

	a.logger.Debugf("appsec is enabled")
	a.AppsecRequests = make(map[string]*AppsecRequest)
	return nil
}

func (a *AppsecConfig) InitLogger(logger *log.Entry) {
	a.logger = logger.WithField("type", "appsec")
}

// beware of malformed requests
func (a *AppsecConfig) SetMethodAndBody(id string, method string, body []byte) {
	_, ok := a.AppsecRequests[id]
	if ok {
		a.AppsecRequests[id].SetMethod(method)
		a.AppsecRequests[id].SetBody(body)
	} else {
		a.AppsecRequests[id] = &AppsecRequest{
			method: method,
			body:   body,
			logger: a.logger,
			url:    a.AppsecUrl,
		}
	}
}

func (a *AppsecConfig) AddHeaders(id string, headers *http.Header) {
	_, ok := a.AppsecRequests[id]
	if ok {
		a.AppsecRequests[id].AddHeaders(headers)
	} else {
		a.AppsecRequests[id] = &AppsecRequest{
			headers: headers,
			logger:  a.logger,
			url:     a.AppsecUrl,
		}
	}
}
