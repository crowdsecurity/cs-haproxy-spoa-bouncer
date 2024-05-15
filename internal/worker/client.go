package worker

import "net"

type WorkerClient struct {
	path string
}

func (w *WorkerClient) GetPath() string {
	return w.path
}

func (w *WorkerClient) GetIP(ip string) string {
	conn, err := net.Dial("unix", w.path)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.Write([]byte("get ip " + ip))
	buffer := make([]byte, 8)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n])
}

func (w *WorkerClient) GetCN(cn string) string {
	conn, err := net.Dial("unix", w.path)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.Write([]byte("get cn " + cn))
	buffer := make([]byte, 8)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n])
}

func (w *WorkerClient) GetGeoIso(ip string) string {
	conn, err := net.Dial("unix", w.path)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.Write([]byte("get geo " + ip + " iso"))
	buffer := make([]byte, 8)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n])
}

func NewWorkerClient(path string) *WorkerClient {
	return &WorkerClient{path: path}
}
