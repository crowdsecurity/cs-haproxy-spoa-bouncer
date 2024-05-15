package worker

import "net"

type WorkerClient struct {
	conn net.Conn
}

func (w *WorkerClient) GetIP(ip string) string {
	w.conn.Write([]byte("get ip " + ip))
	buffer := make([]byte, 16)
	n, err := w.conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n-1])
}

func (w *WorkerClient) GetCN(cn string) string {
	w.conn.Write([]byte("get cn " + cn))
	buffer := make([]byte, 16)
	n, err := w.conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n-1])
}

func (w *WorkerClient) GetGeoIso(ip string) string {
	w.conn.Write([]byte("get geo " + ip + " iso"))
	buffer := make([]byte, 16)
	n, err := w.conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n-1])
}

func NewWorkerClient(path string) *WorkerClient {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil
	}
	return &WorkerClient{conn: c}
}
