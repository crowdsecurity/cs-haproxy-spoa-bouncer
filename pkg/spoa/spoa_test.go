package spoa

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"

	"github.com/negasus/haproxy-spoe-go/frame"
	"github.com/negasus/haproxy-spoe-go/message"
	"github.com/negasus/haproxy-spoe-go/payload/kv"
	"github.com/negasus/haproxy-spoe-go/varint"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type lframe struct {
	*frame.Frame
	tmp       [5]byte
	varintBuf [10]byte
}

// copied and extended from github.com/negasus/haproxy-spoe-go/frame
func (f *lframe) Encode(dest io.Writer) (n int, err error) {
	buf := bytes.Buffer{}

	buf.WriteByte(byte(f.Type))

	binary.BigEndian.PutUint32(f.tmp[:], f.Flags)

	buf.Write(f.tmp[0:4])

	n = varint.PutUvarint(f.varintBuf[:], f.StreamID)
	buf.Write(f.varintBuf[:n])

	n = varint.PutUvarint(f.varintBuf[:], f.FrameID)
	buf.Write(f.varintBuf[:n])

	var payload []byte

	switch f.Type {
	case frame.TypeAgentHello, frame.TypeAgentDisconnect, frame.TypeHaproxyHello, frame.TypeHaproxyDisconnect:
		payload, err = f.KV.Bytes()
		if err != nil {
			return
		}

	case frame.TypeAgentAck:
		if f.Actions != nil {
			for _, act := range f.Actions {
				payload, err = act.Marshal(payload)
				if err != nil {
					return
				}
			}
		}
	case frame.TypeNotify:
		for _, msg := range *f.Messages {
			payload = append(payload, []byte(msg.Name)...)
			payload = append(payload, uint8(len(msg.KV.Data())))
			b, err := msg.KV.Bytes()
			if err != nil {
				return 0, err
			}
			payload = append(payload, b...)
		}

	default:
		err = fmt.Errorf("unexpected frame type %d", f.Type)
		return
	}

	buf.Write(payload)

	binary.BigEndian.PutUint32(f.tmp[:], uint32(buf.Len()))

	n, err = dest.Write(f.tmp[0:4])
	if err != nil || n != 4 {
		return 0, fmt.Errorf("error write frameSize. writes %d, expect %d, err: %v", n, len(f.tmp), err)
	}

	n, err = dest.Write(buf.Bytes())
	if err != nil || n != buf.Len() {
		return 0, fmt.Errorf("error write frame. writes %d, expect %d, err: %v", n, len(f.tmp), err)
	}

	f.Len = uint32(buf.Len())

	return 4 + buf.Len(), nil
}

type Messages []Message

type Message struct {
	Name string                 `yaml:"name"`
	KV   map[string]interface{} `yaml:"kv"`
}

type FrameYAML struct {
	Type     string                 `yaml:"type"`
	FrameID  uint64                 `yaml:"frame_id"`
	StreamID uint64                 `yaml:"stream_id"`
	KV       map[string]interface{} `yaml:"kv"`
	Messages []Message              `yaml:"messages"`
}

type TestCase struct {
	Name  string      `yaml:"name"`
	Tests []TestFrame `yaml:"tests"`
}

type TestFrame struct {
	Frame  *FrameYAML  `yaml:"frame"`
	Assert *AssertYAML `yaml:"assert"`
}

type AssertYAML struct {
	Type             string `yaml:"type"`
	NotEmptyResponse bool   `yaml:"not_empty_response"`
	Size             int    `yaml:"size"`
	SizeResponse     int    `yaml:"size_response"`
	frame_id         int    `yaml:"frame_id"`
	stream_id        int    `yaml:"stream_id"`
}

func TestHandleSPOA(t *testing.T) {
	files, err := filepath.Glob("./testcases/*.yaml")
	require.NoError(t, err)

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			content, err := os.ReadFile(file)
			require.NoError(t, err)

			var tc TestCase
			err = yaml.Unmarshal(content, &tc)
			require.NoError(t, err)

			for index, test := range tc.Tests {
				if test.Frame.KV != nil {
					tc.Tests[index].Frame.KV = copyKV(test.Frame.KV)
				}
				if test.Frame.Messages != nil {
					for i, msg := range test.Frame.Messages {
						if msg.KV != nil {
							tc.Tests[index].Frame.Messages[i].KV = copyKV(msg.KV)
						}
					}
				}
				fmt.Printf("Messages: %+v\n", spew.Sdump(tc.Tests))
			}
			runSpoaTestCase(t, tc)
		})
	}
}

func copyKV(kv map[string]interface{}) map[string]interface{} {
	newKV := make(map[string]interface{})
	for k, v := range kv {
		switch v.(type) {
		case map[string]interface{}:
			newKV[k] = copyKV(v.(map[string]interface{}))
		case int:
			newKV[k] = uint32(v.(int))
		case []interface{}:
			bytes := make([]byte, len(v.([]interface{})))
			for i, item := range v.([]interface{}) {
				if num, ok := item.(int); ok {
					bytes[i] = byte(num)
				}
			}
			newKV[k] = bytes
		default:
			newKV[k] = v
		}
	}
	return newKV
}

func convertToFrame(fj *FrameYAML) (*lframe, error) {
	f := &lframe{
		Frame: frame.NewFrame(),
	}

	switch fj.Type {
	case "HaproxyHello":
		f.Type = frame.TypeHaproxyHello
	case "HaproxyNotify":
		f.Type = frame.TypeNotify
	default:
		return nil, fmt.Errorf("unknown type %s", fj.Type)
	}

	f.FrameID = fj.FrameID
	f.StreamID = fj.StreamID

	// cf https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt 3.2 (especially 3.2.4 and 3.2.6)
	if len(fj.KV) > 0 {
		if fj.Messages != nil {
			return nil, fmt.Errorf("kv and messages are mutually exclusive")
		}
		for k, v := range fj.KV {
			f.KV.Add(k, v)
		}
	}

	if fj.Messages != nil {
		if fj.KV != nil {
			return nil, fmt.Errorf("kv and messages are mutually exclusive")
		}
		f.Messages = &message.Messages{}
		for _, msg := range fj.Messages {
			m := &message.Message{
				Name: msg.Name,
				KV:   kv.AcquireKV(),
			}
			for k, v := range msg.KV {
				m.KV.Add(k, v)
			}
			*f.Messages = append(*f.Messages, m)
		}

	}

	return f, nil
}

func runSpoaTestCase(t *testing.T, tc TestCase) {
	t.Logf("Running test case: %s\n", tc.Name)

	socketConnChan := make(chan server.SocketConn)
	worker, err := server.NewWorkerSocket(socketConnChan, "./")
	if err != nil {
		t.Fatalf("failed to create worker server: %s", err)
	}
	defer worker.Close()
	worker.NewWorkerListener("wrksocket", os.Getgid())
	os.Setenv("WORKERSOCKET", "crowdsec-spoa-worker-wrksocket.sock")
	os.Setenv("WORKERNAME", "worker")

	spoa, err := New("", "spoa")
	if err != nil {
		t.Fatalf("failed to create Spoa instance: %v", err)
	}

	//spoa
	ctx, cancel := context.WithCancel(context.Background())
	go spoa.ServeUnix(ctx)
	conn, err := net.Dial("unix", "./spoa")
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	t.Logf("Testing case: %s\n", tc.Name)

	// check the frame
	for _, test := range tc.Tests {
		//create the frame
		f, err := convertToFrame(test.Frame)
		if err != nil {
			t.Fatalf("failed to convert frame: %v", err)
		}
		buf := &bytes.Buffer{}

		// debugging purpose
		frameSize, err := f.Encode(buf)
		if err != nil {
			t.Fatalf("expect err is nil, got %v", err)
		}

		bufBytes := buf.Bytes()
		var b strings.Builder
		for _, c := range bufBytes {
			if c < 32 || c > 126 {
				fmt.Fprintf(&b, ".")
			} else {
				fmt.Fprintf(&b, "%c", c)
			}
		}
		t.Logf("Frame: %s\n", b.String())
		t.Logf("Frame: %x\n", buf.Bytes())
		encodedFrameSize := int(binary.BigEndian.Uint32(bufBytes[0:4]))
		t.Logf("Frame size: %d\n", encodedFrameSize)
		assert.Equal(t, frameSize-4, encodedFrameSize)

		// write the frame
		size, err := f.Encode(conn)
		if test.Assert.Size != 0 {
			assert.Equal(t, f.Len, uint32(frameSize)-4)
			assert.Equal(t, test.Assert.Size-4, int(f.Len))
		}

		if err != nil {
			t.Fatalf("failed to encode messages: %v", err)
		}
		t.Logf("Wrote %d bytes\n", size)
		responseFrame := frame.AcquireFrame()
		defer frame.ReleaseFrame(responseFrame)
		responseFrame.Read(conn)
		if err != nil {
			t.Fatalf("failed to read: %v", err)
		}

		// assert response size
		if test.Assert.SizeResponse != 0 {
			assert.Equal(t, test.Assert.SizeResponse, int(responseFrame.Len))
		}

		// assert response type
		if test.Assert.Type != "" {
			var ft frame.Type
			switch test.Assert.Type {
			case "HaproxyDisconnect":
				ft = frame.TypeHaproxyHello
			case "Notify":
				ft = frame.TypeNotify
			case "AgentHello":
				ft = frame.TypeAgentHello
			case "AgentAck":
				ft = frame.TypeAgentAck
			case "AgentDisconnect":
				ft = frame.TypeAgentDisconnect
			default:
				t.Fatalf("unknown type %s", test.Assert.Type)
			}
			assert.Equal(t, ft, responseFrame.Type)
		}
		t.Logf("Response:%v\n", spew.Sdump(responseFrame))

		//assert frame_id
		if test.Assert.frame_id != 0 {
			assert.Equal(t, test.Assert.frame_id, int(responseFrame.FrameID))
		}

		//assert stream_id
		if test.Assert.stream_id != 0 {
			assert.Equal(t, test.Assert.stream_id, int(responseFrame.StreamID))
		}
	}
	cancel()
	worker.Close()
	spoa.Shutdown(ctx)
	// Remove existing socket
	if err := os.Remove("./spoa"); err != nil {
		if !os.IsNotExist(err) {
			t.Fatalf("failed to remove socket: %v", err)
		}
	}
}
