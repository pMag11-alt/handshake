package handshake

import (
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"time"
)

// halfConn is one direction of the record layer.
type halfConn struct {
	suite  *suite
	aead   aead
	iv     []byte
	seq    uint64
	secret []byte
}

func (hc *halfConn) setSecret(s *suite, secret []byte) error {
	key, iv := s.trafficKeys(secret)
	a, err := s.newAEAD(key)
	if err != nil {
		return err
	}
	hc.suite, hc.aead, hc.iv, hc.seq, hc.secret = s, a, iv, 0, secret
	return nil
}

// nonce is the static IV XORed with the 64-bit record sequence number.
func (hc *halfConn) nonce() []byte {
	n := make([]byte, len(hc.iv))
	copy(n, hc.iv)
	for i := 0; i < 8; i++ {
		n[len(n)-1-i] ^= byte(hc.seq >> (8 * i))
	}
	return n
}

// seal encrypts TLSInnerPlaintext (content || type) into a full record.
func (hc *halfConn) seal(typ uint8, payload []byte) []byte {
	inner := make([]byte, 0, len(payload)+1)
	inner = append(append(inner, payload...), typ)
	length := len(inner) + hc.aead.Overhead()
	header := []byte{recordApplicationData, 0x03, 0x03, byte(length >> 8), byte(length)}
	out := hc.aead.Seal(header, hc.nonce(), inner, header)
	hc.seq++
	return out
}

// open decrypts a record body and strips the zero padding.
func (hc *halfConn) open(header, body []byte) (uint8, []byte, error) {
	inner, err := hc.aead.Open(nil, hc.nonce(), body, header)
	if err != nil {
		return 0, nil, fail(alertBadRecordMAC, "record failed authentication")
	}
	hc.seq++
	i := len(inner) - 1
	for i >= 0 && inner[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, fail(alertUnexpectedMessage, "record has no content type")
	}
	return inner[i], inner[:i], nil
}

// Conn is a TLS 1.3 connection. It implements net.Conn.
type Conn struct {
	conn     net.Conn
	isClient bool
	config   *Config

	handshakeMu   sync.Mutex
	handshakeDone bool
	handshakeErr  error

	inMu, outMu sync.Mutex
	in, out     halfConn

	raw    []byte // bytes read from the socket but not yet parsed
	hsBuf  []byte // handshake bytes waiting for a complete message
	appBuf []byte // decrypted application data not yet returned
	// readErr sticks once the read side fails or the peer closes.
	readErr error

	// ccsAllowed covers the window where a middlebox-compatibility
	// change_cipher_spec record may arrive and must be ignored.
	ccsAllowed   bool
	firstRecord  bool
	closeSent    bool
	clientRandom []byte

	state ConnectionState
}

// Client wraps conn as the client side of a TLS connection.
func Client(conn net.Conn, config *Config) *Conn {
	if config == nil {
		config = &Config{}
	}
	return &Conn{conn: conn, isClient: true, config: config, firstRecord: true}
}

// Server wraps conn as the server side; config.Certificate must be set.
func Server(conn net.Conn, config *Config) *Conn {
	return &Conn{conn: conn, config: config}
}

// Dial connects and completes a handshake. An empty ServerName is filled
// from addr.
func Dial(network, addr string, config *Config) (*Conn, error) {
	cfg := Config{}
	if config != nil {
		cfg = *config
	}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		cfg.ServerName = host
	}
	raw, err := net.DialTimeout(network, addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	c := Client(raw, &cfg)
	if err := c.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

type listener struct {
	net.Listener
	config *Config
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

// Listen returns a listener whose connections speak TLS 1.3. The
// handshake runs on the first Read or Write.
func Listen(network, addr string, config *Config) (net.Listener, error) {
	if config == nil || config.Certificate == nil {
		return nil, errors.New("tls: Listen needs Config.Certificate")
	}
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &listener{l, config}, nil
}

func (c *Conn) tracef(format string, args ...any) {
	if c.config.Trace != nil {
		c.config.Trace(fmt.Sprintf(format, args...))
	}
}

func (c *Conn) keyLog(label string, secret []byte) {
	if c.config.KeyLogWriter != nil {
		fmt.Fprintf(c.config.KeyLogWriter, "%s %x %x\n", label, c.clientRandom, secret)
	}
}

// ---- record reading ------------------------------------------------------------------

func (c *Conn) fill(n int) error {
	for len(c.raw) < n {
		buf := make([]byte, max(4096, n-len(c.raw)))
		k, err := c.conn.Read(buf)
		c.raw = append(c.raw, buf[:k]...)
		if err != nil {
			if len(c.raw) >= n {
				return nil
			}
			if err == io.EOF && len(c.raw) > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

// readRecord returns the next record's content type and plaintext,
// decrypting it, skipping compatibility CCS records and handling alerts.
func (c *Conn) readRecord() (uint8, []byte, error) {
	for {
		if err := c.fill(5); err != nil {
			return 0, nil, err
		}
		header := c.raw[:5]
		typ := header[0]
		length := int(header[3])<<8 | int(header[4])
		if length > maxCiphertext {
			return 0, nil, fail(alertRecordOverflow, "record of %d bytes", length)
		}
		if typ < recordChangeCipherSpec || typ > recordApplicationData {
			return 0, nil, fail(alertUnexpectedMessage, "unknown record type %d", typ)
		}
		if err := c.fill(5 + length); err != nil {
			return 0, nil, err
		}
		header = append([]byte(nil), c.raw[:5]...)
		body := c.raw[5 : 5+length]
		c.raw = c.raw[5+length:]

		if typ == recordChangeCipherSpec {
			if !c.ccsAllowed || length != 1 || body[0] != 1 {
				return 0, nil, fail(alertUnexpectedMessage, "unexpected change_cipher_spec")
			}
			continue
		}
		data := body
		if c.in.aead != nil {
			if typ != recordApplicationData {
				return 0, nil, fail(alertUnexpectedMessage, "plaintext record after keys were set")
			}
			var err error
			typ, data, err = c.in.open(header, body)
			if err != nil {
				return 0, nil, err
			}
			if len(data) > maxPlaintext {
				return 0, nil, fail(alertRecordOverflow, "plaintext too long")
			}
		} else {
			data = append([]byte(nil), body...)
		}
		switch typ {
		case recordAlert:
			if len(data) != 2 {
				return 0, nil, fail(alertDecodeError, "malformed alert")
			}
			if alert(data[1]) == alertCloseNotify {
				return 0, nil, io.EOF
			}
			return 0, nil, &AlertError{Alert: alert(data[1]), Received: true}
		case recordHandshake:
			if len(data) == 0 {
				return 0, nil, fail(alertUnexpectedMessage, "empty handshake record")
			}
		}
		return typ, data, nil
	}
}

const maxHandshakeMessage = 1 << 17

// readHandshake returns the next complete handshake message.
func (c *Conn) readHandshake() (typ uint8, body, raw []byte, err error) {
	for {
		if len(c.hsBuf) >= 4 {
			n := int(c.hsBuf[1])<<16 | int(c.hsBuf[2])<<8 | int(c.hsBuf[3])
			if n > maxHandshakeMessage {
				return 0, nil, nil, fail(alertIllegalParameter, "handshake message of %d bytes", n)
			}
			if len(c.hsBuf) >= 4+n {
				raw = c.hsBuf[:4+n]
				c.hsBuf = c.hsBuf[4+n:]
				return raw[0], raw[4:], raw, nil
			}
		}
		rtyp, data, err := c.readRecord()
		if err != nil {
			return 0, nil, nil, err
		}
		if rtyp != recordHandshake {
			return 0, nil, nil, fail(alertUnexpectedMessage, "expected a handshake record, got type %d", rtyp)
		}
		c.hsBuf = append(c.hsBuf, data...)
	}
}

// expect reads a handshake message of the given type and records it in the
// transcript.
func (c *Conn) expect(want uint8, transcript hash.Hash) ([]byte, []byte, error) {
	typ, body, raw, err := c.readHandshake()
	if err != nil {
		return nil, nil, err
	}
	if typ != want {
		return nil, nil, fail(alertUnexpectedMessage, "expected handshake message %d, got %d", want, typ)
	}
	if transcript != nil {
		transcript.Write(raw)
	}
	return body, raw, nil
}

// setReadSecret switches read keys. Handshake messages may not straddle a
// key change, so nothing may be buffered at this point.
func (c *Conn) setReadSecret(s *suite, secret []byte) error {
	if len(c.hsBuf) > 0 {
		return fail(alertUnexpectedMessage, "handshake message spans a key change")
	}
	return c.in.setSecret(s, secret)
}

// ---- record writing ------------------------------------------------------------------

func (c *Conn) writeRecord(typ uint8, data []byte) error {
	for first := true; first || len(data) > 0; first = false {
		n := min(len(data), maxPlaintext)
		chunk := data[:n]
		data = data[n:]
		var rec []byte
		if c.out.aead == nil || typ == recordChangeCipherSpec {
			version := byte(0x03)
			if c.firstRecord {
				version = 0x01 // TLS 1.0 in the very first record, for old middleboxes
				c.firstRecord = false
			}
			rec = append([]byte{typ, 0x03, version, byte(n >> 8), byte(n)}, chunk...)
		} else {
			rec = c.out.seal(typ, chunk)
		}
		if _, err := c.conn.Write(rec); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) writeHandshake(msgs ...[]byte) error {
	var all []byte
	for _, m := range msgs {
		all = append(all, m...)
	}
	return c.writeRecord(recordHandshake, all)
}

func (c *Conn) sendAlert(a alert) {
	level := byte(2)
	if a == alertCloseNotify || a == alertUserCanceled {
		level = 1
	}
	c.writeRecord(recordAlert, []byte{level, byte(a)})
}

// ---- public API -------------------------------------------------------------------------

// Handshake runs the handshake if it has not run yet. Read and Write call
// it automatically.
func (c *Conn) Handshake() error {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	if c.handshakeDone || c.handshakeErr != nil {
		return c.handshakeErr
	}
	c.inMu.Lock()
	c.outMu.Lock()
	start := time.Now()
	var err error
	if c.isClient {
		err = c.clientHandshake()
	} else {
		err = c.serverHandshake()
	}
	c.state.HandshakeDuration = time.Since(start)
	if err != nil {
		var ae *AlertError
		if errors.As(err, &ae) && !ae.Received {
			c.sendAlert(ae.Alert)
		}
		c.handshakeErr = err
		c.tracef("handshake failed: %v", err)
	} else {
		c.handshakeDone = true
		c.tracef("handshake complete in %s", c.state.HandshakeDuration.Round(time.Microsecond))
	}
	c.outMu.Unlock()
	c.inMu.Unlock()
	return err
}

// ConnectionState describes the negotiated connection.
func (c *Conn) ConnectionState() ConnectionState {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	return c.state
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	c.inMu.Lock()
	defer c.inMu.Unlock()
	for len(c.appBuf) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		typ, data, err := c.readRecord()
		if err != nil {
			var ae *AlertError
			if errors.As(err, &ae) && !ae.Received {
				c.outMu.Lock()
				c.sendAlert(ae.Alert)
				c.outMu.Unlock()
			}
			c.readErr = err
			continue
		}
		switch typ {
		case recordApplicationData:
			c.appBuf = data
		case recordHandshake:
			c.hsBuf = append(c.hsBuf, data...)
			if err := c.handlePostHandshake(); err != nil {
				c.readErr = err
			}
		default:
			c.readErr = fail(alertUnexpectedMessage, "unexpected record type %d", typ)
		}
	}
	n := copy(b, c.appBuf)
	c.appBuf = c.appBuf[n:]
	return n, nil
}

// handlePostHandshake processes NewSessionTicket and KeyUpdate messages
// that arrive after the handshake.
func (c *Conn) handlePostHandshake() error {
	for len(c.hsBuf) >= 4 {
		n := int(c.hsBuf[1])<<16 | int(c.hsBuf[2])<<8 | int(c.hsBuf[3])
		if len(c.hsBuf) < 4+n {
			return nil
		}
		typ, body := c.hsBuf[0], c.hsBuf[4:4+n]
		c.hsBuf = c.hsBuf[4+n:]
		switch {
		case typ == typeNewSessionTicket && c.isClient:
			t, err := parseNewSessionTicket(body)
			if err != nil {
				return err
			}
			// Resumption is not implemented; the ticket is only reported.
			c.tracef("<- NewSessionTicket (lifetime %ds, %d-byte ticket) ignored", t.lifetime, len(t.ticket))
		case typ == typeKeyUpdate:
			if len(body) != 1 || body[0] > 1 {
				return fail(alertDecodeError, "malformed KeyUpdate")
			}
			if len(c.hsBuf) > 0 {
				return fail(alertUnexpectedMessage, "KeyUpdate not at a record boundary")
			}
			if err := c.in.setSecret(c.in.suite, c.in.suite.nextTrafficSecret(c.in.secret)); err != nil {
				return err
			}
			c.tracef("<- KeyUpdate (update_requested=%v)", body[0] == 1)
			if body[0] == 1 {
				c.outMu.Lock()
				err := c.updateWriteKey(false)
				c.outMu.Unlock()
				if err != nil {
					return err
				}
			}
		default:
			return fail(alertUnexpectedMessage, "unexpected post-handshake message %d", typ)
		}
	}
	return nil
}

func (c *Conn) updateWriteKey(requestPeer bool) error {
	if err := c.writeRecord(recordHandshake, marshalKeyUpdate(requestPeer)); err != nil {
		return err
	}
	c.tracef("-> KeyUpdate (update_requested=%v)", requestPeer)
	return c.out.setSecret(c.out.suite, c.out.suite.nextTrafficSecret(c.out.secret))
}

// KeyUpdate rotates our sending keys and asks the peer to rotate theirs.
func (c *Conn) KeyUpdate() error {
	if err := c.Handshake(); err != nil {
		return err
	}
	c.outMu.Lock()
	defer c.outMu.Unlock()
	return c.updateWriteKey(true)
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	c.outMu.Lock()
	defer c.outMu.Unlock()
	if c.closeSent {
		return 0, errors.New("tls: write after close")
	}
	if err := c.writeRecord(recordApplicationData, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// CloseWrite sends close_notify without closing the socket.
func (c *Conn) CloseWrite() error {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	if c.closeSent {
		return nil
	}
	c.closeSent = true
	c.sendAlert(alertCloseNotify)
	return nil
}

// Close sends close_notify (after a successful handshake) and closes the
// underlying connection.
func (c *Conn) Close() error {
	c.handshakeMu.Lock()
	done := c.handshakeDone
	c.handshakeMu.Unlock()
	if done {
		c.CloseWrite()
	}
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
