package dnscrypt

import (
	"bytes"
	"net"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// TCPResponseWriter - ResponseWriter implementation for UDP
type TCPResponseWriter struct {
	tcpConn net.Conn
	encrypt encryptionFunc
	query   EncryptedQuery
}

// type check
var _ ResponseWriter = &TCPResponseWriter{}

// LocalAddr - server socket local address
func (w *TCPResponseWriter) LocalAddr() net.Addr {
	return w.tcpConn.LocalAddr()
}

// RemoteAddr - client's address
func (w *TCPResponseWriter) RemoteAddr() net.Addr {
	return w.tcpConn.RemoteAddr()
}

// WriteMsg - writes DNS message to the client
func (w *TCPResponseWriter) WriteMsg(m *dns.Msg) error {
	res, err := w.encrypt(m, w.query)
	if err != nil {
		return err
	}

	return writePrefixed(res, w.tcpConn)
}

// ServeTCP - listens to TCP connections, queries are then processed by Server.Handler.
// It blocks the calling goroutine and to stop it you need to close the listener.
func (s *Server) ServeTCP(l net.Listener) error {
	// Check that server is properly configured
	if !s.validate() {
		return ErrServerConfig
	}

	// Buffer to read incoming messages
	handler := s.Handler
	if handler == nil {
		handler = DefaultHandler
	}

	// Serialize the cert right away and prepare it to be sent to the client
	certBuf, err := s.ResolverCert.Serialize()
	if err != nil {
		return err
	}
	certTxt := packTxtString(certBuf)

	for {
		conn, err := l.Accept()
		if err == nil {
			go func() {
				_ = s.handleTCPConnection(conn, handler, certTxt)
				_ = conn.Close()
			}()
		}

		if err != nil {
			if isConnClosed(err) {
				log.Info("udpListen.ReadFrom() returned because we're reading from a closed connection, exiting loop")
			} else {
				log.Info("got error when reading from UDP listen: %s", err)
			}
			break
		}
	}

	return nil
}

func (s *Server) handleTCPConnection(conn net.Conn, handler Handler, certTxt string) error {
	for {
		b, err := readPrefixed(conn)
		if err != nil {
			return err
		}
		if len(b) < minDNSPacketSize {
			// Ignore the packets that are too short
			return ErrTooShort
		}

		if bytes.Equal(b[:clientMagicSize], s.ResolverCert.ClientMagic[:]) {
			// This is an encrypted message, we should decrypt it
			m, q, err := s.decrypt(b)
			if err != nil {
				return err
			}
			rw := &TCPResponseWriter{
				tcpConn: conn,
				encrypt: s.encrypt,
				query:   q,
			}
			// nolint
			err = handler.ServeDNS(rw, m)
			if err != nil {
				return err
			}
		} else {
			// Most likely this a DNS message requesting the certificate
			reply, err := s.handleHandshake(b, certTxt)
			if err != nil {
				return err
			}
			err = writePrefixed(reply, conn)
			if err != nil {
				return err
			}
		}
	}
}
