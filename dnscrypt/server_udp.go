package dnscrypt

import (
	"bytes"
	"net"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

type encryptionFunc func(m *dns.Msg, q EncryptedQuery) ([]byte, error)

// UDPResponseWriter - ResponseWriter implementation for UDP
type UDPResponseWriter struct {
	udpConn    *net.UDPConn
	remoteAddr net.Addr
	encrypt    encryptionFunc
	query      EncryptedQuery
}

// type check
var _ ResponseWriter = &UDPResponseWriter{}

// LocalAddr - server socket local address
func (w *UDPResponseWriter) LocalAddr() net.Addr {
	return w.udpConn.LocalAddr()
}

// RemoteAddr - client's address
func (w *UDPResponseWriter) RemoteAddr() net.Addr {
	return w.remoteAddr
}

// WriteMsg - writes DNS message to the client
func (w *UDPResponseWriter) WriteMsg(m *dns.Msg) error {
	res, err := w.encrypt(m, w.query)
	if err != nil {
		return err
	}

	_, _ = w.udpConn.WriteTo(res, w.remoteAddr)
	return nil
}

// ServeUDP - listens to UDP connections, queries are then processed by Server.Handler.
// It blocks the calling goroutine and to stop it you need to close the listener.
func (s *Server) ServeUDP(l *net.UDPConn) error {
	// Check that server is properly configured
	if !s.validate() {
		return ErrServerConfig
	}

	// Buffer to read incoming messages
	b := make([]byte, dns.MaxMsgSize)
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
		n, addr, err := l.ReadFrom(b)
		if n < minDNSPacketSize {
			// Ignore the packets that are too short
			continue
		}

		if bytes.Equal(b[:clientMagicSize], s.ResolverCert.ClientMagic[:]) {
			// This is an encrypted message, we should decrypt it
			m, q, err := s.decrypt(b[:n])
			if err == nil {
				rw := &UDPResponseWriter{
					udpConn:    l,
					remoteAddr: addr,
					encrypt:    s.encrypt,
					query:      q,
				}
				// nolint
				go handler.ServeDNS(rw, m)
			}
		} else {
			// Most likely this a DNS message requesting the certificate
			reply, err := s.handleHandshake(b, certTxt)
			if err == nil {
				_, _ = l.WriteTo(reply, addr)
			}
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
