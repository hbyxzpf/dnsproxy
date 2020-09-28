package dnscrypt

import (
	"net"

	"github.com/miekg/dns"
)

// Handler is implemented by any value that implements ServeDNS.
type Handler interface {
	ServeDNS(rw ResponseWriter, r *dns.Msg) error
}

// ResponseWriter - interface that needs to be implemented for different protocols
type ResponseWriter interface {
	LocalAddr() net.Addr       // LocalAddr - local socket address
	RemoteAddr() net.Addr      // RemoteAddr - remote client socket address
	WriteMsg(m *dns.Msg) error // WriteMsg - writes response message to the client
}

// DefaultHandler - default Handler implementation
// that is used by Server if custom handler is not configured
var DefaultHandler Handler = &defaultHandler{}

type defaultHandler struct{}

// ServeDNS - implements Handler interface
func (h *defaultHandler) ServeDNS(rw ResponseWriter, r *dns.Msg) error {
	// Google DNS
	res, err := dns.Exchange(r, "8.8.8.8:53")
	if err != nil {
		return err
	}
	return rw.WriteMsg(res)
}
