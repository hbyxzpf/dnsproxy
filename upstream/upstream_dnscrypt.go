package upstream

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/dnscrypt"
	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

//
// DNSCrypt
//
type dnsCrypt struct {
	boot       *bootstrapper
	client     *dnscrypt.Client       // DNSCrypt client properties
	serverInfo *dnscrypt.ResolverInfo // DNSCrypt resolver info

	sync.RWMutex // protects DNSCrypt client
}

func (p *dnsCrypt) Address() string { return p.boot.address }

func (p *dnsCrypt) Exchange(m *dns.Msg) (*dns.Msg, error) {
	reply, err := p.exchangeDNSCrypt(m)

	if os.IsTimeout(err) || err == io.EOF {
		// If request times out, it is possible that the server configuration has been changed.
		// It is safe to assume that the key was rotated (for instance, as it is described here: https://dnscrypt.pl/2017/02/26/how-key-rotation-is-automated/).
		// We should re-fetch the server certificate info so that the new requests were not failing.
		p.Lock()
		p.client = nil
		p.serverInfo = nil
		p.Unlock()

		// Retry the request one more time
		return p.exchangeDNSCrypt(m)
	}

	return reply, err
}

// exchangeDNSCrypt attempts to send the DNS query and returns the response
func (p *dnsCrypt) exchangeDNSCrypt(m *dns.Msg) (*dns.Msg, error) {
	var client *dnscrypt.Client
	var resolverInfo *dnscrypt.ResolverInfo

	p.RLock()
	client = p.client
	resolverInfo = p.serverInfo
	p.RUnlock()

	now := uint32(time.Now().Unix())
	if client == nil || resolverInfo == nil || resolverInfo.ResolverCert.NotAfter < now {
		p.Lock()

		// Using "udp" for DNSCrypt upstreams by default
		client = &dnscrypt.Client{Timeout: p.boot.timeout}
		ri, err := client.Dial(p.boot.address)

		if err != nil {
			p.Unlock()
			return nil, errorx.Decorate(err, "failed to fetch certificate info from %s", p.Address())
		}

		p.client = client
		p.serverInfo = ri
		resolverInfo = ri
		p.Unlock()
	}

	reply, err := client.Exchange(m, resolverInfo)

	if reply != nil && reply.Truncated {
		log.Tracef("Truncated message was received, retrying over TCP, question: %s", m.Question[0].String())
		tcpClient := dnscrypt.Client{Timeout: p.boot.timeout, Net: "tcp"}
		reply, err = tcpClient.Exchange(m, resolverInfo)
	}

	if err == nil && reply != nil && reply.Id != m.Id {
		err = dns.ErrId
	}

	return reply, err
}
