package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestServerUDPServeCert(t *testing.T) {
	testServerServeCert(t, "udp")
}

func TestServerTCPServeCert(t *testing.T) {
	testServerServeCert(t, "tcp")
}

func TestServerUDPRespondMessages(t *testing.T) {
	testServerRespondMessages(t, "udp")
}

func TestServerTCPRespondMessages(t *testing.T) {
	testServerRespondMessages(t, "tcp")
}

func testServerServeCert(t *testing.T, network string) {
	srv := newTestServer(t, &testHandler{})
	defer srv.Close()

	client := &Client{
		Net:     network,
		Timeout: 1 * time.Second,
	}

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if network == "tcp" {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	assert.Nil(t, err)
	assert.NotNil(t, ri)

	assert.Equal(t, ri.ProviderName, srv.server.ProviderName)
	assert.True(t, bytes.Equal(srv.server.ResolverCert.ClientMagic[:], ri.ResolverCert.ClientMagic[:]))
	assert.Equal(t, srv.server.ResolverCert.EsVersion, ri.ResolverCert.EsVersion)
	assert.Equal(t, srv.server.ResolverCert.Signature, ri.ResolverCert.Signature)
	assert.Equal(t, srv.server.ResolverCert.NotBefore, ri.ResolverCert.NotBefore)
	assert.Equal(t, srv.server.ResolverCert.NotAfter, ri.ResolverCert.NotAfter)
	assert.True(t, bytes.Equal(srv.server.ResolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
	assert.True(t, bytes.Equal(srv.server.ResolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
}

func testServerRespondMessages(t *testing.T, network string) {
	srv := newTestServer(t, &testHandler{})
	defer srv.Close()

	client := &Client{
		Timeout: 1 * time.Second,
		Net:     network,
	}

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if network == "tcp" {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	assert.Nil(t, err)
	assert.NotNil(t, ri)

	conn, err := net.Dial(network, stamp.ServerAddrStr)
	assert.Nil(t, err)

	for i := 0; i < 10; i++ {
		m := createTestMessage()
		res, err := client.ExchangeConn(conn, m, ri)
		assert.Nil(t, err)
		assertTestMessageResponse(t, res)
	}
}

type testServer struct {
	server     *Server
	resolverPk ed25519.PublicKey
	udpConn    *net.UDPConn
	tcpListen  net.Listener
	handler    Handler
}

func (s *testServer) TCPAddr() *net.TCPAddr {
	return s.tcpListen.Addr().(*net.TCPAddr)
}

func (s *testServer) UDPAddr() *net.UDPAddr {
	return s.udpConn.LocalAddr().(*net.UDPAddr)
}

func (s *testServer) Close() {
	_ = s.udpConn.Close()
	_ = s.tcpListen.Close()
}

func newTestServer(t *testing.T, handler Handler) *testServer {
	cert, publicKey, _ := generateValidCert(t)
	s := &Server{
		ProviderName: "2.dnscrypt-cert.example.org",
		ResolverCert: cert,
		Handler:      handler,
	}

	srv := &testServer{
		server:     s,
		resolverPk: publicKey,
	}

	var err error
	srv.tcpListen, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	assert.Nil(t, err)
	srv.udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	assert.Nil(t, err)

	go s.ServeUDP(srv.udpConn)
	go s.ServeTCP(srv.tcpListen)
	return srv
}

type testHandler struct{}

// ServeDNS - implements Handler interface
func (h *testHandler) ServeDNS(rw ResponseWriter, r *dns.Msg) error {
	// Google DNS
	res := new(dns.Msg)
	res.SetReply(r)
	answer := new(dns.A)
	answer.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeA,
		Ttl:    300,
		Class:  dns.ClassINET,
	}
	answer.A = net.IPv4(8, 8, 8, 8)
	res.Answer = append(res.Answer, answer)
	return rw.WriteMsg(res)
}
