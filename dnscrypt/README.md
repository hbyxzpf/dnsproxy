# DNSCrypt Go Library

Golang-implementation of DNSCrypt client and server.

## Client

```
// AdGuard DNS stamp
stampStr := "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"

// Initializing the DNSCrypt client
c := dnscrypt.Client{Net: "udp", Timeout: 10 * time.Second}

// Fetching and validating the server certificate
resolverInfo, err := client.Dial(stampStr)
if err != nil {
    return err
}

// Create a DNS request
req := dns.Msg{}
req.Id = dns.Id()
req.RecursionDesired = true
req.Question = []dns.Question{
    {Name: "google-public-dns-a.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
}

// Get the DNS response
reply, err := c.Exchange(&req, resolverInfo)
```

## Server

TODO