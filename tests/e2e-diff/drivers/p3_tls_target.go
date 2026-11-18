// Command p3_tls_target is a minimal TLS 1.3 origin used by the P3 real-machine
// suite as the Reality target. Xray 26's Reality needs the target to negotiate
// X25519MLKEM768; Go 1.27 does by default, while the OpenSSL/Python servers in
// the base image only offer X25519 and make the handshake fail.
package main

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: p3_tls_target <addr> <cert> <key>")
	}
	cert, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	ln, err := tls.Listen("tcp", os.Args[1], &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
		}(c)
	}
}
