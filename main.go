package main

import (
	// ssh server
	"fmt"
	"log"
	"net"
	"os"

	"tailscale.com/tsnet"
)
type Server interface {
	Serve(net.Listener) error
	HandleConn(net.Conn)
}

func withTCP(server Server) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *configPort))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	if err := server.Serve(listener); err != nil {
		log.Fatalf("failed to serve SSH: %v", err)
	}
}

func withTailscale(server Server) {
	ts := &tsnet.Server{
		Hostname: *configTSName,
		Dir: *configStateDir,
	}
	defer ts.Close()
	if *configVerbose {
		ts.Logf = log.New(os.Stderr, "[tsnet] ", log.LstdFlags).Printf
	} else {
		ts.Logf = nil
	}
	if *configExposeSSH {
		initTailscaleSSH(ts, server)
	}
	// Why is this needed if we use configExposeSSH?
	//  If we disable it, we get a message: ssh: server has no host keys
	listener, err := ts.Listen("tcp", fmt.Sprintf(":%d", *configPort))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	if err := server.Serve(listener); err != nil {
		log.Fatalf("failed to serve SSH: %v", err)
	}
}

func main() {
	initializeFlags()
	secret := ""
	if ! *configNoPassword {
		k := initializeKey()
		secret = initializeTOTP(k)
	}

	s := initSSHServer(secret)
	if *configNoTailscale {
		withTCP(s)
	} else {
		withTailscale(s)
	}
}
