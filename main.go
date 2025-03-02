package main

import (
	// ssh server
	"fmt"
	"log"
	"net"
	"os"

	"tailscale.com/tsnet"
)

func withTCP(body func(listener net.Listener)) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *configPort))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	body(listener)
}

func withTailscale(body func(listener net.Listener)) {
	server := &tsnet.Server{
		Hostname: *configTSName,
		Dir: *configStateDir,
	}
	defer server.Close()
	if *configVerbose {
		server.Logf = log.New(os.Stderr, "[tsnet] ", log.LstdFlags).Printf
	} else {
		server.Logf = nil
	}
	listener, err := server.Listen("tcp", fmt.Sprintf(":%d", *configPort))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	body(listener)
}

func main() {
	initializeFlags()
	secret := ""
	if ! *configNoPassword {
		k := initializeKey()
		secret = initializeTOTP(k)
	}

	f := func(listener net.Listener) {
		startSSHServer(listener, secret)
	}
	if *configNoTailscale {
		withTCP(f)
	} else {
		withTailscale(f)
	}
}
