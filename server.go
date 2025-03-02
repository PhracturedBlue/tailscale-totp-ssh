package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

//Replacement for ssh.DirectTCPIPHandler that allows converting hostname->ip-address
func directTCPIPHandler(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	// Need to handle user check here if no password auth is enabled
	if *configNoPassword && *configLoginUser != "" {
		if ctx.User() != *configLoginUser {
			log.Printf("Disallowing invalid user: %s", ctx.User())
			newChan.Reject(gossh.ConnectionFailed, "connection disallowed")
			return
		}
	}
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}
	ip_address, err := validateHostPort(d.DestAddr, d.DestPort)
	if err != nil {
		log.Printf("port forwarding is disaallowed for %s:%d: %s", d.DestAddr, d.DestPort, err)
		newChan.Reject(gossh.Prohibited, "port forwarding is disallowed")
		return
	}
	dest := net.JoinHostPort(ip_address, strconv.FormatInt(int64(d.DestPort), 10))

	var dialer net.Dialer
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		log.Printf("failed to dial %s: %s", dest, err)
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		dconn.Close()
		return
	}
	go gossh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(ch, dconn)
	}()
	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
	}()
}

func startSSHServer(listener net.Listener, secret string) {
	ssh.Handle(func(s ssh.Session) {
		// Need to handle user check here if no password auth is enabled
		if *configNoPassword && *configLoginUser != "" {
			if s.User() != *configLoginUser {
				log.Printf("Disallowing invalid user: %s", s.User())
				s.Exit(1)
				return
			}
		}
		sessionHandler(s)
	})

	log.Printf("starting ssh server on port %d...", *configPort)
	forwardHandler := &ssh.ForwardedTCPHandler{}
	sshServer := &ssh.Server{
		Addr: fmt.Sprintf(":%d", *configPort),
		ConnCallback: func(ctx ssh.Context, conn net.Conn) net.Conn {
			log.Printf("New connection from %s", conn.RemoteAddr())
			return conn
		},
		ConnectionFailedCallback: func(conn net.Conn, err error) {
			log.Printf("Connection failed from %s: %v", conn.RemoteAddr(), err)
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session": ssh.DefaultSessionHandler,
			"direct-tcpip": directTCPIPHandler,
		},
	}
	if ! *configNoPassword {
		sshServer.SetOption(ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			if *configLoginUser != "" {
				if ctx.User() != *configLoginUser {
					log.Printf("Disallowing invalid user: %s", ctx.User())
					return false
				}
			}
			return validateTOTP(pass, secret)
		}))
	}
	sshServer.SetOption(ssh.HostKeyFile("./id_rsa"))
	if err := sshServer.Serve(listener); err != nil {
            log.Fatalf("failed to serve SSH: %v", err)
        }
}

