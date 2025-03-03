package main

import (
	"context"
	"log"
	"net"
	"time"
 	"tailscale.com/tsnet"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/types/logger"
)

type tsSSHServer struct {
	server Server
}
func (srv *tsSSHServer) HandleSSHConn(conn net.Conn) error {
	srv.server.HandleConn(conn)
	return nil
}

func (srv *tsSSHServer) NumActiveConns() int {
	return 0
}

func (srv *tsSSHServer) OnPolicyChange() {}

func (srv *tsSSHServer) Shutdown() {}

func initTailscaleSSH(ts *tsnet.Server, sshServer Server) {

	ipnlocal.RegisterNewSSHServer(func(logf logger.Logf, lb *ipnlocal.LocalBackend) (ipnlocal.SSHServer, error) {
		srv := &tsSSHServer{server: sshServer}
		return srv, nil
	})
	
	lc, err := ts.LocalClient()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			status, err := lc.Status(context.Background())
			if err != nil {
				break
			}

			if status.BackendState == "Running" {
				newPrefs := ipn.MaskedPrefs{RunSSHSet: true}
				newPrefs.RunSSH = true
				_, err := lc.EditPrefs(context.Background(), &newPrefs)
				if err != nil {
					log.Printf("Failed to expose SSH to tailscale: %s", err)
				} else {
					log.Print("Connected to tailscale")
				}
				break
			}
			time.Sleep(1 * time.Second)
		}
	}()
}
