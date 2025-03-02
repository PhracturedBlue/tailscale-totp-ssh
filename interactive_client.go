
package main

import (
	"errors"
	"fmt"
	"log"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	terminal "golang.org/x/term"
)

// Attach SSH clinet to SSH server, and setup a PTY if needed
func configureClientTerm(clientSession *gossh.Session, s ssh.Session, wants_pty bool) error {
	if wants_pty {
		ptyReq, winCh, isPty := s.Pty()
		if isPty {
			err := clientSession.RequestPty(ptyReq.Term, 20, 80, nil)
			if err != nil {
				log.Fatalf("Failed to request PTY: %v", err)
			}
			go func() {
				for win := range winCh {
					log.Printf("Setting window size to %d x %d", win.Width, win.Height)
					clientSession.WindowChange(win.Height, win.Width)
				}
			}()
		} else {
			return errors.New("Interactive terminal requested, but no PTY found")
		}
	}
	clientSession.Stdout = s
	clientSession.Stderr = s
	clientSession.Stdin = s
	return  nil
}

// Start up a new SSH session to the intended target, and forward the connection,
// configuring a pty if needed
func setupAndConnectSSHClient(user string, host string, port string, s ssh.Session, term *terminal.Terminal) {
	clientConfig := &gossh.ClientConfig{
		User: user,
		Auth: []gossh.AuthMethod{
			gossh.PasswordCallback(func () (secret string, err error) {
				line, err := term.ReadPassword("password: ")
				return line, err
			}),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), // Insecure, use proper verification
	}
	clientConn, err := gossh.Dial("tcp", host + port, clientConfig)
	if err != nil {
		log.Printf("Failed to dial: %v", err)
		s.Exit(1)
		return
	}
	defer clientConn.Close()
	clientSession, err := clientConn.NewSession()
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		s.Exit(1)
		return
	}
	defer clientSession.Close()
	if configureClientTerm(clientSession, s, s.RawCommand() == "") != nil {
		log.Printf("Failed to establish client terminal: %s", err)
		return
	}
	if s.RawCommand() == "" {
		err = clientSession.Shell()
	} else {
		err = clientSession.Start(s.RawCommand())
	}
	if err != nil {
		log.Printf("Failed to start run command on  remote host")
		return
	}
	err = clientSession.Wait()
	if err != nil {
		fmt.Println("Session exited with error:", err)
	}
}

// Handle an incoming SSH connection.  Note that jump connections are handled
// directly by startSSHServer, and will not come here
func sessionHandler(s ssh.Session) {
	term := terminal.NewTerminal(s, "user@host: ")
	line, err := term.ReadLine()
	if err != nil {
		log.Printf("Invalid input: %s", err)
		s.Exit(1)
		return
	}
	log.Printf("requested user@host: %s", line)
	user, host, port, err := parseUserHostPort(line)
	if err != nil {
		log.Printf("Invalid input: %s", err)
		s.Exit(1)
		return
	}
	setupAndConnectSSHClient(user, host, port, s, term)
}

