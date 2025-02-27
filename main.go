package main

import (
	// ssh server
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	// crypto functions from https://github.com/gtank/cryptopasta/blob/master/encrypt.go
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"flag"
	"strconv"
	"regexp"
	"strings"
	"encoding/base64"
	"path/filepath"
	terminal "golang.org/x/term"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"tailscale.com/tsnet"

)

var (
	configTOTP = flag.String("totp", "", "totp secret")
	configTSName      = flag.String("tsname", "", "tailscale name")
	configLoginUser   = flag.String("user", "", "login user")
	configStateDir    = flag.String("statedir", "", "Tailscale state dir")
	configHostKeyFile = flag.String("hostkey", "./id_rsa", "Host key file")
	configVerbose     = flag.Bool("verbose", false, "if set, verbosely log tsnet information")
	configPort        = flag.Int("port", 22, "listen port")
	configAllowedDomains      stringArrayFlags
	configAllowedSubnets      stringArrayFlags
	configAllowedPortRanges   intRangeArrayFlags
	aeskey string
)

type stringArrayFlags []string

func (i *stringArrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *stringArrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type intRangeArrayFlags [][2]uint32

func (i *intRangeArrayFlags) String() string {
	pairs := []string{}
	for _, item := range *i {
		if item[0] == item[1] {
			pairs = append(pairs, fmt.Sprintf("%d", item[0]))
		} else {
			pairs = append(pairs, fmt.Sprintf("%d-%d", item[0], item[1]))
		}
	}
	return strings.Join(pairs, ", ")
}

func (i *intRangeArrayFlags) Set(value string) error {
	rng := strings.Split(value, "-")
	if len(rng) == 1 {
		val, err := strconv.ParseUint(rng[0], 10, 32)
		if err != nil {
			return err
		}
		*i = append(*i, [2]uint32{uint32(val), uint32(val)})
	} else if len(rng) == 2 {
		val1, err := strconv.ParseUint(rng[0], 10, 32)
		if err != nil {
			return err
		}
		val2, err := strconv.ParseUint(rng[1], 10, 32)
		if err != nil {
			return err
		}
		*i = append(*i, [2]uint32{uint32(val1), uint32(val2)})
	} else {
		return errors.New("Invalid format for " + value)
	}
	return nil
}

// Generate symmetric encryption key
func NewEncryptionKey() *[32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return &key
}

// Encrypt byte data with encryption key
func Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt byte data with encryption key
func Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

// Detect if an encryption key was built into the binary, and exit with a new key if not
// otherwise return the provided key in the needed format
func initializeKey() *[32]byte {
	if aeskey == "" {
		_k := NewEncryptionKey()
		log.Fatalf("AESKEY was not supplied.  Rebuild with:\ngo build -ldflags '-s -w -X main.aeskey=%s'",
			base64.StdEncoding.EncodeToString(_k[:]))
	}
	_k, err := base64.StdEncoding.DecodeString(aeskey)
	if err != nil {
		panic(err)
	}
	key := [32]byte(_k)
	return &key
}

// Parse flags and validate them as needed
func initializeFlags() {
	flag.Var(&configAllowedDomains, "jump_domains", "Restrict allowed jump domains")
	flag.Var(&configAllowedSubnets, "jump_subnets", "Restrict allowed jump subnets")
	flag.Var(&configAllowedPortRanges, "jump_ports", "Restrict allowed jump ports (specify # or from-to)")
	flag.Parse()
	if (*configTSName == "") {
		log.Fatalf("-tsname is a required flag")
	}
	if (*configStateDir == "") {
		defaultDirectory, err := os.UserConfigDir()
		if err != nil {
			log.Fatalf("can't find default user config directory: %v", err)
		}
		*configStateDir = filepath.Join(defaultDirectory, "tailscale-totp-ssh")
	}
	if _, err := os.Stat(*configHostKeyFile); err != nil {
		log.Fatalf("Host key file %s dos not exist.  Generate with\nssh-keygen -f %s", *configHostKeyFile, *configHostKeyFile)
	}
	if len(configAllowedDomains) > 0 {
		log.Printf("Restrict jump domains to %s", configAllowedDomains.String());
	}
	if len(configAllowedSubnets) > 0 {
		for _, subnet := range configAllowedSubnets {
			_, _, err := net.ParseCIDR(subnet)
			if err != nil {
				log.Fatalf("Invalid subnet: %s", subnet)
			}
		}
		log.Printf("Restrict jump subnets to %s", configAllowedSubnets.String());
	}
	if len(configAllowedPortRanges) > 0 {
		log.Printf("Restrict jump ports to: %s", configAllowedPortRanges.String())
	}
}

// Validate TSRP key if specified, or generate a new one and return it
// If a new key is generated, the UR, the encypted-key, and the QR code for the client is also displayed
// The key is encrypted to make casual snooping harder to extract...Ths is just security through obscurity
func initializeTOTP(key *[32]byte) string {
	if (*configTOTP == "") {
		totpKey, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "SSH",
			AccountName: "foo@example.com",
			Period:      30, // Time step in seconds
			SecretSize:  20, // Length of the secret key
			Digits:      6,  // Number of digits in the OTP code
			Algorithm:   0,  // Hashing algorithm (SHA1 by default)
		})
		if err != nil {
			panic(err)
		}
		enc, err := Encrypt([]byte(totpKey.Secret()), key)
		if err != nil {
			panic(err)
		}
		log.Printf("Secret key: %s", base64.StdEncoding.EncodeToString(enc))
		fmt.Println("Provisioning URI:", totpKey.URL())
		q, err := qrcode.New(totpKey.URL(), qrcode.Low)
		if err != nil {
			panic(err)
		}
		art := q.ToString(false)
		fmt.Println(art)
		return totpKey.Secret()
	} else {
		decodedData, err := base64.StdEncoding.DecodeString(*configTOTP)
		if err != nil {
			panic(err)
		}
		sec, err := Decrypt(decodedData, key)
		if err != nil {
			panic(err)
		}
		secret := string(sec)
		log.Printf("Secret: %s", secret)
		return secret
	}
}

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

func isIPInSubnet(ipAddress string, subnet string) bool {
	ip := net.ParseIP(ipAddress)
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return false // Invalid subnet format
	}
	return ipnet.Contains(ip)
}

func validateHostPort(host string, port uint32) error {
	r := regexp.MustCompile("(\\d+\\.\\d+\\.\\d+\\.\\d+)|([a-z0-9-]+)\\.([a-z0-9-][[a-z0-9-.]+)")
	match := r.FindStringSubmatch(host)
	if match == nil {
		return errors.New("Invalid host: " + host)
	}
	ip_address, _, domain := match[0], match[1], match[2]
	if ip_address != "" {
		if len(configAllowedSubnets) > 0 {
			ok := false
			for _, subnet := range configAllowedSubnets {
				if isIPInSubnet(ip_address, subnet) {
					ok = true
					break
				}
			}
			if ! ok {
				return fmt.Errorf("Invalid IP '%s'", ip_address)
			}
		}
	} else {
		if len(configAllowedDomains) > 0 {
			ok := false
			for _, dom := range configAllowedDomains {
				if domain == dom {
					ok = true
					break
				}
			}
			if ! ok {
				return fmt.Errorf("Invalid domain '%s'", domain)
			}
		}
	}
	if len(configAllowedPortRanges) > 0 {
		ok := false
		for _, portRange := range configAllowedPortRanges {
			if port >= portRange[0] && port <= portRange[1] {
				ok = true
				break
			}
		}
		if ! ok {
			return fmt.Errorf("Invalid port '%d'", port)
		}
	}
	return nil
}

func parseUserHostPort(line string) (string, string, string, error) {
	r := regexp.MustCompile("^([a-z0-9]+)@(\\d+\\.\\d+\\.\\d+\\.\\d+|[a-z0-9-]+\\.[a-z0-9-][[a-z0-9-.]+)(?::(\\d+))?$")
	match := r.FindStringSubmatch(line)
	if match == nil {
		return "", "", "", errors.New("Invalid format: " +  line)
	}
	user, host, port := match[0], match[1], match[2]
	if port == "" {
		port = "22"
	}
	port_num, _ := strconv.ParseUint(port, 10, 32)
	err := validateHostPort(host, uint32(port_num))
	if err != nil {
		return "", "", "", err
	}
	return user, host, ":" + port, nil
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

func startSSHServer(listener net.Listener, secret string) {
	ssh.Handle(sessionHandler)

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
		PasswordHandler: func(ctx ssh.Context, pass string) bool {
			if *configLoginUser != "" {
				if ctx.User() != *configLoginUser {
					log.Printf("Disallowing invalid user: %s", ctx.User())
					return false
				}
			}
			return totp.Validate(string(pass), secret)
		},
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			err := validateHostPort(host, port)
			if err == nil {
				log.Printf("Forwrding port %s:%d", host, port)
				return true
			} else {
				log.Printf("Disallowing port-forwarding for %s:%d: %s", host, port, err)
				return false
			}
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session": ssh.DefaultSessionHandler,
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
	}
	sshServer.SetOption(ssh.HostKeyFile("./id_rsa"))
	if err := sshServer.Serve(listener); err != nil {
            log.Fatalf("failed to serve SSH: %v", err)
        }
}

func main() {
	k := initializeKey()
	initializeFlags()
	secret := initializeTOTP(k)

	withTailscale(func(listener net.Listener) {
		startSSHServer(listener, secret)
	})
}
