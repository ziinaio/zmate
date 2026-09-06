package zmate

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/creack/pty"
	"github.com/giancarlosio/gorainbow"
	"github.com/gliderlabs/ssh"
	"github.com/urfave/cli/v2"
	sshcrypto "golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

const banner = `
███████╗███╗   ███╗ █████╗ ████████╗███████╗
╚══███╔╝████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
  ███╔╝ ██╔████╔██║███████║   ██║   █████╗  
 ███╔╝  ██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  
███████╗██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
`

const examples = `
Invite peers in your LAN.

	zmate -l 192.168.1.2:2222

Invite peers using **ssh.example.com** as entrypoint for your peers:

	zmate -s ssh.example.com

Show connection info:

		echo $ZMATE_CONNECTION_INFO
		echo $ZMATE_CONNECTION_INFO_RO
`

var (
	// sessionName contains the name of the Zellij session.
	// An empty string denotes that the host has not yet initiaed a session.
	sessionName = ""

	// rwUser contains the username for full read-write acess
	rwUser = ""

	// roUser contains the username for read-only access
	roUser = ""

	// quickShareMode flags if zmate is running in quick-share mode
	quickShareMode = false
)

// charset contains the list of available characters for random session-name generation.
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomString returns a random string of characters of the given length.
func randomString(length int) (string, error) {
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}
	return string(result), nil
}

// App serves as entry-point for github.com/urfave/cli
var App = &cli.App{
	Name:        "zmate",
	Usage:       "💻 📤 👥 Instant terminal sharing; using Zellij." + "\n" + gorainbow.Rainbow(banner),
	Description: examples,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "listen",
			Aliases: []string{"l"},
			Usage:   "Listen on this port.",
			Value:   "127.0.0.1:2222",
		},
		&cli.StringFlag{
			Name:    "server",
			Aliases: []string{"s"},
			Usage:   "The SSH server to use as endpoint.",
			Value:   "",
		},
		&cli.StringFlag{
			Name:    "user",
			Aliases: []string{"u"},
			Usage:   "Username for SSH authentication.",
		},
		&cli.StringFlag{
			Name:    "host-key",
			Aliases: []string{"k"},
			Usage:   "Path to the built-in SSH server's private host key.",
		},
		&cli.StringFlag{
			Name:  "known-hosts",
			Usage: "Path to the known_hosts file used to verify the entrypoint.",
		},
	},
	Action: func(ctx *cli.Context) error {
		// Separate out the port from the listen-address.
		listenHost, port, err := parseListenAddress(ctx.String("listen"))
		if err != nil {
			return err
		}
		if ctx.String("server") == "" && listenHost == "127.0.0.1" {
			return fmt.Errorf("address for remote ssh server not provided consider adding one with -s <server-addr> or make it accessible on your local network with -l 0.0.0.0:2222")
		}
		// Determine username for SSH authentication.
		username := ctx.String("user")
		if username == "" {
			// Use current user if none specified.
			currentUser, err := user.Current()
			if err != nil {
				return err
			}
			username = currentUser.Username
		}

		// Check ZELLIJ_SESSION_NAME env-var
		zellijSessionName := os.Getenv("ZELLIJ_SESSION_NAME")
		if zellijSessionName != "" {
			fmt.Println("")
			log.Println("Starting from within Zellij session: ", zellijSessionName)
			quickShareMode = true
		}

		if quickShareMode {
			sessionName = zellijSessionName
		} else {
			// Generate a random Zellij session-name.
			sessionName, err = randomString(7)
			if err != nil {
				return err
			}
			sessionName = fmt.Sprintf("zmate-%s", sessionName)
		}

		// Generate bearer tokens for full and read-only access.
		rwUser, err = randomString(16)
		if err != nil {
			return err
		}

		// Generate a random username for read-only access.
		roUser, err = randomString(16)
		if err != nil {
			return err
		}
		roUser += "-ro"

		hostKey, hostKeyPath, err := loadOrCreateHostKey(ctx.String("host-key"))
		if err != nil {
			return err
		}
		hostKeyAlias := hostKeyAlias(hostKey)

		chGuard := make(chan struct{}, 2)
		remotePort := port

		// Start the remote port-forwarding tunnel if a server endpoint is specified.
		server := ctx.String("server")
		// Track which host to connect to for Zellij (server or local listener)
		serverOrHost := server
		if server != "" {
			remotePortReady := make(chan int, 1)
			go func() {
				if err := runReverseTunnel(remotePortReady, listenHost, server, username, ctx.String("known-hosts"), port); err != nil {
					log.Fatalf("SSH remote port-forwarding tunnel terminated: %s\n", err)
				}
			}()
			remotePort = <-remotePortReady
		} else {
			// Pure local mode; skip remote port forwarding
			log.Println("Skipping remote port-forwarding (local-only mode)")
		}

		// Start the SSH server
		go func() {
			if err := runServer(chGuard, port, remotePort, ctx.String("listen"), hostKey, hostKeyPath, hostKeyAlias, server); err != nil {
				log.Fatalf("SSH server error: %v", err)
			}
		}()
		<-chGuard

		// Print connection info
		fmt.Println("")
		if server != "" {
			fmt.Println("Join via:")
			fmt.Printf("  %s  # read-write\n", sshConnectionCommand(remotePort, rwUser, server, hostKeyAlias))
			fmt.Printf("  %s  # read-only\n", sshConnectionCommand(remotePort, roUser, server, hostKeyAlias))
		}
		if listenHost != "127.0.0.1" {
			displayHost := listenHost
			if displayHost == "0.0.0.0" {
				displayHost = "<local-addr>"
			}
			fmt.Println("Join via:")
			fmt.Printf("  %s  # read-write\n", sshConnectionCommand(port, rwUser, displayHost, hostKeyAlias))
			fmt.Printf("  %s  # read-only\n", sshConnectionCommand(port, roUser, displayHost, hostKeyAlias))
		}

		// Start the Zellij session over SSH
		if server == "" {
			serverOrHost = listenHost
		}

		if quickShareMode {
			select {} // just keep running
		} else {
			fmt.Println("\nPress Enter to continue...")
			bufio.NewReader(os.Stdin).ReadBytes('\n')
			return runZellij(serverOrHost, sessionName, remotePort)
		}
	},
}

func parseListenAddress(address string) (string, int, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("invalid listen address %q: %w", address, err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portString)
	}
	return host, port, nil
}

func runServer(chGuard chan struct{}, localPort, advertisedPort int, listenAddr string, hostKey sshcrypto.Signer, hostKeyPath, hostKeyAlias, entrypoint string) error {
	// Define the SSH server
	server := &ssh.Server{
		Addr: listenAddr,
		Handler: func(s ssh.Session) {
			username := s.User()

			// Disallow clients connecting with the wrong username.
			if !(username == rwUser || username == roUser) {
				return
			}

			// Mark user as read-only if applicable.
			isReadOnly := username == roUser

			// The Zellij command.
			cmd := exec.Command("zellij", "-l", "compact", "attach", "--create", sessionName)

			// Zellij requires a PTY.
			ptyReq, winCh, isPty := s.Pty()
			if !isPty {
				io.WriteString(s, "No PTY requested. Zellij requires a PTY.\n")
				s.Exit(1)
				return
			}

			// Set TERM environment variable
			cmd.Env = os.Environ()
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
			cmd.Env = append(cmd.Env, fmt.Sprintf("SHELL=%s", os.Getenv("SHELL")))
			cmd.Env = append(cmd.Env, fmt.Sprintf("ZMATE_CONNECTION_INFO=%s", sshConnectionCommand(advertisedPort, rwUser, entrypoint, hostKeyAlias)))
			cmd.Env = append(cmd.Env, fmt.Sprintf("ZMATE_CONNECTION_INFO_RO=%s", sshConnectionCommand(advertisedPort, roUser, entrypoint, hostKeyAlias)))

			// Start Zellij in a new PTY
			ptmx, err := pty.Start(cmd)
			if err != nil {
				log.Printf("Failed to start PTY: %v", err)
				s.Exit(1)
				return
			}
			defer ptmx.Close()

			// Handle window resize
			go func() {
				for win := range winCh {
					pty.Setsize(ptmx, &pty.Winsize{
						Cols: uint16(win.Width),
						Rows: uint16(win.Height),
					})
				}
			}()

			// For read-only connections i/o is only redirected in one direction.
			if isReadOnly {
				// Connect session input/output to the PTY
				io.Copy(s, ptmx) // blocks until Zellij exits
			} else {
				// Connect session input/output to the PTY
				go io.Copy(ptmx, s)
				io.Copy(s, ptmx) // blocks until Zellij exits
			}
		},
	}

	server.AddHostKey(hostKey)
	log.Printf("Using SSH host key %s (%s)", hostKeyPath, sshcrypto.FingerprintSHA256(hostKey.PublicKey()))

	log.Printf("Starting zmate server on %s...\n", listenAddr)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	chGuard <- struct{}{}
	return server.Serve(listener)
}

func hostKeyAlias(signer sshcrypto.Signer) string {
	digest := sha256.Sum256(signer.PublicKey().Marshal())
	return "zmate-" + hex.EncodeToString(digest[:8])
}

func sshConnectionCommand(port int, username, host, alias string) string {
	return fmt.Sprintf("ssh -oHostKeyAlias=%s -p%d %s@%s", alias, port, username, host)
}

func loadOrCreateHostKey(path string) (sshcrypto.Signer, string, error) {
	if path == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return nil, "", fmt.Errorf("find user config directory: %w", err)
		}
		path = filepath.Join(configDir, "zmate", "ssh_host_ed25519_key")
	}

	keyBytes, err := os.ReadFile(path)
	if err == nil {
		signer, err := sshcrypto.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse SSH host key %q: %w", path, err)
		}
		return signer, path, nil
	}
	if !os.IsNotExist(err) {
		return nil, "", fmt.Errorf("read SSH host key %q: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, "", fmt.Errorf("create SSH host key directory: %w", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate SSH host key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, "", fmt.Errorf("encode SSH host key: %w", err)
	}
	keyBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, keyBytes, 0600); err != nil {
		return nil, "", fmt.Errorf("write SSH host key %q: %w", path, err)
	}
	signer, err := sshcrypto.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse generated SSH host key: %w", err)
	}
	return signer, path, nil
}

func runReverseTunnel(remotePortReady chan<- int, bindAddr, remoteHost, username, knownHostsFile string, localPort int) error {
	log.Println("Starting SSH reverse port-forwarding...")

	// Connect to the running SSH agent
	sshAgentSocket := os.Getenv("SSH_AUTH_SOCK")
	if sshAgentSocket == "" {
		return fmt.Errorf("SSH agent not found: ensure SSH_AUTH_SOCK is set")
	}

	// Open the agent socket
	agentConn, err := net.Dial("unix", sshAgentSocket)
	if err != nil {
		return fmt.Errorf("connect to SSH agent: %w", err)
	}
	defer agentConn.Close()

	// Create a new agent client
	agentClient := sshagent.NewClient(agentConn)

	// SSH client configuration
	hostKeyCallback, err := knownHostsCallback(knownHostsFile)
	if err != nil {
		return err
	}
	config := &sshcrypto.ClientConfig{
		User: username, // Replace with your SSH username
		Auth: []sshcrypto.AuthMethod{
			// Use the SSH agent to retrieve keys for authentication
			sshcrypto.PublicKeysCallback(agentClient.Signers),
		},
		HostKeyCallback: hostKeyCallback,
	}

	remoteAddress := remoteHost
	if _, _, err := net.SplitHostPort(remoteAddress); err != nil {
		remoteAddress = net.JoinHostPort(remoteHost, "22")
	}
	client, err := sshcrypto.Dial("tcp", remoteAddress, config)
	if err != nil {
		return fmt.Errorf("failed to dial SSH server: %v", err)
	}

	// Request remote port forwarding
	listener, err := client.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", localPort))
	if err != nil {
		log.Printf("Remote port %d unavailable; requesting an automatically allocated port", localPort)
		listener, err = client.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			return fmt.Errorf("failed to set up remote port forwarding on port %d or an automatic port: %w", localPort, err)
		}
	}
	remotePort := listener.Addr().(*net.TCPAddr).Port

	log.Printf("Remote port forwarding established: %s:%d -> localhost:%d", remoteHost, remotePort, localPort)
	remotePortReady <- remotePort

	// Handle incoming connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Remote forwarding listener stopped: %v", err)
				return
			}

			// Connect to the local SSH server
			localConn, err := net.Dial("tcp", net.JoinHostPort(bindAddr, strconv.Itoa(localPort)))
			if err != nil {
				log.Printf("Failed to connect to local service: %v", err)
				conn.Close()
				continue
			}

			// Start bidirectional copy
			go func() {
				defer conn.Close()
				defer localConn.Close()
				go io.Copy(localConn, conn)
				io.Copy(conn, localConn)
			}()
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Println("Shutting down...")
	return client.Close()
}

func knownHostsCallback(path string) (sshcrypto.HostKeyCallback, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("find home directory for known_hosts: %w", err)
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %q: %w", path, err)
	}
	return callback, nil
}

func runZellij(server, sessionName string, port int) error {
	// Connect to SSH agent
	sshAgentSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAgentSock == "" {
		return fmt.Errorf("SSH_AUTH_SOCK not set")
	}
	agentConn, err := net.Dial("unix", sshAgentSock)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH agent: %w", err)
	}
	defer agentConn.Close()
	ag := sshagent.NewClient(agentConn)

	// SSH config
	config := &sshcrypto.ClientConfig{
		User: rwUser,
		Auth: []sshcrypto.AuthMethod{
			sshcrypto.PublicKeysCallback(ag.Signers),
		},
		HostKeyCallback: sshcrypto.InsecureIgnoreHostKey(), // Don't use this in production
	}

	// Connect
	addr := fmt.Sprintf("%s:%d", server, port)
	client, err := sshcrypto.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Save current terminal state
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("failed to set terminal raw mode: %w", err)
	}
	defer term.Restore(fd, oldState)

	// Handle Ctrl+C gracefully
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		term.Restore(fd, oldState)
		os.Exit(0)
	}()

	// Request PTY
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}
	width, height, err := term.GetSize(fd)
	if err != nil {
		width, height = 80, 24 // fallback
	}
	err = session.RequestPty(termType, height, width, sshcrypto.TerminalModes{
		sshcrypto.ECHO: 1,
	})
	if err != nil {
		return fmt.Errorf("request for PTY failed: %w", err)
	}

	// Set I/O
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Start Zellij
	if err := session.Start("zellij attach " + sessionName); err != nil {
		return fmt.Errorf("failed to start zellij: %w", err)
	}

	// Wait for session to end
	if err := session.Wait(); err != nil {
		return fmt.Errorf("zellij session ended with error: %w", err)
	}

	return nil
}
