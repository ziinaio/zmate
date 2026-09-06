# zmate

💻 📤 👥 Instant terminal sharing; using Zellij.

[![asciicast](https://asciinema.org/a/0ALuQtrvl62WPd7atwDZeyRzY.svg)](https://asciinema.org/a/0ALuQtrvl62WPd7atwDZeyRzY)

zmate lets you invite peers into a local [Zellij](https://github.com/zellij-org/zellij) session over untrusted networks, despite you being behind a NAT gateway.
It is heavily inspired by [tmate](https://github.com/tmate-io/tmate).

zmate is (basically) server-less.
You only need a standard OpenSSH server with a public IP that serves as an entry-point for your peers.
Your peers only need a standard OpenSSH client.

Starting zmate inside an already open Zellij session will invite peers into that session.
Otherwise zmate will spin up a new Zellij session with a random name.

## How does it work?

zmate configures an ephemeral SSH remote port-forwarding tunnel on your public SSH server, pointing back to a local high-port.
It then starts a minimal SSH server on that local high-port, that throws connecting clients directly into a Zellij session.
Peers connecting to the high-port on your server via SSH are forwarded through the tunnel directly into your local Zellij session.
Once the host terminates zmate (by closing the Zellij session), the remote port-forwarding tunnel and internal SSH server are terminated and all peers automatically kicked.

> The host should always terminate the Zellij session by closing all tabs and panes.
> Simply detaching will still close zmate and therefor terminate the builtin SSH server and the tunnel.
> However, it will leave behind a dangling Zellij session and also likely screw up your peers' terminal, because their connection gets terminated very disgracefully.

### zmate Session Life-Cycle

```mermaid
sequenceDiagram
    participant Host
    participant zmate
    participant Zellij
    participant Builtin-SSHd
    participant Public-SSHd
    participant Peer

    Note over Host,Peer: Start zmate
    Host->>zmate: Start zmate
    zmate->>Builtin-SSHd: Start builtin SSHd (2222)
    zmate->>Public-SSHd: Configure remote port-forwarding tunnel (2222)
    Public-SSHd-->>Builtin-SSHd: Forwards connections back to builtin SSHd (2222)

    Note over Host,Public-SSHd: Host connects to session
    Host->>Public-SSHd: Connect via SSH
    Public-SSHd->>Builtin-SSHd: Forward connecting host to builtin SSH
    Builtin-SSHd->>Zellij: Exec into Zellij session

    Note over Public-SSHd,Peer: Peer connects to session
    Peer->>Public-SSHd: Connect via SSH
    Public-SSHd->>Builtin-SSHd: Forward connecting peer to builtin SSHd
    Builtin-SSHd->>Zellij: Exec into Zellij session

    Note over Host,Peer: Zellij session closed or host detached
    zmate->>Public-SSHd: Terminate remote port-forwarding tunnel
    zmate->>Builtin-SSHd: Terminate builtin SSHd
    zmate->>Host: Terminate zmate
```

## Security Model

Both, the remote port-forwarding and the builtin minimal SSH server, are initiated and terminated with zmate.
While zmate is not running, no listening-port will be bound, neither on your server, nor locally.
You can choose the port on which to bind when you start zmate; default is 2222.
If that port is already occupied on the public SSH entrypoint, zmate asks the server to allocate a free remote port and prints that port in the connection commands.

The builtin minimal SSH server uses a randomly generated 16-character username as a short-lived bearer token.
Anyone who learns a connection command can join with the access level encoded by that username, so treat read-write and read-only connection commands as secrets.
Peers connecting with a wrong username are immediately disconnected.

The connection to the public SSH entrypoint is verified against `~/.ssh/known_hosts` by default.
Use `--known-hosts` to select a different file.

By default, zmate will bind the builtin SSH server to `127.0.0.1:2222`.
If you explicitly decide to bind it to `:2222`, you can make your Zellij session available on your LAN.
Peers in your network can then connect to the high-port on your Zellij host, directly, effectively bypassing the round-trip through the tunnel.

On first use, zmate generates an Ed25519 host key at `$XDG_CONFIG_HOME/zmate/ssh_host_ed25519_key` (normally `~/.config/zmate/ssh_host_ed25519_key`) and reuses it on subsequent runs.
This gives peers a stable SSH identity for the forwarded endpoint.
Use `--host-key` to select an existing key or a different persistent location.
The host-key fingerprint is printed at startup so peers can verify it out of band.
Generated connection commands use a key-specific `HostKeyAlias`.
This prevents different zmate hosts using the same public relay address and port from colliding in a peer's `known_hosts`, while still rejecting a changed key for an identity seen before.
OpenSSH will ask peers to accept the key the first time they connect to a particular zmate host.

## Installation

### Prerequisites

You as the host:

- [Zellij](https://zellij.dev/)
- a standard [OpenSSH](https://github.com/openssh/openssh-portable) client
- an SSH server with a public IP address, configured for password-less authentication (loaded ssh-agent with keys)

Your peers:

- a standard [OpenSSH](https://github.com/openssh/openssh-portable) client

On macOS, zmate preserves `TMPDIR` and lets Zellij select its native socket directory; `XDG_RUNTIME_DIR` is not required.

### Install via Go

```
go install github.com/ziinaio/zmate@latest
```

Or you can download the [latest release build](https://github.com/ziinaio/zmate/releases) for your platform.

## Usage

```
NAME:
   zmate - 💻 📤 👥 Instant terminal sharing; using Zellij.
           
   ███████╗███╗   ███╗ █████╗ ████████╗███████╗
   ╚══███╔╝████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
     ███╔╝ ██╔████╔██║███████║   ██║   █████╗  
    ███╔╝  ██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  
   ███████╗██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
   ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

USAGE:
   zmate [global options]

DESCRIPTION:
   
   Invite peers in your LAN.

     zmate -l 192.168.1.2:2222

   Invite peers using **ssh.example.com** as entrypoint for your peers:

     zmate -s ssh.example.com

   Show connection info:

       echo $ZMATE_CONNECTION_INFO
       echo $ZMATE_CONNECTION_INFO_RO


COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --listen value, -l value    Listen on this port. (default: "127.0.0.1:2222")
   --server value, -s value    The SSH server to use as endpoint.
   --user value, -u value      Username for SSH authentication.
   --host-key value, -k value  Path to the built-in SSH server's private host key.
   --known-hosts value          Path to the known_hosts file used to verify the entrypoint.
   --help, -h                  show help
```

### Host

```
zmate -s myserver
```

This generates a random Zellij session name and separate random usernames for read-write and read-only access.

### Peer

```
ssh -p 2222 <session-name>@myserver
```

---

Made with :heart: at :artificial_satellite: c-base, Berlin.
