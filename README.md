# tailscale-totp-ssh
This implements a Tailscale host that provides an SSH server with a TOTP password.
The host may only act as an SSH Jump host (i.e. it is only used as a means to ssh
into another host, and no access to the tailscale host is provided).

# Rationalle
Tailscale has builtin passwordless SSH support, or you can use a standard SSH server
and enforce password/key authentication.  Tailscale's rationale is that they will
authenticate before enabling an SSH connection using your provider of choice.
However, the providers supported by tailscale all have different issues related to authentication:
* Google: wants to tie your Tailscale authorization to a Google account on the device
* Microsoft: wants to tie your Tailscale authorization to a Microsoft device on the device
* GitHub: will persist your authentication on the device for a long time
* OIDC:  have not found a provider I trust, and do not want to self-host an authentication server
* Passkeys: would be fine, but each passkey needs its own account, and you can only have 3 on the Personal Tailscale tier

Using an SSH server with a password would be fine, but I wanted my password to rotate to prevent snooping, so using TOTP
provides an additional layer of security.  Note that this is not truly 2FA since both factors are 'something you have'
(a device authenticated to tailscale and a device with a TOTP authenticator), but my TOTP is restricted by biometric data,
and so the end result is that you need both my device and access to my bio-data to be able to login, and that is sufficient
for my needs).  Implementing true 2FA would not be hard if desired.

The SSH server is also restriced to acting as a jump host.  This is because I run tailscale in a container, and the only
useful thing to do is to SSH to another host.  By embedding that functionality in a single application, the deployment is
simplified.

The server supports native Jump Proxies in openssh:
```
ssh -J user@internal.host user2@tailnet
```
Or via interactive prompt:
```
ssh user@tailnet
> user@internal.host
```

# TOTP
The 1st time it is run, the server will generate a TOTP token and display the URL and QR code (for the client).  Additionally,
It will display the secret as an encrypted string.  The encryption here is not strong (symmetric encryption, with the key embedded
in the binary), but it means that it is not easily discoverable from a simple 'ps'
The encrytption key must be added at build time.  If not, then the applictaion will generate a random key, and provide
instructions on rebuilding with that key.

# Jump hosts
The target jump hosts can be limited using netmasks, allowed domains, and allowed target ports.  This should ensure that
even in the case that the login to the server is possible, a valid internal destination (along with apropriate credentials)
is also needed.

# Security
While This code is using off-the-shelf components for Tailscale, SSH, TOTP, and AES, there is no gaurantee that the parts are put
together in as secure manner.  I've done my best, but I'm not a security expert.  If  you have any doubts at all, you probably
shouldn't be using this software
