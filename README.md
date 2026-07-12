# reality-rs

Clean-room Rust implementation work for a Debian x86_64 REALITY server that
accepts VLESS-over-TCP connections from Xray clients.

> Status: verified locally with official Xray 26.5.9 as the client core, using
> VLESS over TCP with REALITY and the Chrome fingerprint.

Current foundation:

- REALITY ClientHello authentication primitives (X25519, HKDF-SHA256, AES-256-GCM)
- TLS 1.3 ClientHello record parser with SNI, TLS 1.3, X25519, and
  X25519MLKEM768-key-share extraction
- VLESS `decryption: none` request-header parser

The TLS 1.3 record and handshake engine is deliberately not claimed complete.
Interoperability is only declared after Xray-client integration tests pass.

## Compatibility boundary

The parser accepts the ClientHello key-share forms used by current Xray clients,
including the X25519 portion of the hybrid X25519MLKEM768 share. The pending
TLS 1.3 engine must implement the full selected group before accepting hybrid
handshakes; authentication alone is not a completed connection.

## Target

Debian GNU/Linux with kernel `6.1.174-1`, x86_64. The release build uses the
portable `x86_64-unknown-linux-gnu` target; it does not depend on the kernel
version beyond normal TCP socket support.

## Debian installation

### One-click installer

After downloading or cloning this release, run one command as root. It installs
the Linux binary, creates the service account and config, enables systemd, and
writes a ready-to-copy V2rayN profile to `/root/reality-rs-v2rayn.txt`.

The bundled installer verifies `dist/reality-rs-linux-amd64` against its
adjacent SHA-256 file before installation.

```sh
sudo bash install.sh --sni www.example.com --fallback www.example.com:443
```

For unattended provisioning, add `--yes`; UUID and short ID are generated when
not supplied. Existing configuration is preserved on upgrades. Use
`--force-config` only when intentionally regenerating keys and client details.

For the official GitHub repository, the same one-click flow downloads the
versioned Linux bundle directly:

```sh
curl -fsSL https://raw.githubusercontent.com/ElinaMilin/reality-rs/main/install.sh | \
  sudo bash -s -- --release-base-url \
  https://raw.githubusercontent.com/ElinaMilin/reality-rs/main/dist \
  --sni www.example.com
```

### Post-install management

Run the command below for an interactive service-management menu. The
`config` command provides a guided edit for the listen address, SNI, fallback,
UUID and short ID, creates a timestamped config backup, then restarts the
service only if the new configuration is valid.

```sh
sudo reality-rsctl
sudo reality-rsctl config
```

### Build from source

On the Debian x86_64 server, build natively. This avoids cross-compiler and
glibc compatibility issues:

```sh
sudo apt update
sudo apt install -y build-essential cmake pkg-config curl ca-certificates
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
cargo build --release
sudo install -m 0755 target/release/reality-rs /usr/local/bin/reality-rs
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin reality-rs
sudo install -d -m 0750 -o reality-rs -g reality-rs /etc/reality-rs
```

Run `reality-rs keygen`, then copy `config.example.json` to
`/etc/reality-rs/config.json`, replace its UUID, private key, server name,
short ID, and fallback address. Restrict the file with:

```sh
sudo chown reality-rs:reality-rs /etc/reality-rs/config.json
sudo chmod 0640 /etc/reality-rs/config.json
sudo install -m 0644 packaging/reality-rs.service /etc/systemd/system/reality-rs.service
sudo systemctl daemon-reload
sudo systemctl enable --now reality-rs
```

`server_names` must be names accepted by Xray clients and `fallback` must be a
reachable TLS endpoint. The public key printed by `keygen` is the `pbk` value
used by V2rayN; the private key stays only on the server.

## V2rayN client profile

Create a VLESS profile with the configured UUID, server IP/name, and port. Set
transport to TCP and security to REALITY. Enter the `public_key` output as
`pbk`, a configured `short_ids` entry as `sid`, one configured server name as
SNI, and use the `chrome` fingerprint. Leave the flow field empty: this server
supports VLESS-over-TCP direct outbound, not XTLS Vision.

The compatibility test uses official Xray 26.5.9 as the client core with the
same VLESS+REALITY settings, then fetches a local HTTP target through its SOCKS
inbound. It completes with the response `relay-ok`.
