#!/usr/bin/env python3
"""Minimal login + consent app for Ory Hydra.

Hydra delegates both steps to this app. That delegation is the point of the
experiment: Hydra itself records nothing about who the human is, so whatever
attribution evidence exists is whatever this app chooses to write. Every
decision it makes is logged to consent-evidence.jsonl.
"""
import json, os, time, urllib.request, urllib.parse
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

ADMIN = "http://127.0.0.1:4445"
HUMAN = "human-1"                      # pseudonymous subject
EVIDENCE = os.environ.get("ATB_HYDRA_CONSENT_EVIDENCE",
                          str(Path(__file__).resolve().parent / "consent-evidence.jsonl"))


def api(path, payload):
    req = urllib.request.Request(f"{ADMIN}{path}", data=json.dumps(payload).encode(),
                                 method="PUT", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def get(path):
    with urllib.request.urlopen(f"{ADMIN}{path}", timeout=15) as r:
        return json.loads(r.read())


def record(event, **fields):
    row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}
    with open(EVIDENCE, "a") as fh:
        fh.write(json.dumps(row) + "\n")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)

        if u.path == "/login":
            challenge = q.get("login_challenge", [""])[0]
            req = get(f"/admin/oauth2/auth/requests/login?login_challenge={challenge}")
            # This app authenticates the human. Hydra does not, and cannot.
            res = api(f"/admin/oauth2/auth/requests/login/accept?login_challenge={challenge}",
                      {"subject": HUMAN, "remember": False,
                       "acr": "pwd", "amr": ["pwd"]})
            record("login.accepted", subject=HUMAN, client=req.get("client", {}).get("client_id"),
                   requested_scope=req.get("requested_scope"), acr="pwd", amr=["pwd"],
                   note="This app asserted the human's identity. Hydra received it; it did not establish it.")
            return self._redirect(res["redirect_to"])

        if u.path == "/consent":
            challenge = q.get("consent_challenge", [""])[0]
            req = get(f"/admin/oauth2/auth/requests/consent?consent_challenge={challenge}")
            subject = req.get("subject")
            requested = req.get("requested_scope", [])
            granted = [s for s in requested if s in ("openid", "offline", "payments:preview")]
            # Evidence the operator chooses to bind into the token itself.
            res = api(f"/admin/oauth2/auth/requests/consent/accept?consent_challenge={challenge}",
                      {"grant_scope": granted, "remember": False,
                       "grant_access_token_audience": req.get("requested_access_token_audience", []),
                       "session": {
                           "access_token": {
                               "atb_human_subject": subject,
                               "atb_consent_recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                               "atb_consent_recorded_by": "benchmark-consent-app",
                               "atb_granted_scope": granted,
                           }}})
            record("consent.accepted", subject=subject,
                   client=req.get("client", {}).get("client_id"),
                   requested_scope=requested, granted_scope=granted,
                   note="Attribution exists only because this app wrote it. Hydra stores the "
                        "subject string it was handed and asserts nothing about its provenance.")
            return self._redirect(res["redirect_to"])

        self.send_response(404); self.end_headers()

    def _redirect(self, to):
        self.send_response(302); self.send_header("Location", to); self.end_headers()


if __name__ == "__main__":
    open(EVIDENCE, "w").close()
    HTTPServer(("127.0.0.1", 3001), H).serve_forever()
