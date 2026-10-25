"""Real-browser check of the example app, with Chromium's virtual passkey device.

Run the example first:

    DEMO_PASSWORD='demo password 123' cargo run --example minimal --features axum,passkeys

then:

    python3 tests/browser/passkeys.py

It signs in with the password, checks the cookie flags, adds a passkey,
signs out, signs in with the passkey, and checks that a page on another
origin (same site, other port, so SameSite cookies are still sent) can't
end the user's sessions.
"""

import http.server
import os
import sys
import threading

from playwright.sync_api import sync_playwright

APP = os.environ.get("APP", "http://localhost:3000")
PASSWORD = os.environ.get("DEMO_PASSWORD", "demo password 123")
EVIL_PORT = 3999
EVIL_PAGE = f"""<!doctype html><title>evil</title><script>
fetch("{APP}/auth/sessions/end-others", {{method: "POST", credentials: "include", mode: "no-cors"}})
  .then(() => document.title = "sent", () => document.title = "failed");
</script>"""

failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


class Evil(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = EVIL_PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def wait_status(page, text):
    page.wait_for_function("t => document.getElementById('status').textContent.includes(t)", arg=text, timeout=15000)


def main():
    evil = http.server.ThreadingHTTPServer(("127.0.0.1", EVIL_PORT), Evil)
    threading.Thread(target=evil.serve_forever, daemon=True).start()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(APP)
        cdp = ctx.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        auth = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True,
        }})["authenticatorId"]

        # Password sign-in.
        page.fill("#password", "wrong password")
        page.click("button[type=submit]")
        wait_status(page, "Wrong username or password")
        check(True, "a wrong password is refused with the app's own wording")
        page.fill("#password", PASSWORD)
        page.click("button[type=submit]")
        wait_status(page, "Signed in.")
        cookies = {c["name"]: c for c in ctx.cookies()}
        s = cookies.get("__Host-doorward")
        check(s is not None, "session cookie set")
        check(s and s["httpOnly"] and s["secure"] and s["sameSite"] == "Strict" and s["path"] == "/", "session cookie is HttpOnly, Secure, SameSite=Strict, Path=/")
        check(s and s["expires"] == -1, "not ticked: the session cookie ends with the browser")
        check("__Host-doorward-device" in cookies, "remembered-browser cookie set")
        check(page.evaluate("document.cookie") == "", "scripts can't read either cookie")

        # Add a passkey (the sign-in is recent, so no confirmation is asked).
        page.click("#add-passkey")
        wait_status(page, "Passkey added.")
        creds = cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth})["credentials"]
        check(len(creds) == 1 and creds[0]["isResidentCredential"], "a discoverable passkey was made")
        check(creds[0]["rpId"] == "localhost", "for this site only")

        # Sign out, then in with the passkey and no username.
        page.click("#sign-out")
        wait_status(page, "Signed out.")
        check("__Host-doorward" not in {c["name"] for c in ctx.cookies()}, "signing out clears the session cookie")
        page.fill("#username", "")
        page.click("#passkey-sign-in")
        wait_status(page, "Signed in with a passkey.")
        check("passkey" in page.text_content("#method"), "the session says it began with a passkey")

        # A second session elsewhere, then a page on another origin tries to end it.
        other = browser.new_context()
        op = other.new_page()
        op.goto(APP)
        op.fill("#password", PASSWORD)
        op.click("button[type=submit]")
        wait_status(op, "Signed in.")
        evil_page = ctx.new_page()
        evil_page.goto(f"http://localhost:{EVIL_PORT}/")
        evil_page.wait_for_function("document.title !== 'evil'", timeout=10000)
        op.reload()
        op.wait_for_selector("#signed-in:not([hidden])", timeout=10000)
        check(True, "a request from another origin couldn't end the other session")
        log = open(os.environ.get("APP_LOG", "/dev/null")).read() if os.environ.get("APP_LOG") else ""
        if log:
            check("cross-origin request refused" in log, "and the server logged the refusal")

        browser.close()
    evil.shutdown()
    if failures:
        print(f"{len(failures)} check(s) failed")
        sys.exit(1)
    print("all browser checks passed")


if __name__ == "__main__":
    main()
