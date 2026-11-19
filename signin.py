"""Sign-in with the company's identity provider (OIDC), through Streamlit's
st.login. It is on when .streamlit/secrets.toml has an [auth] section that
exposes the ID token (expose_tokens = "id"); without one the page works as
before, with no sign-in.

The ID token is what the page sends the gateway as the caller's proof: the
virtual key names the identity provider, so the gateway verifies the token
and records who made each call. Streamlit does not refresh it, so once it
expires (an hour, by Okta's default) the person signs in again.
"""

from __future__ import annotations

import base64
import json
import time

import streamlit as st

# Ask for a new sign-in this close to expiry, so no call leaves with a token
# that lapses on the way.
MARGIN_S = 60


def configured() -> bool:
    """An [auth] section with its client filled in; a template left blank
    keeps the page working without sign-in."""
    try:
        auth = st.secrets.get("auth") or {}
    except Exception:  # noqa: BLE001 - no secrets.toml at all means no sign-in
        return False
    return bool(str(auth.get("client_id", "")).strip() and str(auth.get("client_secret", "")).strip())


def _expiry(token: str) -> int:
    """The token's exp claim. Read without verifying: the gateway verifies it;
    the page only needs to know when to ask for a new one."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return int(claims.get("exp") or 0)
    except (IndexError, ValueError):
        return 0


def require() -> tuple[str, str]:
    """The signed-in person's email and ID token; otherwise the page stops at
    a sign-in prompt."""
    if not st.user.is_logged_in:
        st.title("LLM Gateway Playground")
        with st.container(border=True):
            st.markdown("#### Sign in to continue")
            st.markdown(
                "Every call this page makes through the LLM gateway carries your sign-in, so the gateway "
                "verifies who you are and Observability records each call under your name."
            )
            st.button("Log in", type="primary", on_click=st.login)
        st.stop()

    token = (st.user.tokens or {}).get("id", "")
    if not token:
        st.error('Sign-in works, but the ID token is not exposed: add expose_tokens = "id" to [auth] in .streamlit/secrets.toml.')
        st.stop()
    if _expiry(token) - MARGIN_S <= time.time():
        st.title("LLM Gateway Playground")
        st.warning("Your sign-in has expired. Log out and sign in again to keep calling the gateway.")
        st.button("Log out", type="primary", on_click=st.logout)
        st.stop()

    user = str(st.user.get("email") or st.user.get("sub") or "")
    return user, token
