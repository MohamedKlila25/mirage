"""Mirage analyst dashboard (Phase 0 skeleton: live sessions and events).

Reached only through an SSH tunnel:  ssh -L 8501:localhost:8501 <ec2>
Attacker text is shown in tables only, never rendered as Markdown, so a planted link or
image can't load in the analyst's browser.
"""
import os

import streamlit as st

from dashboard.data import counts, get_db, recent_events, sessions_overview

try:                                  # local runs: pick up MONGO_URI (and creds) from .env
    from local.env import load_env
    load_env()
except Exception:
    pass

st.set_page_config(page_title="Mirage", layout="wide")


@st.cache_resource
def _db():
    return get_db(os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017/maya"))


@st.fragment(run_every="5s")
def live():
    db = _db()
    c = counts(db)
    cols = st.columns(4)
    cols[0].metric("Sessions", c["sessions"])
    cols[1].metric("Events", c["events"])
    cols[2].metric("Pending approvals", c["pending_approvals"])
    cols[3].metric("Kill switch", "ON" if c["kill_switch"] else "off")

    st.subheader("Attacker sessions")
    sessions = sessions_overview(db)
    if sessions:
        st.dataframe(sessions, hide_index=True)
    else:
        st.info("No attacker activity yet.")

    st.subheader("Latest events")
    events = recent_events(db)
    if events:
        st.dataframe(events, hide_index=True)
    else:
        st.info("No events yet.")


st.title("Mirage — analyst dashboard")
live()
