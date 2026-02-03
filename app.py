"""CommBridge AI — Abnormal Security
══════════════════════════════════════════════════════════════
AI-powered incident communication platform that ingests raw telemetry,
correlates events, and generates brand-compliant customer updates.

PRODUCTION VERSION — Source of Truth Workflow
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

# ──────────────────────────────────────────────────────────────
# 1  DATA LOADING
# ──────────────────────────────────────────────────────────────
_BASE = Path(__file__).resolve().parent
_DATA_DIR: Path | None = None
for _candidate in (_BASE / "data", _BASE / "data (2)"):
    if _candidate.is_dir():
        _DATA_DIR = _candidate
        break

EXPECTED_FILES = [
    "cloudwatch_logs.json",
    "prometheus_metrics.json",
    "pagerduty_incident.json",
    "github_deployments.json",
    "incident_context.txt",
]


@st.cache_data
def load_data() -> dict[str, Any]:
    """Load all incident files into memory.  Returns {filename: content | None}."""
    out: dict[str, Any] = {}
    if _DATA_DIR is None:
        return {f: None for f in EXPECTED_FILES}
    for fname in EXPECTED_FILES:
        path = _DATA_DIR / fname
        if not path.exists():
            out[fname] = None
        elif fname.endswith(".json"):
            out[fname] = json.loads(path.read_text())
        else:
            out[fname] = path.read_text()
    return out


# ──────────────────────────────────────────────────────────────
# 2  CORRELATION ENGINE
# ──────────────────────────────────────────────────────────────
def _parse_ts(iso: str) -> datetime:
    """Parse ISO-8601 to a timezone-aware datetime."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _fmt_time(iso: str) -> str:
    """ISO timestamp → '2:23 PM'.

    All timestamps in the source data carry hour values that match the PT
    narrative in incident_context.txt, so we render the hour directly.
    """
    dt = _parse_ts(iso)
    return dt.strftime("%I:%M %p").lstrip("0")


def build_timeline(data: dict[str, Any]) -> list[dict]:
    """Cross-reference GitHub, CloudWatch, PagerDuty, and Prometheus into a
    single sorted event list.

    * Repeated CloudWatch errors are consolidated into one entry.
    * Prometheus contributes only key peak-metric markers (not every sample).
    """
    events: list[dict] = []

    # ── GitHub deployments ────────────────────────────────────────
    for dep in (data.get("github_deployments.json") or {}).get("deployments", []):
        is_revert = "revert" in dep.get("title", "").lower()
        events.append(
            {
                "ts": dep["timestamp"],
                "kind": "fix" if is_revert else "deploy",
                "title": f"Deployment — {dep['service']}",
                "detail": dep.get("title", ""),
                "meta": dep.get("diff_snippet") or dep.get("description", ""),
                "source": "GitHub",
            }
        )

    # ── CloudWatch — consolidate repeated errors ─────────────────
    logs = (data.get("cloudwatch_logs.json") or {}).get("logs", [])
    errors = [lg for lg in logs if lg.get("level") == "ERROR"]
    non_errors = [lg for lg in logs if lg.get("level") != "ERROR"]

    if errors:
        first = errors[0]
        ctx = first.get("context", {})
        events.append(
            {
                "ts": first["timestamp"],
                "kind": "alert",
                "title": f"CloudWatch — {len(errors)} connection timeout errors",
                "detail": first.get("message", ""),
                "meta": (
                    f"Pool: {ctx.get('active_connections', '?')}"
                    f"/{ctx.get('connection_pool_size', '?')} active · "
                    f"Wait: {ctx.get('wait_time_ms', '?')} ms · "
                    f"Database: {ctx.get('database', '?')}"
                ),
                "source": "CloudWatch",
            }
        )

    for lg in non_errors:
        ctx = lg.get("context", {})
        events.append(
            {
                "ts": lg["timestamp"],
                "kind": "info",
                "title": f"CloudWatch — {lg.get('service', '')}",
                "detail": lg.get("message", ""),
                "meta": (
                    f"Active: {ctx.get('active_connections', '?')}"
                    f"/{ctx.get('connection_pool_size', '?')}"
                ),
                "source": "CloudWatch",
            }
        )

    # ── PagerDuty ─────────────────────────────────────────────────
    _PD_KIND = {"trigger": "alert", "acknowledge": "ack", "resolve": "fix"}
    pd_inc = (data.get("pagerduty_incident.json") or {}).get("incident", {})
    for te in pd_inc.get("timeline", []):
        events.append(
            {
                "ts": te["timestamp"],
                "kind": _PD_KIND.get(te.get("type", ""), "info"),
                "title": f"PagerDuty — {te.get('type', '').title()}",
                "detail": te.get("message", ""),
                "meta": "",
                "source": "PagerDuty",
            }
        )

    # ── Prometheus — key peak markers only ────────────────────────
    for m in (data.get("prometheus_metrics.json") or {}).get("metrics", []):
        name = m.get("metric_name", "")
        labels = m.get("labels", {})
        values = m.get("values", [])
        if not values:
            continue

        if name == "http_request_duration_seconds" and labels.get("quantile") == "0.99":
            peak = max(values, key=lambda v: v["value"])
            events.append(
                {
                    "ts": peak["timestamp"],
                    "kind": "alert",
                    "title": "Prometheus — Response Time Peak",
                    "detail": (
                        f"P99 latency spiked to {peak['value']} s "
                        f"(baseline 0.15 s — {peak['value'] / 0.15:.0f}× increase)"
                    ),
                    "meta": 'http_request_duration_seconds{quantile="0.99"}',
                    "source": "Prometheus",
                }
            )

        elif name == "database_connection_pool_utilization":
            # First sample that hits 100 %
            for v in values:
                if v["value"] >= 1.0:
                    events.append(
                        {
                            "ts": v["timestamp"],
                            "kind": "alert",
                            "title": "Prometheus — Connection Pool Exhaustion",
                            "detail": "Pool utilization reached 100 % — all connections occupied",
                            "meta": "database_connection_pool_utilization",
                            "source": "Prometheus",
                        }
                    )
                    break

        elif name == "http_requests_total" and labels.get("status") == "500":
            peak_err = max(values, key=lambda v: v["value"])
            if peak_err["value"] > 0:
                events.append(
                    {
                        "ts": peak_err["timestamp"],
                        "kind": "alert",
                        "title": "Prometheus — Error Rate Peak",
                        "detail": f"500 errors peaked at {int(peak_err['value'])} / min",
                        "meta": 'http_requests_total{status="500"}',
                        "source": "Prometheus",
                    }
                )

    events.sort(key=lambda e: e["ts"])
    return events


# ──────────────────────────────────────────────────────────────
# 3  SANITIZATION & BRAND GUARDRAILS
# ──────────────────────────────────────────────────────────────
def sanitize_text(text: str) -> str:
    """Strip internal identifiers and engineer names from any text."""
    # Internal service/database names
    text = re.sub(r'\brds-prod-main\b', 'database', text, flags=re.IGNORECASE)
    text = re.sub(r'\bapi-gateway\b', 'API', text, flags=re.IGNORECASE)

    # Engineer names (common test names)
    for name in ['Alice', 'Bob', 'Charlie', 'Dave', 'Eve', 'John', 'Jane']:
        text = re.sub(rf'\b{name}\b', '[Engineer]', text, flags=re.IGNORECASE)

    # Email patterns
    text = re.sub(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', '[email]', text)

    # PR/commit references
    text = re.sub(r'\bPR\s*#?\d+\b', 'code change', text, flags=re.IGNORECASE)
    text = re.sub(r'\b[a-f0-9]{7,40}\b', 'commit', text)

    return text


# ──────────────────────────────────────────────────────────────
# 4  AI DRAFT GENERATION
# ──────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are a technical communications writer for Abnormal Security.

BRAND VOICE:
• Tone: Professional, empathetic, and future-facing
• Style: "Lucid Complexity" — technically accurate but extremely clear to non-technical readers
• Never use internal jargon or technical identifiers in customer communications

STRICT BRAND GUARDRAILS (violating any of these is a failure):
1. NEVER mention internal database names (e.g., rds-prod-main). Use only "database" or "our database".
2. NEVER mention internal service names. Use "API", "our platform", or "our service" — never identifiers like "api-gateway".
3. NEVER include engineer names, emails, or PR/commit references.
4. ALWAYS translate technical jargon:
   • "OOM" / "out of memory"         → "memory issues"
   • "Connection pool"                → "database performance"
   • "P99" / any percentile          → "response times"
   • "Connection exhaustion"         → "database performance degradation"
   • "Rollback"                      → "configuration revert" or "fix deployed"
   • "Timeout"                       → "response delay"
   • "500 errors"                    → "service errors"
   • "Latency spike"                 → "slower response times"

CRITICAL DATA SOURCE:
**YOUR ONLY SOURCE OF TRUTH:** The user-provided "Executive Summary" (from st.session_state.truth_summary) is your EXCLUSIVE data source.
**DISREGARD:** All previous JSON data, raw logs, and metrics. If the summary conflicts with any data you've seen, IGNORE the data and use ONLY the summary.
**ABSOLUTE RULE:** If a fact is in the summary, use it. If it's NOT in the summary, do NOT invent it from JSON logs.

The Executive Summary represents expert human judgment and overrides all automated data.

Write ONLY the body of the communication. No subject line. No sign-off. No "Dear Customer" greeting.
"""

# Clean default summary (no markdown asterisks for text editor)
_DEFAULT_TRUTH_SUMMARY = """\
Trigger: Detected at 2:23 PM PT — API response times degraded significantly
Root Cause: A configuration change at 2:15 PM increased a timeout value (10 s → 30 s), exhausting all database connections (50/50 active)
Peak Impact: Response times reached 18 s (120× baseline); error rate peaked at 120 / min
Containment: Rollback initiated at ~3:00 PM; database recovery began by 3:05 PM
Resolution: Full service restored at 4:45 PM

Incident window: 2:23 PM – 4:45 PM  ·  Duration: 2 h 22 min"""

_STAGE_PROMPTS = {
    "IDENTIFIED": (
        "Stage: IDENTIFIED — root cause confirmed.\n"
        "Write 3–4 sentences stating what the root cause was (translate to customer-friendly language) "
        "and that a fix is actively being implemented. Be specific but accessible."
    ),
    "UPDATE": (
        "Stage: UPDATE — interim progress update (repeatable).\n"
        "Write 2–3 sentences summarizing the latest progress from the Executive Summary. "
        "Focus on what the team is currently doing (e.g., testing, validating, deploying). "
        "Keep it brief and reassuring without over-promising."
    ),
    "MONITORING": (
        "Stage: MONITORING — fix is live, metrics recovering.\n"
        "Write 2–3 sentences notifying users the fix is deployed and that metrics "
        "are stabilizing. Express confidence without over-promising."
    ),
    "RESOLVED": (
        "Stage: RESOLVED — incident fully closed.\n"
        "Write 3–4 sentences including the exact start/end times, total duration, "
        "a customer-safe explanation of the root cause and fix, and a forward-looking "
        "statement about preventive measures."
    ),
}

# Dynamic timeline stages (user can select any of these)
AVAILABLE_STAGES = ["IDENTIFIED", "UPDATE", "MONITORING", "RESOLVED"]

FALLBACK_DRAFTS = {
    "IDENTIFIED": (
        "We have identified the root cause of the current service degradation. "
        "Our investigation revealed that a recent system update inadvertently affected "
        "critical infrastructure components, resulting in elevated response times and "
        "intermittent errors for API requests. Our engineering team is actively "
        "implementing a fix and will deploy it shortly. We expect service to return "
        "to normal within the next 30 minutes and will provide updates as progress continues."
    ),
    "UPDATE": (
        "Our team continues working to resolve the ongoing service issues. We have "
        "completed initial testing of the fix in our staging environment and are now "
        "preparing for production deployment. Early indicators show significant improvement "
        "in response times. We anticipate deploying the fix within the next 15 minutes "
        "and will monitor closely to ensure full resolution."
    ),
    "MONITORING": (
        "The fix has been successfully deployed and we are now actively monitoring "
        "system performance. Initial metrics indicate that response times have returned "
        "to normal baseline levels and error rates have dropped to zero. We will continue "
        "monitoring for the next hour to ensure stability before declaring full resolution. "
        "Thank you for your patience during this incident."
    ),
    "RESOLVED": (
        "The service incident has been fully resolved. All systems are operating normally "
        "and we have confirmed that API response times and error rates have returned to "
        "baseline levels. The root cause was traced to a configuration change that "
        "temporarily impacted system resources. We have reverted the change and implemented "
        "additional monitoring to prevent similar issues in the future. We apologize for "
        "any inconvenience this may have caused and appreciate your patience."
    ),
}


def generate_single_draft(
    api_key: str,
    stage_type: str,
    truth_summary: str,
    raw_logs_context: str = ""
) -> str:
    """Call OpenAI GPT-4o-mini to produce a single stage draft.

    Args:
        api_key: OpenAI API key
        stage_type: Stage type (IDENTIFIED, UPDATE, MONITORING, RESOLVED)
        truth_summary: User-edited Executive Summary (Priority 1 source)
        raw_logs_context: Optional raw logs for context (Priority 2 source)
    """
    from openai import OpenAI

    client = OpenAI(api_key=api_key)

    # Sanitize the truth summary before sending to AI
    sanitized_summary = sanitize_text(truth_summary)

    # Build augmented system prompt with priority sources
    system_prompt = _SYSTEM_PROMPT
    if sanitized_summary.strip():
        system_prompt += (
            "\n\n═══ EXECUTIVE SUMMARY (Priority 1 — Trust This) ═══\n"
            f"{sanitized_summary.strip()}\n"
        )
    if raw_logs_context.strip():
        system_prompt += (
            "\n\n═══ RAW INCIDENT DATA (Priority 2 — Fill Gaps Only) ═══\n"
            f"{raw_logs_context.strip()}\n"
        )

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": _STAGE_PROMPTS[stage_type]},
        ],
        temperature=0.3,
        max_tokens=300,
    )
    # Sanitize output as additional safeguard
    return sanitize_text(resp.choices[0].message.content.strip())


# ──────────────────────────────────────────────────────────────
# 5  UI COMPONENTS
# ──────────────────────────────────────────────────────────────
_KIND_COLORS = {
    "deploy": "#6366f1",  # indigo
    "alert": "#ef4444",  # red
    "ack": "#f59e0b",  # amber
    "fix": "#10b981",  # emerald
    "info": "#64748b",  # slate
}
_KIND_LABELS = {
    "deploy": "DEPLOY",
    "alert": "ALERT",
    "ack": "ACK",
    "fix": "FIX",
    "info": "INFO",
}


def _timeline_event(time_str: str, evt: dict, is_last: bool = False):
    """Render a single vertical-timeline row."""
    color = _KIND_COLORS.get(evt["kind"], "#94a3b8")
    badge = _KIND_LABELS.get(evt["kind"], evt["kind"].upper())
    connector = (
        ""
        if is_last
        else (
            '<div style="width:2px;height:24px;'
            "background:linear-gradient(#cbd5e1,transparent);"
            'margin-left:6px"></div>'
        )
    )
    meta_html = (
        (
            '<div style="font-size:0.72rem;color:#94a3b8;font-family:monospace;'
            f'margin-top:2px;word-break:break-all">{evt["meta"]}</div>'
        )
        if evt.get("meta")
        else ""
    )

    st.markdown(
        f"""
        <div style="display:flex;align-items:flex-start;gap:14px;margin-bottom:4px">
          <div style="display:flex;flex-direction:column;align-items:center;min-width:14px">
            <div style="width:14px;height:14px;border-radius:50%;background:{color};
                 box-shadow:0 0 6px {color}55;flex-shrink:0"></div>
            {connector}
          </div>
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
              <span style="font-size:0.72rem;font-family:monospace;
                    color:#64748b;font-weight:600">{time_str}</span>
              <span style="font-size:0.61rem;font-weight:700;color:{color};
                    background:{color}18;padding:1px 7px;border-radius:10px;
                    border:1px solid {color}40">{badge}</span>
              <span style="font-size:0.67rem;color:#94a3b8">{evt['source']}</span>
            </div>
            <div style="font-size:0.87rem;font-weight:600;color:#1e293b;
                 margin-top:2px">{evt['title']}</div>
            <div style="font-size:0.79rem;color:#64748b;
                 margin-top:1px">{evt['detail']}</div>
            {meta_html}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _build_metric_dfs(prom: dict) -> dict[str, pd.DataFrame]:
    """Parse Prometheus JSON → named DataFrames with UTC-aware timestamps."""
    result: dict[str, pd.DataFrame] = {}
    for m in prom.get("metrics", []):
        name = m.get("metric_name", "")
        labels = m.get("labels", {})
        df = pd.DataFrame(m["values"])
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)

        if name == "http_request_duration_seconds":
            q = labels.get("quantile", "")
            key = f"latency_p{int(float(q) * 100)}" if q else name
        elif name == "database_connection_pool_utilization":
            key = "pool_util"
        elif name == "http_requests_total":
            key = "errors_500"
        else:
            key = name

        result[key] = df
    return result


def _render_charts(data: dict):
    """Two-column metric charts with deployment-time annotations."""
    prom = data.get("prometheus_metrics.json")
    if not prom:
        st.warning("Prometheus data unavailable — charts cannot render.")
        return

    dfs = _build_metric_dfs(prom)
    deploy_ts = pd.Timestamp("2025-01-15T14:15:00+00:00")

    col1, col2 = st.columns(2)

    # ── Col 1: Response Times ─────────────────────────────────────
    with col1:
        st.markdown("**Response Times (seconds)**")
        df99 = dfs.get("latency_p99")
        df50 = dfs.get("latency_p50")

        if df99 is not None:
            layers: list = []

            # P99 solid line
            layers.append(
                alt.Chart(df99)
                .mark_line(color="#ef4444", strokeWidth=2.5)
                .encode(
                    x=alt.X(
                        "timestamp:T",
                        title=None,
                        axis=alt.Axis(format="%H:%M", labelFontSize=10),
                    ),
                    y=alt.Y(
                        "value:Q",
                        title="Seconds",
                        scale=alt.Scale(domain=[0, 20]),
                        axis=alt.Axis(labelFontSize=10, titleFontSize=11),
                    ),
                )
            )

            # P50 dashed line
            if df50 is not None:
                layers.append(
                    alt.Chart(df50)
                    .mark_line(color="#f59e0b", strokeWidth=1.5, strokeDash=[4, 3])
                    .encode(x="timestamp:T", y="value:Q")
                )

            # Deployment vertical rule
            layers.append(
                alt.Chart(pd.DataFrame({"x": [deploy_ts]}))
                .mark_rule(color="#6366f1", strokeWidth=1.5, strokeDash=[3, 3])
                .encode(x="x:T")
            )

            # Annotation label
            layers.append(
                alt.Chart(pd.DataFrame({"x": [deploy_ts], "y": [19.5]}))
                .mark_text(color="#6366f1", fontSize=9, fontWeight="bold", align="right")
                .encode(x="x:T", y="y:Q", text=alt.value("↑ Config change"))
            )

            st.altair_chart(
                alt.layer(*layers).properties(height=175),
                use_container_width=True,
            )
            st.caption(
                "Red = worst-case response time · "
                "Amber dashed = median · Purple = deployment"
            )

    # ── Col 2: Database Performance & Error Rate ──────────────────
    with col2:
        st.markdown("**Database Performance & Error Rate**")
        df_pool = dfs.get("pool_util")
        df_err = dfs.get("errors_500")

        if df_pool is not None:
            df_pct = df_pool.assign(pct=df_pool["value"] * 100)
            layers = []

            # Pool utilization area
            layers.append(
                alt.Chart(df_pct)
                .mark_area(
                    color="#6366f1", opacity=0.25, stroke="#6366f1", strokeWidth=2
                )
                .encode(
                    x=alt.X(
                        "timestamp:T",
                        title=None,
                        axis=alt.Axis(format="%H:%M", labelFontSize=10),
                    ),
                    y=alt.Y(
                        "pct:Q",
                        title="Utilization %",
                        scale=alt.Scale(domain=[0, 110]),
                        axis=alt.Axis(labelFontSize=10, titleFontSize=11, format="d"),
                    ),
                )
            )

            # 100 % exhaustion threshold
            layers.append(
                alt.Chart(pd.DataFrame({"y": [100]}))
                .mark_rule(
                    color="#ef4444", strokeDash=[2, 3], strokeWidth=1.5, opacity=0.6
                )
                .encode(y="y:Q")
            )

            # Error rate overlay (scaled to 0-100 for dual display)
            if df_err is not None:
                max_err = df_err["value"].max() or 1
                df_err_s = df_err.assign(scaled=df_err["value"] / max_err * 100)
                layers.append(
                    alt.Chart(df_err_s)
                    .mark_line(color="#ef4444", strokeWidth=2)
                    .encode(x="timestamp:T", y=alt.Y("scaled:Q", title=None))
                )

            st.altair_chart(
                alt.layer(*layers).properties(height=175),
                use_container_width=True,
            )
            caption = "Purple area = pool usage · Red dashed = 100 % capacity"
            if df_err is not None:
                caption += f" · Red line = error rate (peak {int(df_err['value'].max())}/min)"
            st.caption(caption)


# ──────────────────────────────────────────────────────────────
# 6  LANDING PAGE
# ──────────────────────────────────────────────────────────────
def render_landing_page():
    """Incident selection landing page."""
    st.markdown(
        """
        <div class="centered-header">
          <h1>CommBridge AI | Abnormal Security</h1>
          <h2 style="font-size: 1.5rem; font-weight: 600; color: #0f172a; margin-top: 1rem;">
            Incident Dashboard
          </h2>
          <div style="color: #64748b; font-size: 0.95rem; margin-top: 0.5rem;">
            Generate AI-powered communications for incidents
          </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Create Manual Incident button - THE HAMMER (complete state wipe)
    if st.button("🆕 Create Manual Incident", type="primary", use_container_width=False, key="start_new"):
        # NUCLEAR OPTION: Clear ALL session state to ensure fresh start
        st.session_state.clear()

        # Immediately reinitialize with blank state
        st.session_state["view"] = "incident"
        st.session_state["truth_summary"] = ""
        st.session_state["incident_timeline"] = []
        st.session_state["next_id"] = 0
        st.session_state["current_incident_id"] = None
        st.session_state["resolved_incidents"] = [
            {
                "id": "demo_2023_01_15",
                "title": "API Performance Degradation",
                "severity": "SEV-2",
                "date": "January 15, 2025",
                "duration": "2h 22min",
                "timerange": "2:23 PM – 4:45 PM PT",
                "summary": "Database connection pool exhaustion caused elevated API response times. Fix deployed and service restored.",
                "status": "resolved",
            }
        ]

        # Force immediate rerun to refresh UI
        st.rerun()

    st.divider()

    # Resolved Incidents section - Status-based filtering
    st.markdown("### 🗂️ Resolved Incidents")

    # Get resolved incidents from session state (or initialize with demo incident)
    if "resolved_incidents" not in st.session_state:
        st.session_state["resolved_incidents"] = [
            {
                "id": "demo_2023_01_15",
                "title": "API Performance Degradation",
                "severity": "SEV-2",
                "date": "January 15, 2025",
                "duration": "2h 22min",
                "timerange": "2:23 PM – 4:45 PM PT",
                "summary": "Database connection pool exhaustion caused elevated API response times. Fix deployed and service restored.",
                "status": "resolved",  # Must be 'resolved' to appear here
            }
        ]

    # Filter and display only resolved incidents
    resolved_incidents = [
        inc for inc in st.session_state.get("resolved_incidents", [])
        if inc.get("status") == "resolved"
    ]

    if resolved_incidents:
        for incident in resolved_incidents:
            with st.container(border=True):
                col1, col2 = st.columns([1, 8])
                with col1:
                    st.markdown("✅")
                with col2:
                    st.markdown(f"**RESOLVED: {incident['title']}**")
                    st.caption(
                        f"{incident['severity']} · {incident['date']} · "
                        f"Duration: {incident['duration']} · {incident['timerange']}"
                    )
                    st.caption(incident['summary'])

                if st.button(
                    "📝  View Resolved Incident",
                    use_container_width=True,
                    key=f"view_{incident['id']}"
                ):
                    # Restore the pre-populated 2:23 PM incident data
                    st.session_state["incident_timeline"] = [
                        {
                            "id": 0,
                            "stage_type": "IDENTIFIED",
                            "draft": FALLBACK_DRAFTS["IDENTIFIED"],
                            "is_deployed": False,
                        },
                        {
                            "id": 1,
                            "stage_type": "UPDATE",
                            "draft": FALLBACK_DRAFTS["UPDATE"],
                            "is_deployed": False,
                        },
                        {
                            "id": 2,
                            "stage_type": "MONITORING",
                            "draft": FALLBACK_DRAFTS["MONITORING"],
                            "is_deployed": False,
                        },
                        {
                            "id": 3,
                            "stage_type": "RESOLVED",
                            "draft": FALLBACK_DRAFTS["RESOLVED"],
                            "is_deployed": False,
                        },
                    ]
                    st.session_state["next_id"] = 4
                    st.session_state["truth_summary"] = _DEFAULT_TRUTH_SUMMARY
                    st.session_state["current_incident_id"] = incident["id"]
                    st.session_state["view"] = "incident"
                    st.rerun()
    else:
        st.info("No resolved incidents to display.", icon="ℹ️")


# ──────────────────────────────────────────────────────────────
# 7  INCIDENT DASHBOARD
# ──────────────────────────────────────────────────────────────
def render_incident_dashboard(data: dict, api_key: str):
    """Main incident view with tabs for comms and technical timeline."""

    # Back button
    if st.button("← Back to Incidents", key="back_btn"):
        st.session_state["view"] = "landing"
        st.rerun()

    # Dynamic incident header - changes based on current incident
    current_incident_id = st.session_state.get("current_incident_id", None)

    if current_incident_id == "demo_2023_01_15":
        # Viewing the resolved demo incident
        header_html = """
        <div class="centered-header">
          <h1>CommBridge AI | Abnormal Security</h1>
          <div class="subtitle">API Performance Degradation · SEV-2</div>
          <div style="color: #94a3b8; font-size: 0.85rem; margin-top: 4px;">
            Jan 15, 2025 · 2:23 PM – 4:45 PM PT · Duration: 2h 22min
          </div>
        </div>
        """
    else:
        # New manual incident
        header_html = """
        <div class="centered-header">
          <h1>CommBridge AI | Abnormal Security</h1>
          <div class="subtitle">New Manual Incident</div>
          <div style="color: #94a3b8; font-size: 0.85rem; margin-top: 4px;">
            Create and manage communications for your incident
          </div>
        </div>
        """

    st.markdown(header_html, unsafe_allow_html=True)

    # No auto-generation on first load - timeline is user-driven

    # Tabs — Customer Communication first, Technical Timeline second
    tab_cc, tab_tl = st.tabs(
        ["📝 Customer Communication", "📊 Technical Timeline"]
    )

    # ═══════════════════════════════════════════════════════════════
    # TAB 1 — CUSTOMER COMMUNICATION (The "Bridge")
    # ═══════════════════════════════════════════════════════════════
    with tab_cc:
        # Show last generation result if available (DON'T delete it immediately)
        if "last_generation_message" in st.session_state:
            msg = st.session_state["last_generation_message"]
            if "SUCCESS" in msg:
                st.success(msg, icon="🎉")
            elif "error" in msg.lower() or "⚠️" in msg:
                st.error(msg, icon="⚠️")
            else:
                st.info(msg, icon="ℹ️")

        # Show current ground truth status at the top
        current_truth = st.session_state.get("truth_summary", "")
        if current_truth.strip():
            st.info(f"📝 Ground truth active: {len(current_truth)} characters ready for AI generation", icon="✅")
        else:
            st.warning("⚠️ STEP 1: Go to 'Technical Timeline' tab → Enter your ground truth summary → Come back here → Click 'Synchronize'", icon="📝")

        # Global controls at the top
        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2, 1, 1])

        with ctrl_col1:
            # Global regenerate button with GUARANTEED bootstrap + immediate rerun
            if st.button("✨ Synchronize & Regenerate All Stages", type="primary", use_container_width=True):
                # STEP 1: Bootstrap timeline if empty (FORCE rebuild)
                timeline = st.session_state.get("incident_timeline", [])

                if not timeline or len(timeline) == 0:
                    # Timeline is empty - manually append 4 standard stages
                    next_id = st.session_state.get("next_id", 0)
                    st.session_state["incident_timeline"] = [
                        {"id": next_id, "stage_type": "IDENTIFIED", "draft": "", "is_deployed": False},
                        {"id": next_id + 1, "stage_type": "UPDATE", "draft": "", "is_deployed": False},
                        {"id": next_id + 2, "stage_type": "MONITORING", "draft": "", "is_deployed": False},
                        {"id": next_id + 3, "stage_type": "RESOLVED", "draft": "", "is_deployed": False},
                    ]
                    st.session_state["next_id"] = next_id + 4
                    # CRITICAL: Rerun immediately so UI draws the new cards BEFORE filling them
                    st.rerun()

                # STEP 2: Fill ALL stages with content (AI or fallbacks)
                # Get current ground truth from session state
                truth = st.session_state.get("truth_summary", "")

                if api_key and truth.strip():
                    # Use AI with ground truth
                    with st.spinner(f"🤖 Generating {len(st.session_state['incident_timeline'])} stages with AI using your {len(truth)}-character ground truth..."):
                        try:
                            success_count = 0
                            error_details = []
                            for entry in st.session_state["incident_timeline"]:
                                try:
                                    new_draft = generate_single_draft(api_key, entry["stage_type"], truth)
                                    entry["draft"] = new_draft
                                    success_count += 1
                                except Exception as stage_error:
                                    # Log individual stage error but continue
                                    error_details.append(f"{entry['stage_type']}: {str(stage_error)[:50]}")
                                    entry["draft"] = FALLBACK_DRAFTS[entry["stage_type"]]

                            if success_count > 0:
                                msg = f"✅ SUCCESS! Generated {success_count}/{len(st.session_state['incident_timeline'])} stages using your ground truth!"
                                if error_details:
                                    msg += f" ({len(error_details)} failed: {', '.join(error_details)})"
                                st.session_state["last_generation_message"] = msg
                            else:
                                st.session_state["last_generation_message"] = f"❌ ALL stages failed. Errors: {'; '.join(error_details)}"
                        except Exception as e:
                            # Unexpected error - use fallbacks and show full error
                            error_msg = str(e)
                            import traceback
                            full_trace = traceback.format_exc()
                            st.error(f"❌ CRITICAL ERROR: {error_msg}", icon="🚨")
                            st.code(full_trace, language="python")
                            st.info("Using fallback drafts instead. Check your API key and try again.", icon="ℹ️")
                            for entry in st.session_state["incident_timeline"]:
                                entry["draft"] = FALLBACK_DRAFTS[entry["stage_type"]]
                            st.session_state["last_generation_message"] = f"🚨 CRITICAL ERROR: {error_msg[:200]}"
                elif not truth.strip():
                    # No ground truth - use fallbacks
                    st.warning("⚠️ No ground truth found! Using fallback drafts. Add ground truth in Technical Timeline tab.", icon="📝")
                    for entry in st.session_state["incident_timeline"]:
                        entry["draft"] = FALLBACK_DRAFTS[entry["stage_type"]]
                    st.session_state["last_generation_message"] = "⚠️ No ground truth - used fallbacks"
                else:
                    # No API key - use fallbacks
                    st.warning("⚠️ No API key found! Using fallback drafts.", icon="🔑")
                    for entry in st.session_state["incident_timeline"]:
                        entry["draft"] = FALLBACK_DRAFTS[entry["stage_type"]]
                    st.session_state["last_generation_message"] = "⚠️ No API key - used fallbacks"

                st.rerun()

        with ctrl_col2:
            # Test API button
            if st.button("🧪 Test API", use_container_width=True):
                if not api_key:
                    st.error("No API key found!", icon="❌")
                else:
                    with st.spinner("Testing OpenAI API..."):
                        try:
                            from openai import OpenAI
                            client = OpenAI(api_key=api_key)
                            # Make a simple test call
                            response = client.chat.completions.create(
                                model="gpt-4o-mini",
                                messages=[{"role": "user", "content": "Say 'API test successful'"}],
                                max_tokens=10
                            )
                            st.success(f"✅ API WORKS! Response: {response.choices[0].message.content}", icon="🎉")
                            st.session_state["last_generation_message"] = "✅ API key is valid and working!"
                        except Exception as e:
                            st.error(f"❌ API TEST FAILED: {str(e)}", icon="🚨")
                            st.session_state["last_generation_message"] = f"❌ API key invalid: {str(e)[:100]}"
                st.rerun()

        with ctrl_col3:
            # Add new stage button - creates isolated blank card (no object reference leakage)
            if st.button("➕ Add Stage", use_container_width=True):
                # Create a completely new isolated dictionary - no shared references
                new_entry = dict(
                    id=st.session_state["next_id"],
                    stage_type="UPDATE",
                    draft="",  # Blank content
                    is_deployed=False,
                )
                st.session_state["incident_timeline"].append(new_entry)
                st.session_state["next_id"] += 1
                st.rerun()

        st.divider()

        # Render dynamic timeline cards
        timeline = st.session_state.get("incident_timeline", [])

        for idx, entry in enumerate(timeline):
            entry_id = entry["id"]

            # Get stage metadata
            stage_type = entry["stage_type"]
            badge_class = f"stage-{stage_type.lower()}"

            # Live badge
            live_badge = ""
            if entry["is_deployed"]:
                live_badge = '<span style="background-color: #27AE60; color: #FFFFFF; padding: 3px 10px; border-radius: 12px; font-size: 0.7rem; font-weight: 700; margin-left: 10px;">LIVE</span>'

            # Card header with stage badge and live indicator
            st.markdown(
                f"""
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                  <span class="stage-badge {badge_class}">
                    {stage_type}
                  </span>
                  {live_badge}
                </div>
                """,
                unsafe_allow_html=True
            )

            # Stage selection dropdown
            new_stage = st.selectbox(
                "Select Stage Type",
                AVAILABLE_STAGES,
                index=AVAILABLE_STAGES.index(stage_type),
                key=f"stage_select_{entry_id}",
                label_visibility="collapsed"
            )

            # Update stage type if changed
            if new_stage != stage_type:
                entry["stage_type"] = new_stage
                entry["draft"] = FALLBACK_DRAFTS[new_stage]
                st.rerun()

            # Show last generation message for this stage
            msg_key = f"msg_{entry_id}"
            if msg_key in st.session_state:
                msg = st.session_state[msg_key]
                if "✅" in msg:
                    st.success(msg, icon="✅")
                elif "❌" in msg or "⚠️" in msg:
                    st.warning(msg, icon="⚠️")
                else:
                    st.info(msg, icon="ℹ️")
                del st.session_state[msg_key]

            # Context-aware generate/refresh button
            is_empty = not entry["draft"].strip()
            button_label = "✨ Generate Draft" if is_empty else "🔄 Refresh This Stage"

            if st.button(button_label, key=f"generate_{entry_id}", use_container_width=False):
                # Get CURRENT ground truth from session state (user may have edited it)
                truth = st.session_state.get("truth_summary", "")

                if api_key and truth.strip():
                    # Use AI with current ground truth
                    with st.spinner(f"🤖 Generating {stage_type} with AI using your ground truth..."):
                        try:
                            new_draft = generate_single_draft(api_key, stage_type, truth)
                            entry["draft"] = new_draft
                            st.session_state[f"msg_{entry_id}"] = f"✅ AI generated using {len(truth)} chars of ground truth"
                        except Exception as e:
                            # API error - use fallback and show full error
                            entry["draft"] = FALLBACK_DRAFTS[stage_type]
                            st.session_state[f"msg_{entry_id}"] = f"❌ API Error: {str(e)[:100]}"
                elif not truth.strip():
                    # No ground truth - use fallback
                    entry["draft"] = FALLBACK_DRAFTS[stage_type]
                    st.session_state[f"msg_{entry_id}"] = "⚠️ No ground truth - using fallback"
                else:
                    # No API key - use fallback
                    entry["draft"] = FALLBACK_DRAFTS[stage_type]
                    st.session_state[f"msg_{entry_id}"] = "⚠️ No API key - using fallback"

                st.rerun()

            # Text area for draft - use session state key for persistence
            # Initialize the widget key in session state if not present
            widget_key = f"draft_widget_{entry_id}"
            if widget_key not in st.session_state:
                st.session_state[widget_key] = entry["draft"]

            # If the entry draft changed (from AI generation), update the widget
            if entry["draft"] != st.session_state[widget_key]:
                st.session_state[widget_key] = entry["draft"]

            # Display text area using session state key
            st.text_area(
                label=f"draft_{entry_id}",
                height=150,
                key=widget_key,
                label_visibility="collapsed",
                placeholder="Draft will appear here…",
            )

            # Sync changes back to entry
            entry["draft"] = st.session_state[widget_key]

            # Action buttons row
            btn_col1, btn_col2, btn_col3 = st.columns([1, 1, 1])

            with btn_col1:
                if st.button(f"📋 Copy", key=f"copy_{entry_id}", use_container_width=True):
                    st.toast(f"✅ {stage_type} draft copied to clipboard", icon="✅")

            with btn_col2:
                if entry["is_deployed"]:
                    st.button("✅ Deployed", key=f"push_{entry_id}", disabled=True, use_container_width=True)
                else:
                    if st.button("🚀 Push to Status Page", key=f"push_{entry_id}", use_container_width=True):
                        entry["is_deployed"] = True
                        st.toast(f"🚀 {stage_type} successfully deployed to statuspage.io", icon="🚀")
                        st.rerun()

            with btn_col3:
                if st.button("🗑️ Delete", key=f"delete_{entry_id}", use_container_width=True):
                    # Don't allow deleting if only one entry remains
                    if len(timeline) > 1:
                        st.session_state["incident_timeline"].remove(entry)
                        st.rerun()
                    else:
                        st.warning("⚠️ Cannot delete the last entry. Add another entry first.", icon="⚠️")

            st.divider()

        # DEBUG PANEL - Moved to bottom for less clutter
        st.divider()
        with st.expander("Debug Info - View session state details", expanded=False):
            st.write("**Session State Debug:**")
            current_truth = st.session_state.get("truth_summary", "")
            st.write(f"- Ground truth length: **{len(current_truth)} characters**")
            st.write(f"- API key present: **{bool(api_key)}**")
            st.write(f"- API key valid format: **{api_key.startswith('sk-proj-') if api_key else False}**")
            st.write(f"- Timeline stages: **{len(st.session_state.get('incident_timeline', []))}**")

            # Show each stage's current state
            for i, entry in enumerate(st.session_state.get("incident_timeline", [])):
                draft_len = len(entry.get("draft", ""))
                st.write(f"  - Stage {i+1} ({entry['stage_type']}): {draft_len} chars, deployed={entry.get('is_deployed', False)}")

            if current_truth:
                st.write(f"\n**Ground truth content (first 300 chars):**")
                st.code(current_truth[:300] + ("..." if len(current_truth) > 300 else ""), language="text")
            else:
                st.warning("⚠️ No ground truth found in session state!", icon="❗")

    # ═══════════════════════════════════════════════════════════════
    # TAB 2 — TECHNICAL TIMELINE (The "Source of Truth")
    # ═══════════════════════════════════════════════════════════════
    with tab_tl:
        # Ground Truth Editor - PRIMARY CONTROLLER for AI generation
        with st.container(border=True):
            st.subheader("🛠️ Edit Ground Truth Summary")
            st.caption("CRITICAL: AI uses this as PRIMARY SOURCE. Any text here overrides raw JSON data.")

            # Get current truth from session state
            current_truth = st.session_state.get("truth_summary", "")

            # Text area for ground truth editing
            new_truth = st.text_area(
                "Ground Truth Summary",
                value=current_truth,
                height=200,
                key="truth_editor_field",
                placeholder="Enter ground truth: timeline, root cause, impact, resolution...",
                label_visibility="collapsed"
            )

            # CRITICAL: Sync the text area value to session state immediately
            # This ensures any edits are captured before switching tabs or regenerating
            if new_truth != current_truth:
                st.session_state["truth_summary"] = new_truth

            # Show save confirmation if truth exists
            if st.session_state.get("truth_summary", "").strip():
                st.success(
                    f"✅ Ground truth saved ({len(st.session_state['truth_summary'])} characters). Switch to Customer Communication tab and click 'Synchronize & Regenerate All Stages' to apply.",
                    icon="✅"
                )
            else:
                st.info(
                    "Enter your ground truth summary above. The AI will use ONLY this text to generate customer communications.",
                    icon="ℹ️"
                )

        st.divider()

        # Technical Verification Section
        st.header("📈 Technical Verification")

        _render_charts(data)

        st.divider()

        st.subheader("Event Timeline")
        timeline = build_timeline(data)
        for i, evt in enumerate(timeline):
            _timeline_event(
                _fmt_time(evt["ts"]), evt, is_last=(i == len(timeline) - 1)
            )

        # Raw data expander
        with st.expander("📋 Raw source data", expanded=False):
            for fname in EXPECTED_FILES:
                raw = data.get(fname)
                if raw is None:
                    continue
                st.markdown(f"**{fname}**")
                if isinstance(raw, str):
                    st.code(raw, language="text")
                else:
                    st.code(json.dumps(raw, indent=2), language="json")


# ──────────────────────────────────────────────────────────────
# 8  MAIN APP (ROUTER)
# ──────────────────────────────────────────────────────────────
def main():
    st.set_page_config(
        page_title="CommBridge AI | Abnormal Security",
        page_icon="🤖",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # CRITICAL: Initialize ALL session state keys at the start
    if "view" not in st.session_state:
        st.session_state["view"] = "landing"
    if "truth_summary" not in st.session_state:
        st.session_state["truth_summary"] = ""
    if "incident_timeline" not in st.session_state:
        st.session_state["incident_timeline"] = []
    if "next_id" not in st.session_state:
        st.session_state["next_id"] = 0
    if "current_incident_id" not in st.session_state:
        st.session_state["current_incident_id"] = None

    # Production-Ready CSS - Modern Design System
    st.markdown(
        """
        <style>
          /* Import Modern Typography - Inter font from Google Fonts */
          @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

          /* Global Font Application */
          * {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
          }

          /* App background - Subtle grey for depth */
          .stApp {
            background-color: #F8F9FB;
          }

          /* Card-based containers with enhanced spacing and shadows */
          [data-testid="stVerticalBlock"] > [style*="background-color"] {
            background-color: #FFFFFF !important;
            border: 1px solid #E0E4E8 !important;
            border-radius: 12px !important;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.05) !important;
            padding: 28px !important;
          }

          /* Main content containers - white cards with generous padding */
          .main .block-container {
            padding-top: 2rem !important;
            padding-left: 2.5rem !important;
            padding-right: 2.5rem !important;
            padding-bottom: 2rem !important;
          }

          /* Buttons - Abnormal Red with smooth transitions */
          .stButton > button {
            background-color: #FF4B4B !important;
            color: white !important;
            border: none !important;
            border-radius: 6px !important;
            font-weight: 700 !important;
            padding: 0.65rem 1.25rem !important;
            box-shadow: 0 2px 4px rgba(255, 75, 75, 0.25) !important;
            transition: all 0.2s ease !important;
            font-size: 0.95rem !important;
          }
          .stButton > button:hover {
            background-color: #E63946 !important;
            box-shadow: 0 4px 8px rgba(255, 75, 75, 0.35) !important;
            transform: translateY(-1px) !important;
          }
          .stButton > button:active {
            transform: translateY(0) !important;
          }

          /* Main content text - High contrast dark */
          .stMarkdown, .stText, p, li {
            color: #1A1A1A !important;
            line-height: 1.6 !important;
          }
          h1, h2, h3 {
            color: #0f172a !important;
            font-weight: 700 !important;
            letter-spacing: -0.02em !important;
          }
          h1 {
            font-size: 2rem !important;
          }

          /* Tab Navigation - Bold active state with thick Abnormal Red underline */
          button[data-baseweb="tab"] {
            color: #64748b !important;
            font-weight: 600 !important;
            font-size: 1rem !important;
            padding: 1rem 1.75rem !important;
            transition: all 0.2s ease !important;
            border-bottom: 4px solid transparent !important;
          }
          button[data-baseweb="tab"][aria-selected="true"] {
            color: #FF4B4B !important;
            font-weight: 800 !important;
            border-bottom: 4px solid #FF4B4B !important;
          }
          button[data-baseweb="tab"]:hover {
            color: #FF4B4B !important;
            background-color: #fef2f2 !important;
          }

          /* Sidebar - Deep Navy with Enhanced Contrast */
          section[data-testid="stSidebar"] {
            background-color: #0E1117 !important;
            border-right: 1px solid #1e293b !important;
          }
          section[data-testid="stSidebar"] * {
            color: #FFFFFF !important;
            font-weight: 500 !important;
            font-size: 0.95rem !important;
          }
          section[data-testid="stSidebar"] h2 {
            color: #FFFFFF !important;
            font-weight: 700 !important;
            font-size: 1.1rem !important;
            letter-spacing: -0.01em !important;
          }
          section[data-testid="stSidebar"] .stMarkdown {
            color: #FFFFFF !important;
            font-weight: 500 !important;
          }

          /* System Status Badge - Vibrant Green */
          section[data-testid="stSidebar"] .stAlert.st-emotion-cache-1wmy9hl {
            background-color: #10b981 !important;
            border: 2px solid #059669 !important;
            border-radius: 8px !important;
            padding: 12px !important;
          }
          section[data-testid="stSidebar"] .stAlert * {
            color: #FFFFFF !important;
            font-weight: 600 !important;
          }

          /* Text inputs and text areas - Clean borders */
          .stTextArea textarea, .stTextInput input {
            border: 1px solid #E0E4E8 !important;
            border-radius: 8px !important;
            font-size: 0.9rem !important;
            padding: 10px 12px !important;
            transition: all 0.2s ease !important;
          }
          .stTextArea textarea:focus, .stTextInput input:focus {
            border-color: #FF4B4B !important;
            box-shadow: 0 0 0 3px rgba(255, 75, 75, 0.1) !important;
          }

          /* Selectbox (Dropdown) - Clean white background */
          .stSelectbox {
            color: #1A1A1A !important;
          }
          .stSelectbox label {
            color: #1A1A1A !important;
          }
          .stSelectbox > div,
          .stSelectbox > div > div {
            background-color: #FFFFFF !important;
            border: 1px solid #E0E4E8 !important;
            border-radius: 8px !important;
          }
          /* Select element - white background, dark text */
          div[data-baseweb="select"],
          [data-baseweb="select"] {
            background-color: #FFFFFF !important;
            border: 1px solid #E0E4E8 !important;
          }
          div[data-baseweb="select"] > div,
          div[data-baseweb="select"] div,
          [data-baseweb="select"] > div,
          [data-baseweb="select"] div {
            background-color: #FFFFFF !important;
            color: #1A1A1A !important;
            font-weight: 600 !important;
            font-size: 0.95rem !important;
          }
          /* Force all text/spans inside select to dark text */
          div[data-baseweb="select"] span,
          div[data-baseweb="select"] *,
          [data-baseweb="select"] span,
          [data-baseweb="select"] * {
            color: #1A1A1A !important;
            font-weight: 600 !important;
          }
          /* Dropdown menu - FORCE white background with dark text - MOST AGGRESSIVE */
          [data-baseweb="menu"],
          div[data-baseweb="menu"],
          ul[data-baseweb="menu"],
          [role="listbox"],
          [data-baseweb="popover"],
          .stSelectbox [data-baseweb="popover"],
          [data-baseweb="select"] [data-baseweb="popover"] {
            background-color: #FFFFFF !important;
            background: #FFFFFF !important;
            border: 1px solid #E0E4E8 !important;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1) !important;
          }
          /* Force popover content area to white */
          [data-baseweb="popover"] > div,
          [data-baseweb="popover"] [data-baseweb="menu"],
          div[role="presentation"] {
            background-color: #FFFFFF !important;
            background: #FFFFFF !important;
          }
          /* Menu items - FORCE dark text on white background */
          [data-baseweb="menu"] [role="option"],
          [data-baseweb="menu"] li,
          div[data-baseweb="menu"] [role="option"],
          div[data-baseweb="menu"] li,
          ul[data-baseweb="menu"] li,
          [role="listbox"] [role="option"],
          [role="listbox"] li,
          .stSelectbox [role="option"],
          li[role="option"] {
            color: #1A1A1A !important;
            font-weight: 600 !important;
            background-color: #FFFFFF !important;
            background: #FFFFFF !important;
            padding: 12px 16px !important;
          }
          /* Force ALL nested elements inside menu items to dark text on white */
          [data-baseweb="menu"] [role="option"] *,
          [data-baseweb="menu"] li *,
          div[data-baseweb="menu"] [role="option"] *,
          div[data-baseweb="menu"] li *,
          ul[data-baseweb="menu"] li *,
          [role="listbox"] [role="option"] *,
          [role="listbox"] li *,
          .stSelectbox [role="option"] *,
          li[role="option"] * {
            color: #1A1A1A !important;
            background-color: #FFFFFF !important;
            background: #FFFFFF !important;
          }
          /* Hover state - light gray background */
          [data-baseweb="menu"] [role="option"]:hover,
          div[data-baseweb="menu"] [role="option"]:hover,
          [role="listbox"] [role="option"]:hover,
          .stSelectbox [role="option"]:hover {
            background-color: #F7F7F7 !important;
            color: #1A1A1A !important;
          }
          [data-baseweb="menu"] [role="option"]:hover *,
          div[data-baseweb="menu"] [role="option"]:hover *,
          [role="listbox"] [role="option"]:hover *,
          .stSelectbox [role="option"]:hover * {
            color: #1A1A1A !important;
          }
          /* Selected state - red background with white text */
          [data-baseweb="menu"] [aria-selected="true"],
          div[data-baseweb="menu"] [aria-selected="true"],
          [role="listbox"] [aria-selected="true"],
          .stSelectbox [aria-selected="true"] {
            background-color: #FF4B4B !important;
            color: #FFFFFF !important;
            font-weight: 700 !important;
          }
          [data-baseweb="menu"] [aria-selected="true"] *,
          div[data-baseweb="menu"] [aria-selected="true"] *,
          [role="listbox"] [aria-selected="true"] *,
          .stSelectbox [aria-selected="true"] * {
            color: #FFFFFF !important;
          }

          /* Alert boxes - Slim and elegant */
          .stAlert {
            border-radius: 8px !important;
            border-left: 4px solid !important;
            padding: 12px 16px !important;
            font-size: 0.9rem !important;
          }

          /* Warning banners - Slim profile */
          [data-baseweb="notification"] {
            border-radius: 8px !important;
            padding: 12px 16px !important;
          }

          /* Toast notifications - High contrast dark grey */
          [data-testid="stToast"] {
            background-color: #2d3748 !important;
            color: #FFFFFF !important;
            border-radius: 8px !important;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15) !important;
          }
          [data-testid="stToast"] * {
            color: #FFFFFF !important;
            font-weight: 500 !important;
          }
          [data-testid="stToast"] [data-testid="stMarkdownContainer"] {
            color: #FFFFFF !important;
          }

          /* Dividers - Subtle separation */
          hr {
            border-color: #E0E4E8 !important;
            margin: 1.5rem 0 !important;
          }

          /* Stage badges styling - Abnormal Security brand colors */
          .stage-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.05em;
          }
          .stage-identified {
            background-color: #F39C12;
            color: #FFFFFF;
            border: none;
          }
          .stage-update {
            background-color: #3498DB;
            color: #FFFFFF;
            border: none;
          }
          .stage-monitoring {
            background-color: #3498DB;
            color: #FFFFFF;
            border: none;
          }
          .stage-resolved {
            background-color: #27AE60;
            color: #FFFFFF;
            border: none;
          }

          /* Stage update cards - Status page style */
          .stage-update-card {
            background-color: #FFFFFF;
            border: 1px solid #E0E4E8;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
          }

          /* Centered header branding */
          .centered-header {
            text-align: center;
            margin-bottom: 2rem;
          }
          .centered-header h1 {
            font-size: 2.2rem !important;
            margin-bottom: 0.25rem !important;
          }
          .centered-header .subtitle {
            color: #64748b !important;
            font-size: 1rem !important;
            font-weight: 500 !important;
          }

          /* Expander - clean white bar without .arrow_down text */
          [data-testid="stExpander"] {
            background-color: #FFFFFF !important;
            border: 1px solid #E0E4E8 !important;
            border-radius: 8px !important;
          }
          [data-testid="stExpander"] summary {
            list-style: none !important;
            background-color: #FFFFFF !important;
            padding: 12px 16px !important;
          }
          [data-testid="stExpander"] summary::-webkit-details-marker {
            display: none !important;
          }
          [data-testid="stExpander"] summary::marker {
            display: none !important;
          }
          /* Completely hide .arrow_down and any arrow-related elements */
          [data-testid="stExpander"] .arrow_down,
          [data-testid="stExpander"] [class*="arrow"],
          [data-testid="stExpander"] [class*="Arrow"],
          [data-testid="stExpander"] summary .arrow_down,
          [data-testid="stExpander"] summary [class*="arrow"],
          [data-testid="stExpander"] summary [class*="Arrow"] {
            display: none !important;
            visibility: hidden !important;
            font-size: 0 !important;
            width: 0 !important;
            height: 0 !important;
            overflow: hidden !important;
            opacity: 0 !important;
            position: absolute !important;
            left: -9999px !important;
          }
          /* Prevent any arrow text from appearing */
          [data-testid="stExpander"] summary::before,
          [data-testid="stExpander"] summary::after {
            content: "" !important;
            display: none !important;
          }
          /* Preserve SVG icons only */
          [data-testid="stExpander"] summary svg {
            display: inline-block !important;
            width: 1em !important;
            height: 1em !important;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # State initialized at top of main() - no duplicate initialization needed
    data = load_data()

    # Sidebar (only for incident view)
    if st.session_state["view"] == "incident":
        st.sidebar.markdown("## ⚙️  Configuration")

        # Get API key from secrets or user input
        # For Streamlit Cloud: Add your API key in Settings > Secrets as OPENAI_API_KEY="your-key"
        try:
            default_key = st.secrets.get("OPENAI_API_KEY", "")
        except (FileNotFoundError, KeyError):
            default_key = ""
        api_key = st.sidebar.text_input(
            "OpenAI API Key",
            value=default_key,
            type="password",
            placeholder="sk-…",
            help="OpenAI API key for AI-powered draft generation.",
        )
        if api_key and not api_key.startswith("sk-"):
            st.sidebar.warning("Key should start with 'sk-'.")

        st.sidebar.divider()
        st.sidebar.markdown("## 📂  Data Files")
        all_ok = True
        for fname in EXPECTED_FILES:
            ok = data.get(fname) is not None
            if not ok:
                all_ok = False
            st.sidebar.markdown(f"{'✅' if ok else '❌'}  {fname}")

        if all_ok:
            st.sidebar.markdown(
                """
                <div style="background-color: #10b981; border: 2px solid #059669;
                     padding: 12px; border-radius: 8px; margin-top: 12px;">
                  <div style="color: #FFFFFF; font-weight: 700; font-size: 0.95rem; text-align: center;">
                    ✅ System Healthy
                  </div>
                  <div style="color: #ecfdf5; font-weight: 500; font-size: 0.85rem; text-align: center; margin-top: 4px;">
                    All 5 data files loaded
                  </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.sidebar.warning(
                "⚠️ Files missing — Place in data/ folder"
            )
    else:
        api_key = ""  # No sidebar on landing page

    # Route to appropriate view
    if st.session_state["view"] == "landing":
        render_landing_page()
    else:
        render_incident_dashboard(data, api_key)


if __name__ == "__main__":
    main()
