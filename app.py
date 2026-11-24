import json
import sqlite3
from pathlib import Path
from collections import Counter

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "threat_intel.db"

st.set_page_config(
    page_title="Threat Intel | Security Operations",
    page_icon="Γùê",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Theme ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
:root { --bg:#080d12; --panel:#101820; --panel2:#131e27; --line:#22313b;
        --muted:#82939d; --text:#e8f0f2; --teal:#20d6bd; --cyan:#45b9e8; }
html, body, [class*="css"] { font-family:Inter, sans-serif; }
.stApp { background: radial-gradient(ellipse at 50% -20%, #142831 0%, #080d12 52%); color:var(--text); }
header[data-testid="stHeader"] { background:transparent; }
.block-container { padding-top:1.4rem; padding-bottom:2.5rem; max-width:1600px; }
section[data-testid="stSidebar"] { background:#0b1218; border-right:1px solid #1c2b34; }
section[data-testid="stSidebar"] .block-container { padding-top:1.5rem; }
h1,h2,h3 { color:#edf5f6 !important; letter-spacing:-.035em; }
p, label, .stMarkdown { color:#c5d1d5; }
div[data-testid="stMetric"] { background:linear-gradient(145deg,#14212a,#101820);
  border:1px solid #263943; border-radius:14px; padding:17px 18px; }
div[data-testid="stMetricLabel"] { color:#8fa3ab; }
div[data-testid="stMetricValue"] { color:#effafa; font-weight:700; }
div[data-testid="stMetricDelta"] { color:#20d6bd; }
.panel { background:linear-gradient(145deg,rgba(20,31,40,.96),rgba(13,21,28,.96));
  border:1px solid #23343e; border-radius:15px; padding:18px 20px; margin-bottom:14px; }
.eyebrow { color:#20d6bd; text-transform:uppercase; font-size:10px; letter-spacing:.16em; font-weight:800; }
.subtle { color:#82939d; font-size:12px; }
.status { display:inline-block; padding:5px 10px; border-radius:99px; font-size:11px;
  font-weight:700; background:#15372f; color:#54e2bf; border:1px solid #226454; }
.warning { background:#392c18; color:#f2c66d; border:1px solid #73552a; }
div[data-testid="stDataFrame"] { border:1px solid #263943; border-radius:12px; overflow:hidden; }
.stButton>button { border-radius:9px; border:1px solid #2a4850; background:#12252b; color:#c8f7ed; }
.stButton>button:hover { border-color:#20d6bd; color:white; }
div[role="radiogroup"] label { background:#101a22; padding:9px 12px; border-radius:9px; margin:3px; }
hr { border-color:#23343e; }
[data-testid="stPlotlyChart"] { background:transparent; }
</style>
""", unsafe_allow_html=True)

COLORS = {"Critical":"#ff5364","High":"#ff9d4d","Medium":"#f2d35e","Low":"#20d6bd"}
PLOT = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#c5d1d5", family="Inter"), margin=dict(l=10,r=10,t=35,b=10))

def load_json(rel, default=None):
    p = ROOT / rel
    if not p.exists():
        return default if default is not None else []
    try:
        with p.open(encoding="utf-8-sig") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default if default is not None else []

def load_ioc_count():
    try:
        with sqlite3.connect(str(DB_PATH)) as con:
            return con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    except Exception:
        return 0

def records_frame(records):
    return pd.DataFrame(records) if records else pd.DataFrame()

def risk_counts(df):
    if df.empty or "risk_level" not in df:
        return pd.DataFrame({"Risk Level": [], "Count": []})
    order = ["Critical","High","Medium","Low"]
    counts = df["risk_level"].value_counts()
    return pd.DataFrame({"Risk Level":order, "Count":[int(counts.get(x,0)) for x in order]})

# All data sources are intentionally kept separate; synthetic validation is never
# presented as production/real detections.
DATASETS = {
    "Production ┬╖ official output": {
        "path":"results/detections.json", "scored":False,
        "note":"Official Week 2 output. The supplied project currently contains zero real IOC matches in this dataset.",
        "synthetic":False,
    },
    "PCAP Ganna ┬╖ scored case": {
        "path":"results/zeek-real-test/pcap_ganna/scored_detections.json", "scored":True,
        "note":"15 detections from the supplied PCAP Ganna test, scored and joined to Zeek connection evidence. All matched connections are S0.",
        "synthetic":False,
    },
    "Synthetic lab ┬╖ validation": {
        "path":"results/scored_synthetic_detections.json", "scored":True,
        "note":"Synthetic test data used to validate matching and scoring. Do not report these as real incidents.",
        "synthetic":True,
    },
    "MTA case ┬╖ case validation": {
        "path":"results/zeek-real-test/mta-2025-01-22/detections-case-validation.json", "scored":False,
        "note":"19 case-specific IOC matches retained for validation. Risk scoring is not included in this file.",
        "synthetic":False,
    },
}

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown("<div style='font-size:27px;font-weight:800;color:#eaf7f6'>Γùê SENTINEL<span style='color:#20d6bd'>.</span></div><div class='subtle'>THREAT INTELLIGENCE PLATFORM</div>", unsafe_allow_html=True)
    st.markdown("---")
    page = st.radio("WORKSPACE", ["Overview","Detection Alerts","IOC Inventory","MITRE Mapping","Risk Analysis","Wazuh Integration"], label_visibility="visible")
    st.markdown("---")
    st.markdown("<div class='eyebrow'>DATA CONTEXT</div>", unsafe_allow_html=True)
    dataset_name = st.selectbox("Detection dataset", list(DATASETS.keys()), index=1)
    cfg = DATASETS[dataset_name]
    detections = load_json(cfg["path"], [])
    df = records_frame(detections)
    if cfg["synthetic"]:
        st.markdown("<span class='status warning'>SYNTHETIC DATA</span>", unsafe_allow_html=True)
    else:
        st.markdown("<span class='status'>PROJECT DATA</span>", unsafe_allow_html=True)
    st.caption(cfg["note"])
    st.markdown("---")
    st.caption("Local / on-prem data view ┬╖ No external telemetry is sent")

ioc_count = load_ioc_count()
risk_df = df if "risk_level" in df.columns else pd.DataFrame()
critical = int((risk_df.get("risk_level", pd.Series(dtype=str)) == "Critical").sum()) if not risk_df.empty else 0
high = int((risk_df.get("risk_level", pd.Series(dtype=str)) == "High").sum()) if not risk_df.empty else 0

# ---------- Header ----------
left, right = st.columns([3,1])
with left:
    st.markdown("<div class='eyebrow'>SECURITY OPERATIONS CENTER / THREAT INTELLIGENCE</div>", unsafe_allow_html=True)
    st.title(page)
    st.caption("Unified visibility across IOC intelligence, network detections, risk prioritization and response integration.")
with right:
    st.markdown("<div style='text-align:right;padding-top:20px'><span class='status'>ΓùÅ LOCAL DATA</span><br><span class='subtle'>Threat Intel Driven Detection</span></div>", unsafe_allow_html=True)

if cfg["synthetic"]:
    st.warning("Synthetic validation dataset selected ΓÇö these events are for testing only, not real-world incidents.")
elif dataset_name.startswith("Production") and len(df) == 0:
    st.info("No real detections are present in the official output. This is consistent with the project README: the captured traffic and IOC feed cover different time periods.")

# ---------- Overview ----------
if page == "Overview":
    st.markdown("<div class='panel'><span class='eyebrow'>PLATFORM SNAPSHOT</span><br><span class='subtle'>Metrics are calculated from the selected detection dataset and the local IOC database.</span></div>", unsafe_allow_html=True)
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("IOC records", f"{ioc_count:,}", help="Rows stored in data/threat_intel.db")
    c2.metric("Detections", f"{len(df):,}")
    c3.metric("Critical risk", f"{critical:,}")
    c4.metric("High risk", f"{high:,}")
    c5.metric("MITRE confirmed", "0", help="The current mapping file confirms no ATT&CK techniques.")
    a,b = st.columns([1.1,1.45])
    with a:
        st.markdown("<div class='panel'><span class='eyebrow'>RISK DISTRIBUTION</span></div>", unsafe_allow_html=True)
        if "risk_level" in df and len(df):
            rc = risk_counts(df)
            fig = px.pie(rc, names="Risk Level", values="Count", hole=.68,
                         color="Risk Level", color_discrete_map=COLORS)
            fig.update_traces(textposition="inside", textinfo="percent+label", marker=dict(line=dict(color="#101820",width=3)))
            fig.update_layout(**PLOT, showlegend=False, height=300, annotations=[dict(text=str(len(df)),x=.5,y=.5,font_size=26,showarrow=False,font_color="#edf5f6")])
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.markdown("<div style='height:260px;display:grid;place-items:center;color:#82939d'>No scored detections in this dataset</div>", unsafe_allow_html=True)
    with b:
        st.markdown("<div class='panel'><span class='eyebrow'>DETECTION ACTIVITY</span></div>", unsafe_allow_html=True)
        if len(df) and "indicator_type" in df:
            typ = df["indicator_type"].fillna("unknown").value_counts().rename_axis("Type").reset_index(name="Count")
            fig = px.bar(typ, x="Type", y="Count", color="Type", color_discrete_sequence=["#20d6bd","#45b9e8","#ff9d4d","#9c8cff"])
            fig.update_layout(**PLOT, height=300, showlegend=False, xaxis_title="", yaxis_title="Detections")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.markdown("<div style='height:260px;display:grid;place-items:center;color:#82939d'>No detection activity to chart</div>", unsafe_allow_html=True)
    a,b = st.columns(2)
    with a:
        st.markdown("<div class='panel'><span class='eyebrow'>LATEST DETECTIONS</span></div>", unsafe_allow_html=True)
        if len(df):
            cols=[c for c in ["timestamp","indicator","indicator_type","risk_score","risk_level","source"] if c in df]
            st.dataframe(df[cols].head(7), use_container_width=True, hide_index=True)
        else: st.caption("No records available.")
    with b:
        st.markdown("<div class='panel'><span class='eyebrow'>INTELLIGENCE SOURCES</span></div>", unsafe_allow_html=True)
        if DB_PATH.exists():
            try:
                with sqlite3.connect(str(DB_PATH)) as con:
                    src=pd.read_sql_query("SELECT source, COUNT(*) AS records FROM iocs GROUP BY source ORDER BY records DESC",con)
                fig=px.bar(src,x="records",y="source",orientation="h",text="records",color_discrete_sequence=["#20d6bd"])
                fig.update_layout(**PLOT,height=260,xaxis_title="IOC records",yaxis_title="")
                st.plotly_chart(fig,use_container_width=True)
            except Exception: st.caption("Could not read IOC source breakdown.")
        else: st.caption("IOC database not found.")

# ---------- Detection Alerts ----------
elif page == "Detection Alerts":
    st.markdown("<div class='panel'><span class='eyebrow'>DETECTION EXPLORER</span><br><span class='subtle'>Filter and inspect IOC matches with their network evidence.</span></div>", unsafe_allow_html=True)
    if df.empty:
        st.success("No detections in the selected dataset.")
    else:
        f1,f2,f3=st.columns(3)
        types=sorted(df["indicator_type"].dropna().astype(str).unique()) if "indicator_type" in df else []
        levels=sorted(df["risk_level"].dropna().astype(str).unique()) if "risk_level" in df else []
        sources=sorted(df["source"].dropna().astype(str).unique()) if "source" in df else []
        with f1: selected_types=st.multiselect("Indicator type",types,default=types)
        with f2: selected_levels=st.multiselect("Risk level",levels,default=levels)
        with f3: selected_sources=st.multiselect("Threat source",sources,default=sources)
        filtered=df.copy()
        if "indicator_type" in filtered: filtered=filtered[filtered["indicator_type"].astype(str).isin(selected_types)]
        if "risk_level" in filtered and levels: filtered=filtered[filtered["risk_level"].astype(str).isin(selected_levels)]
        if "source" in filtered: filtered=filtered[filtered["source"].astype(str).isin(selected_sources)]
        search=st.text_input("Search indicator, IP, domain, UID or match ID",placeholder="e.g. evil-lab.test")
        if search:
            mask=filtered.astype(str).apply(lambda col: col.str.contains(search,case=False,na=False)).any(axis=1)
            filtered=filtered[mask]
        preferred=["timestamp","indicator","indicator_type","risk_score","risk_level","threat_type","match_type","src_ip","dst_ip","port","evidence_source","source","uid"]
        cols=[x for x in preferred if x in filtered.columns]
        st.caption(f"{len(filtered)} matching records")
        st.dataframe(filtered[cols],use_container_width=True,hide_index=True)
        if len(filtered):
            options=filtered.index.tolist()
            selected=st.selectbox("Inspect detection",options,format_func=lambda i: str(filtered.loc[i].get("indicator","Detection"))+" ┬╖ "+str(filtered.loc[i].get("match_id","")))
            rec=filtered.loc[selected].to_dict()
            st.markdown("<div class='panel'><span class='eyebrow'>DETECTION DETAILS</span></div>",unsafe_allow_html=True)
            x,y=st.columns(2)
            with x:
                for k in ["match_id","timestamp","indicator","ioc_value","indicator_type","threat_type","malware","confidence","source","ioc_first_seen"]:
                    if k in rec and pd.notna(rec[k]): st.write(f"**{k.replace('_',' ').title()}:** {rec[k]}")
            with y:
                for k in ["match_type","matched_field","evidence_source","src_ip","dst_ip","domain","port","protocol","uid","conn_state","orig_bytes","resp_bytes","risk_score","risk_level"]:
                    if k in rec and pd.notna(rec[k]): st.write(f"**{k.replace('_',' ').title()}:** {rec[k]}")
            if isinstance(rec.get("risk_score_details"),dict):
                st.markdown("**Risk score explanation**")
                st.write(rec["risk_score_details"].get("interpretation",""))
                for reason in rec["risk_score_details"].get("reasons",[]): st.write("ΓÇó "+reason)

# ---------- IOC Inventory ----------
elif page == "IOC Inventory":
    st.markdown("<div class='panel'><span class='eyebrow'>THREAT INTELLIGENCE STORE</span><br><span class='subtle'>Search the project's SQLite IOC database.</span></div>",unsafe_allow_html=True)
    if not DB_PATH.exists(): st.error("data/threat_intel.db was not found.")
    else:
        try:
            with sqlite3.connect(str(DB_PATH)) as con:
                counts=pd.read_sql_query("SELECT ioc_type, COUNT(*) AS count FROM iocs GROUP BY ioc_type ORDER BY count DESC",con)
                sources=pd.read_sql_query("SELECT source, COUNT(*) AS count FROM iocs GROUP BY source ORDER BY count DESC",con)
            a,b=st.columns(2)
            with a:
                st.markdown("**IOC types**")
                fig=px.pie(counts,names="ioc_type",values="count",hole=.65,color_discrete_sequence=["#20d6bd","#45b9e8","#ff9d4d","#9c8cff","#f2d35e"])
                fig.update_layout(**PLOT,height=280)
                st.plotly_chart(fig,use_container_width=True)
            with b:
                st.markdown("**Feed contribution**")
                fig=px.bar(sources,x="source",y="count",color_discrete_sequence=["#20d6bd"])
                fig.update_layout(**PLOT,height=280,xaxis_title="",yaxis_title="IOC records")
                st.plotly_chart(fig,use_container_width=True)
            term=st.text_input("Search IOC value",placeholder="Domain, IP, URL or hash")
            type_opts=["All"]+counts["ioc_type"].astype(str).tolist()
            selected_type=st.selectbox("IOC type",type_opts)
            query="SELECT ioc, ioc_type, source, threat_type, malware, confidence, first_seen, last_seen FROM iocs"
            params=[]; where=[]
            if term: where.append("ioc LIKE ?"); params.append("%"+term+"%")
            if selected_type!="All": where.append("ioc_type = ?"); params.append(selected_type)
            if where: query+=" WHERE "+" AND ".join(where)
            query+=" ORDER BY confidence DESC LIMIT 500"
            with sqlite3.connect(str(DB_PATH)) as con:
                result=pd.read_sql_query(query,con,params=params)
            st.caption(f"Showing {len(result)} records (maximum 500 per query)")
            st.dataframe(result,use_container_width=True,hide_index=True)
        except Exception as e: st.error(f"IOC database query failed: {e}")

# ---------- MITRE ----------
elif page == "MITRE Mapping":
    mapping=load_json("mitre/mapping.json",{})
    if not isinstance(mapping,dict): mapping={}
    summary=mapping.get("summary",{})
    a,b,c=st.columns(3)
    a.metric("Detections reviewed",summary.get("total_detections_reviewed",0))
    b.metric("Confirmed techniques",summary.get("confirmed_techniques",0))
    c.metric("Candidate techniques",summary.get("candidate_techniques",0))
    st.markdown("<div class='panel'><span class='eyebrow'>ATT&CK MAPPING POLICY</span><br><b>IOC match alone is insufficient evidence for a confirmed technique.</b><br><span class='subtle'>Only behavior supported by available telemetry may be mapped.</span></div>",unsafe_allow_html=True)
    confirmed=mapping.get("confirmed_mappings",[])
    if confirmed: st.json(confirmed)
    else: st.info("No MITRE ATT&CK techniques are confirmed in the current mapping file.")
    st.markdown("### Candidate techniques")
    candidates=mapping.get("candidate_techniques",[])
    if candidates:
        st.dataframe(pd.DataFrame(candidates),use_container_width=True,hide_index=True)
    reviewed=mapping.get("detections_reviewed",[])
    st.markdown("### Evidence review")
    if reviewed:
        for item in reviewed:
            with st.expander(f"{item.get('threat_type','Review')} ┬╖ {item.get('indicator','')} ┬╖ {item.get('mapping_status','')}"):
                st.write(item.get("reason",""))
                st.json(item)
    st.caption("Candidate techniques are hypotheses only; they are not presented as detected behavior.")

# ---------- Risk Analysis ----------
elif page == "Risk Analysis":
    st.markdown("<div class='panel'><span class='eyebrow'>EXPLAINABLE RISK ENGINE</span><br><span class='subtle'>Risk score is an investigation-priority signal, not proof of compromise.</span></div>",unsafe_allow_html=True)
    if "risk_score" not in df or df.empty:
        st.info("The selected dataset does not contain risk-scored detections. Choose the PCAP Ganna scored case or Synthetic lab validation to explore scoring.")
    else:
        a,b,c=st.columns(3)
        a.metric("Average score",f"{df['risk_score'].mean():.1f}")
        b.metric("Maximum score",int(df["risk_score"].max()))
        c.metric("Scored records",len(df))
        x,y=st.columns(2)
        with x:
            rc=risk_counts(df)
            fig=px.bar(rc,x="Risk Level",y="Count",color="Risk Level",color_discrete_map=COLORS)
            fig.update_layout(**PLOT,height=300,showlegend=False)
            st.plotly_chart(fig,use_container_width=True)
        with y:
            fig=px.histogram(df,x="risk_score",nbins=10,color_discrete_sequence=["#20d6bd"])
            fig.update_layout(**PLOT,height=300,xaxis_title="Risk score",yaxis_title="Detections")
            st.plotly_chart(fig,use_container_width=True)
        st.markdown("### Scoring model")
        st.write("Confidence, threat classification, match type and observed network evidence contribute to a normalized score (maximum raw score: 77).")
        with st.expander("View score components"):
            st.markdown("""
            | Factor | Points |
            |---|---:|
            | Confidence 90ΓÇô100 / 75ΓÇô89 / 50ΓÇô74 / 1ΓÇô49 | 30 / 24 / 16 / 8 |
            | payload_delivery / botnet_cc / malware / credential_theft / phishing | 12 / 10 / 10 / 10 / 8 |
            | EXACT_IP_PORT / URL_IP_PORT_MATCH / EXACT_DOMAIN / EXACT_IP / SUBDOMAIN | 20 / 18 / 15 / 14 / 12 |
            | DNS observation / connection with observed bytes | 5 / 15 |
            | S0 or no response | 0 |
            """)
        if "risk_score_details" in df:
            st.markdown("### Highest-priority detections")
            view=df.sort_values("risk_score",ascending=False)
            show=[c for c in ["indicator","risk_score","risk_level","threat_type","match_type","evidence_source","conn_state","orig_bytes","resp_bytes"] if c in view]
            st.dataframe(view[show],use_container_width=True,hide_index=True)

# ---------- Wazuh / unified SOC correlation ----------
elif page == "Wazuh Integration":
    st.markdown("<div class='panel'><span class='eyebrow'>SOC CORRELATION</span><br><b>IOC Matching ΓåÆ Risk Scoring ΓåÆ Wazuh Alerts ΓåÆ MITRE Evidence Review</b></div>", unsafe_allow_html=True)

    evidence_dir = ROOT / "wazuh" / "evidence" / "live_integration"
    alerts_path = evidence_dir / "ganna_pcap_wazuh_alerts.jsonl"
    enriched_path = evidence_dir / "ganna_mitre_enriched_alerts.json"
    mitre_path = ROOT / "mitre" / "mapping.json"

    st.caption("Offline evidence view. These are exported alerts from a Wazuh Manager test; this page does not query Ubuntu automatically.")
    if st.button("Reload local evidence", key="reload_soc_evidence"):
        st.rerun()

    def read_alerts_file(path):
        output = []
        errors = 0
        if not path.exists():
            return output, errors
        for lineno, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    output.append(record)
                else:
                    errors += 1
            except json.JSONDecodeError:
                errors += 1
        return output, errors

    alerts, parse_errors = read_alerts_file(alerts_path)
    enriched_report = load_json("wazuh/evidence/live_integration/ganna_mitre_enriched_alerts.json", {})
    mitre_mapping = load_json("mitre/mapping.json", {})
    if not isinstance(enriched_report, dict):
        enriched_report = {}
    if not isinstance(mitre_mapping, dict):
        mitre_mapping = {}

    reviews = {
        str(item.get("match_id")): item.get("mitre_review", {})
        for item in enriched_report.get("alerts", [])
        if isinstance(item, dict) and item.get("match_id")
    }
    rows = []
    for a in alerts:
        event = a.get("data") if isinstance(a.get("data"), dict) else {}
        rule = a.get("rule") if isinstance(a.get("rule"), dict) else {}
        match_id = str(event.get("match_id", ""))
        review = reviews.get(match_id, {})
        rows.append({
            "Match ID": match_id,
            "Wazuh Time": a.get("timestamp", ""),
            "Indicator": event.get("indicator", ""),
            "IOC Value": event.get("ioc_value", ""),
            "IOC Type": event.get("ioc_type", event.get("indicator_type", "")),
            "IOC Source": event.get("source", ""),
            "Confidence": event.get("confidence"),
            "Threat Type": event.get("threat_type", ""),
            "Match Type": event.get("match_type", ""),
            "Source IP": event.get("src_ip", ""),
            "Destination IP": event.get("dst_ip", ""),
            "Port": event.get("port"),
            "Connection State": event.get("conn_state", ""),
            "Risk Score": event.get("risk_score"),
            "Risk Level": event.get("risk_level", ""),
            "Rule ID": str(rule.get("id", "")),
            "Alert Level": rule.get("level"),
            "Rule Description": rule.get("description", ""),
            "MITRE Review": review.get("mapping_status", "not_reviewed"),
            "Confirmed MITRE IDs": ", ".join(map(str, review.get("confirmed_techniques", []))),
            "MITRE Reason": review.get("reason", ""),
        })
    soc_df = pd.DataFrame(rows)

    confirmed_ids = set()
    for item in reviews.values():
        if isinstance(item, dict):
            confirmed_ids.update(str(x) for x in item.get("confirmed_techniques", []))
    candidate_items = mitre_mapping.get("candidate_techniques", [])
    if not isinstance(candidate_items, list):
        candidate_items = []

    if alerts_path.exists():
        st.success(f"Loaded {len(alerts)} exported Wazuh alerts from local evidence.")
    else:
        st.warning(f"Missing Wazuh alerts evidence: {alerts_path}")
    if not enriched_path.exists():
        st.info("MITRE enrichment file not found. Per-alert MITRE reviews will show as not_reviewed.")
    if parse_errors:
        st.warning(f"Skipped {parse_errors} invalid JSONL records.")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Wazuh Alerts", len(alerts))
    m2.metric("Unique IOC Matches", soc_df["Match ID"].nunique() if not soc_df.empty else 0)
    m3.metric("High Risk", int((soc_df["Risk Level"] == "High").sum()) if not soc_df.empty else 0)
    m4.metric("MITRE Reviews", int((soc_df["MITRE Review"] != "not_reviewed").sum()) if not soc_df.empty else 0)
    m5.metric("Confirmed MITRE IDs", len(confirmed_ids))

    st.markdown("### Wazuh Alerts + IOC Correlation")
    if soc_df.empty:
        st.info("No exported alerts to display. Copy the evidence files into wazuh/evidence/live_integration/.")
    else:
        f1, f2, f3 = st.columns(3)
        with f1:
            rules = sorted(soc_df["Rule ID"].dropna().astype(str).unique().tolist())
            selected_rules = st.multiselect("Wazuh rule", rules, default=rules)
        with f2:
            risks = sorted(soc_df["Risk Level"].dropna().astype(str).unique().tolist())
            selected_risks = st.multiselect("Risk level", risks, default=risks)
        with f3:
            statuses = sorted(soc_df["MITRE Review"].dropna().astype(str).unique().tolist())
            selected_statuses = st.multiselect("MITRE review", statuses, default=statuses)
        search = st.text_input("Find IOC / IP / match ID / threat", key="soc_search")
        visible = soc_df[
            soc_df["Rule ID"].isin(selected_rules)
            & soc_df["Risk Level"].isin(selected_risks)
            & soc_df["MITRE Review"].isin(selected_statuses)
        ].copy()
        if search:
            visible = visible[visible.astype(str).apply(lambda col: col.str.contains(search, case=False, regex=False, na=False)).any(axis=1)]
        st.caption(f"Showing {len(visible)} of {len(soc_df)} exported Wazuh alerts")
        primary = ["Wazuh Time", "Match ID", "Indicator", "IOC Source", "Threat Type", "Risk Score", "Risk Level", "Rule ID", "Alert Level", "MITRE Review"]
        st.dataframe(visible[primary], use_container_width=True, hide_index=True)
        st.download_button("Export filtered alerts (CSV)", data=visible.to_csv(index=False).encode("utf-8-sig"), file_name="wazuh_ioc_mitre_filtered.csv", mime="text/csv")

        l, r = st.columns(2)
        with l:
            counts = soc_df["Rule ID"].value_counts().rename_axis("Rule ID").reset_index(name="Alerts")
            st.plotly_chart(px.bar(counts, x="Rule ID", y="Alerts", title="Alerts by custom Wazuh rule"), use_container_width=True)
        with r:
            risk_counts_chart = soc_df["Risk Level"].value_counts().rename_axis("Risk Level").reset_index(name="Alerts")
            st.plotly_chart(px.pie(risk_counts_chart, names="Risk Level", values="Alerts", title="Alert risk distribution", color="Risk Level", color_discrete_map=COLORS), use_container_width=True)

        st.markdown("### Alert Details / Investigation")
        choices = visible.index.tolist()
        if choices:
            selected = st.selectbox("Select a Wazuh alert", choices, format_func=lambda i: f"{soc_df.loc[i, 'Match ID']} | {soc_df.loc[i, 'Indicator']} | Rule {soc_df.loc[i, 'Rule ID']}")
            original = alerts[int(selected)]
            data = original.get("data", {})
            row = soc_df.loc[selected]
            left, right = st.columns(2)
            with left:
                st.markdown("**IOC & network evidence**")
                st.json({k: data.get(k) for k in ("match_id", "indicator", "ioc_value", "indicator_type", "source", "confidence", "threat_type", "match_type", "src_ip", "dst_ip", "port", "conn_state", "orig_bytes", "resp_bytes")})
            with right:
                st.markdown("**Wazuh rule & scoring**")
                st.json({"rule": original.get("rule", {}), "risk_score": data.get("risk_score"), "risk_level": data.get("risk_level"), "risk_score_details": data.get("risk_score_details", {})})
            st.markdown("**MITRE evidence review for this alert**")
            st.write(f"Status: **{row['MITRE Review']}**")
            st.write(row["MITRE Reason"] or "No per-alert review loaded.")
            if row["Confirmed MITRE IDs"]:
                st.write("Confirmed technique IDs:", row["Confirmed MITRE IDs"])
            else:
                st.caption("No confirmed ATT&CK technique attributed to this alert.")

    st.markdown("### MITRE ATT&CK ΓÇö Evidence-aware Mapping")
    st.warning("Candidate techniques are investigation hypotheses, NOT confirmed detections. The reviewed S0 traffic has no observed response or transferred bytes.")
    s1, s2, s3 = st.columns(3)
    summary = mitre_mapping.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    s1.metric("Reviewed detections (mapping file)", summary.get("total_detections_reviewed", 0))
    s2.metric("Candidate techniques", len(candidate_items))
    s3.metric("Confirmed techniques", summary.get("confirmed_techniques", 0))
    if candidate_items:
        st.markdown("**Candidates needing additional evidence (global, not assigned to individual alerts)**")
        st.dataframe(pd.DataFrame(candidate_items), use_container_width=True, hide_index=True)
    reviewed_groups = mitre_mapping.get("detections_reviewed", [])
    if reviewed_groups:
        with st.expander("MITRE reviewed traffic groups and evidence reasons"):
            st.dataframe(pd.DataFrame(reviewed_groups), use_container_width=True, hide_index=True)

    st.markdown("### IOC Inventory ΓÇö SQLite Backend")
    if DB_PATH.exists():
        try:
            with sqlite3.connect(str(DB_PATH)) as con:
                total_iocs = con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
                source_counts = pd.read_sql_query("SELECT source, COUNT(*) AS count FROM iocs GROUP BY source ORDER BY count DESC", con)
            st.metric("Total IOC records in SQLite", int(total_iocs))
            st.dataframe(source_counts, use_container_width=True, hide_index=True)
            st.caption("For full IOC search by type/value, use the IOC Inventory page. This is the local project database, not a live threat feed.")
        except Exception as exc:
            st.error(f"Unable to query IOC database: {exc}")
    else:
        st.info("IOC database not found: data/threat_intel.db")

    st.markdown("### Integration evidence & configuration")
    manager_status = ROOT / "wazuh" / "evidence" / "manager_status.txt"
    if manager_status.exists():
        with st.expander("Wazuh Manager status (saved snapshot)"):
            st.code(manager_status.read_text(encoding="utf-8", errors="replace")[:4000])
    archived_path = ROOT / "wazuh" / "evidence" / "received_events.jsonl"
    st.caption(f"Archived synthetic test lines (saved snapshot): {sum(bool(x.strip()) for x in archived_path.read_text(encoding='utf-8', errors='replace').splitlines()) if archived_path.exists() else 'not available'}")
    for title, rel in [("Log collector snippet", "wazuh/config/localfile_snippet.xml"), ("Archives snippet", "wazuh/config/archives_snippet.xml"), ("Custom rules", "wazuh/rules/local_rules.xml")]:
        with st.expander(title):
            p = ROOT / rel
            if p.exists():
                st.code(p.read_text(encoding="utf-8", errors="replace"), language="xml")
            else:
                st.caption(f"File not found: {rel}")

st.markdown("---")
st.markdown("<div style='display:flex;justify-content:space-between;color:#71838c;font-size:11px'><span>Γùê SENTINEL ┬╖ THREAT INTEL DRIVEN DETECTION PLATFORM</span><span>LOCAL PROJECT DATA ┬╖ INVESTIGATION PRIORITY Γëá PROOF OF COMPROMISE</span></div>",unsafe_allow_html=True)
