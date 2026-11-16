#!/usr/bin/env python3
"""Regenerate monitoring/grafana/dashboards/claude-code-ops.json (the dashboard is generated, not hand-edited).

    python monitoring/tools/build_dashboard.py [output.json]

Design notes (learned the hard way):
- Time-series panels use the API's long shape (time, series, value) + typed Infinity `columns` + format `timeseries`;
  a `convertFieldType` transformation left the time column untyped ("Data is missing a time field").
- Tables with timestamps declare the time columns as `timestamp_epoch` for the same reason.
- Dashboard variable `session` (textbox) is passed to every query except the Sessions table itself; clicking a short id
  in the Sessions table sets it, which scopes the whole dashboard to that session.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(HERE), "grafana", "dashboards", "claude-code-ops.json")
DS = {"type": "yesoreyeram-infinity-datasource", "uid": "logs-api"}


def target(ep, scoped=True, **params):
    ps = [{"key": "from", "value": "${__from:date:iso}"}, {"key": "to", "value": "${__to:date:iso}"}]
    if scoped:
        ps.append({"key": "session", "value": "${session}"})
    ps += [{"key": k, "value": v} for k, v in params.items()]
    return [{"refId": "A", "datasource": DS, "type": "json", "source": "url", "format": "table", "parser": "backend",
             "url": f"/api/{ep}", "root_selector": "", "columns": [],
             "url_options": {"method": "GET", "data": "", "params": ps}}]


pid = [0]


def panel(kind, title, x, y, w, h, tg, **kw):
    pid[0] += 1
    p = {"id": pid[0], "type": kind, "title": title, "datasource": DS, "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "targets": tg, "fieldConfig": {"defaults": kw.pop("defaults", {}), "overrides": kw.pop("overrides", [])},
         "options": kw.pop("options", {})}
    p.update(kw)
    return p


def stat(title, field, x, unit="short", thresholds=None):
    d = {"unit": unit}
    if thresholds:
        d["thresholds"] = {"mode": "absolute", "steps": thresholds}
        d["color"] = {"mode": "thresholds"}
    return panel("stat", title, x, 0, 4, 4, target("stats"), defaults=d,
                 options={"reduceOptions": {"calcs": ["lastNotNull"], "fields": f"/^{field}$/", "values": False},
                          "colorMode": "value", "graphMode": "none"})


LONG_COLS = [{"selector": "time", "text": "time", "type": "timestamp_epoch"},
             {"selector": "series", "text": "series", "type": "string"},
             {"selector": "value", "text": "value", "type": "number"}]


def ts(title, x, y, w, ep, bars=False, unit="short", **params):
    # long-format API rows + typed columns + Infinity "timeseries" format => one typed series per label
    tg = target(ep, shape="long", **params)
    tg[0].update({"format": "timeseries", "columns": LONG_COLS})
    d = {"unit": unit, "displayName": "${__field.labels.series}",
         "custom": {"drawStyle": "bars" if bars else "line", "fillOpacity": 40 if bars else 10,
                    "lineWidth": 1, "stacking": {"mode": "normal" if bars else "none"}}}
    return panel("timeseries", title, x, y, w, 8, tg, defaults=d,
                 options={"legend": {"displayMode": "table", "placement": "bottom", "calcs": ["sum"]},
                          "tooltip": {"mode": "multi"}})


def table(title, x, y, w, h, ep, columns=None, overrides=None, scoped=True):
    tg = target(ep, scoped=scoped)
    if columns:  # [(name, type)] -> typed columns (timestamp_epoch gives a real time field)
        tg[0]["columns"] = [{"selector": n, "text": n, "type": t} for n, t in columns]
    tr = []
    if columns:  # the backend returns typed columns alphabetically; restore the declared order
        tr = [{"id": "organize", "options": {"indexByName": {n: i for i, (n, _) in enumerate(columns)}}}]
    return panel("table", title, x, y, w, h, tg, overrides=overrides or [], transformations=tr,
                 options={"showHeader": True, "cellHeight": "sm"}, defaults={"custom": {"filterable": True}})


red = [{"color": "green", "value": None}, {"color": "orange", "value": 5}, {"color": "red", "value": 20}]
errs = [{"color": "green", "value": None}, {"color": "red", "value": 1}]
lowgood = [{"color": "red", "value": None}, {"color": "orange", "value": 50}, {"color": "green", "value": 80}]
pctcol = lambda f: {"matcher": {"id": "byName", "options": f}, "properties": [{"id": "unit", "value": "percent"}]}  # noqa: E731

SESSION_COLS = [("short", "string"), ("started", "timestamp_epoch"), ("last_seen", "timestamp_epoch"),
                ("duration_min", "number"), ("title", "string"), ("cases", "string"), ("models", "string"),
                ("api_calls", "number"), ("output_tokens", "number"), ("tool_calls", "number"),
                ("tool_failures", "number")]
SESSION_LINK = {"matcher": {"id": "byName", "options": "short"}, "properties": [
    {"id": "links", "value": [{"title": "Filter the whole dashboard to this session", "targetBlank": False,
                               "url": "/d/claude-code-ops?var-session=${__data.fields.short}&${__url_time_range}"}]},
    {"id": "custom.width", "value": 90}]}
TITLE_W = {"matcher": {"id": "byName", "options": "title"}, "properties": [{"id": "custom.width", "value": 300}]}

panels = [
    stat("API calls", "api_calls", 0), stat("Output tokens", "output_tokens", 4),
    stat("Cache hit", "cache_hit_pct", 8, "percent", lowgood), stat("Tool calls", "tool_calls", 12),
    stat("Tool failure rate", "tool_failure_pct", 16, "percent", red), stat("Network errors", "network_errors", 20, "short", errs),
    table("Sessions - click an ID to filter the whole dashboard (clear the 'session' box above to reset)", 0, 4, 24, 8,
          "sessions", columns=SESSION_COLS, overrides=[SESSION_LINK, TITLE_W], scoped=False),
    ts("Output tokens by model", 0, 12, 12, "tokens", metric="output", group="model"),
    ts("Context tokens (input + cache) by source", 12, 12, 12, "tokens", metric="context", group="source"),
    ts("Tool calls by tool", 0, 20, 12, "tools_ts", bars=True, metric="calls"),
    ts("Tool failures by tool", 12, 20, 12, "tools_ts", bars=True, metric="failures"),
    table("Tool summary (frequency, failures, latency, result size)", 0, 28, 14, 9, "tool_summary", overrides=[pctcol("failure_pct")]),
    table("Network destinations (scripts -> intel services)", 14, 28, 10, 9, "network", overrides=[pctcol("error_pct")]),
    ts("Outbound calls by host", 0, 37, 12, "network_ts", bars=True),
    table("Passive guard decisions", 12, 37, 6, 8, "guard"),
    table("Sessions & subagents", 18, 37, 6, 8, "agents"),
    table("Recent errors", 0, 45, 24, 9, "errors",
          columns=[("time", "timestamp_epoch"), ("kind", "string"), ("tool", "string"), ("source", "string"), ("text", "string")]),
]
SESSION_VAR = {"type": "textbox", "name": "session", "label": "Session (id or prefix; empty = all)",
               "query": "", "current": {"text": "", "value": ""}, "options": [{"selected": True, "text": "", "value": ""}],
               "hide": 0}
dash = {"uid": "claude-code-ops", "title": "Claude Code - usage & tool ops", "tags": ["claude-code", "telemetry"],
        "timezone": "browser", "refresh": "30s", "schemaVersion": 39, "version": 1, "editable": True,
        "time": {"from": "now-24h", "to": "now"}, "panels": panels, "templating": {"list": [SESSION_VAR]},
        "annotations": {"list": []}}
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(dash, fh, indent=2)
print("wrote", OUT)
