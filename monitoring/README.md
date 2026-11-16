# Claude Code ops dashboard (Grafana)

Self-contained: nothing here imports or depends on the CTI investigation code. It only **reads** the
`*.jsonl` files in a log directory (default `../logs`, written by the telemetry hook) and serves them to Grafana.

```
logs/*.jsonl  --(read-only mount)-->  log-api (monitoring/log_api.py)  <--HTTP, on every panel refresh--  Grafana
```

There is no loader process or database: each time Grafana queries a panel (page load, time-range change,
the 30 s auto-refresh) `log_api.py` re-reads the logs (re-parsing only files that changed).

## Run

```powershell
docker compose -f monitoring/docker-compose.yml up -d
```

Open http://localhost:3000 (login `admin` / `admin`, or set `GRAFANA_ADMIN_PASSWORD` before first start).
The dashboard **Claude Code - usage & tool ops** and the Infinity datasource are provisioned automatically
(first start installs the `yesoreyeram-infinity-datasource` plugin, so it needs internet once).
The plugin is **pinned to 3.7.1** to match the Grafana 11.3.0 image: Infinity 4.x needs Grafana >= 11.6 and fails with
`404 loading react/jsx-runtime`. If you bump the Grafana image to >= 11.6.11, you can drop the pin. To change either,
recreate the stack: `docker compose -f monitoring/docker-compose.yml down -v` then `up -d`.
Both ports bind to 127.0.0.1 only. To point at another log folder: `$env:LOG_DIR="D:\other\logs"` before `up`.

Without Docker, the API alone: `python monitoring/log_api.py --port 8765` then `curl http://127.0.0.1:8765/api/stats`.

## Panels

**Sessions table** (under the KPIs): one row per session - short ID, started, last seen, duration, title, cases
touched, models, API calls, output tokens, tool calls/failures. The title is the session title stored in the transcript
(`logs/sessions.jsonl`, user rename > auto title; sessions with none show "(untitled)"). Click a short ID to set the
dashboard's **Session** variable, which narrows every other panel to that session; clear the box to reset. Network and
guard rows have no session ID, so for them "this session" means its first-to-last activity window (a resumed session
whose window spans a gap can include other sessions' calls from that gap).

KPIs (API calls, output tokens, cache hit %, tool calls, tool failure %, network errors) - output tokens by
model - context tokens (input + cache) by source (main vs each subagent) - tool calls and failures per tool -
tool table (calls, failure %, p50/max latency, result size) - network destinations table + calls by host -
passive-guard decisions - sessions/subagents - recent errors.

## API

`GET /api/<name>?from=&to=` (ISO-8601 or epoch ms), JSON array out. `name`: `health stats tokens tools_ts
tool_summary network network_ts errors guard agents sessions`. Extra params: `session=<id or unique prefix>` narrows any
endpoint except `sessions`/`health` to one session (empty = all), `tokens?metric=output|input|cache_read|cache_write|context&group=model|source`,
`tools_ts?metric=calls|failures|result_chars`, `interval=<seconds>` (default: ~60 buckets per range), `shape=wide|long` on time-series endpoints (the dashboard uses
`long` = fixed `time,series,value` columns that Infinity types natively and splits into one series per label; this
replaced a `convertFieldType` transformation that Grafana left untyped, giving "Data is missing a time field").

## Regenerating the dashboard

`monitoring/grafana/dashboards/claude-code-ops.json` is generated: edit `monitoring/tools/build_dashboard.py` and run
`python monitoring/tools/build_dashboard.py`; Grafana reloads the file within ~30 s. After editing `log_api.py`,
restart the API: `docker restart monitoring-log-api-1`.

## Tests

`python -m unittest discover -s monitoring/tests -v`
