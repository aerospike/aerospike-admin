# Modernize collectinfo: provenance, dropped-node detection, error persistence, diagnostics banners

## Context

Customers routinely collect a collectinfo with an **old** asadm and analyze it with a **latest** asadm. Vital info the latest asadm expects is missing, and the analyzer gives no signal. Problems (tracked in TOOLS-4135):

1. No provenance: `ascinfo.json` carries no asadm version; version only echoed as text into `ascollectinfo.log`/`summary.log` (`_write_version`, [collectinfo_controller.py:151](lib/live_cluster/collectinfo_controller.py#L151)).
2. Old asadm silently dropped nodes on timeout (fixed forward in TOOLS-3596 `55c47ee`: per-node timeout raised to 5s, failed nodes kept with empty `as_stat`). Old bundles still have the drop; analyzer never reconciles captured vs expected nodes. Per-node errors are classified in `async_return_exceptions` ([node.py:81](lib/live_cluster/client/node.py#L81)) then scrubbed to `{}`/`""` and never persisted. **No retry.**
3. Remote-collected bundles have empty `sys_stat` and no `sysinfo.log`/`aerospike.conf`, with no warning.
4. Analyzer has no startup diagnostics path at all (live-cluster startup does, [asadm.py:216-254](asadm.py#L216)).

Goal: self-describing bundles (who/when/how collected, what failed), one bounded retry for transient timeouts, and a concise analyzer startup banner surfacing version mismatch, dropped/missing nodes, missing sysinfo, per-node errors, and a curated set of high-signal anomalies. Analyzer must work on **old** bundles (heuristics) and **new** bundles (rich metadata).

Decisions (confirmed): single PR; bounded single-pass timeout-only retry + persist per-node errors; banner in interactive intro AND re-emitted via `logger.warning` in `--execute` mode.

## Storage decision (backward compatibility) — verified

Write a **separate `collectinfo_meta.json`** into the bundle dir. Do NOT embed a `meta` key in `ascinfo.json`: `_is_valid_collectinfo_json` ([collectinfo_parser.py:95](lib/collectinfo_analyzer/collectinfo_handler/collectinfo_parser/collectinfo_parser.py#L95)) requires every top-level key be a timestamp, so a `meta` key makes new bundles unreadable by old asadm. Verified the separate file is safely ignored: parser ingests only `*ascinfo.json` (line 42) and `continue`s on every other `.json` (line 61); `_add_cinfo_log_files` "Multiple snapshots" check keys off `ascinfo.json` timestamps only, so the extra file does not trip it. Write it as `as_logfile_prefix + "collectinfo_meta.json"` (only the prefix path is available in `_dump_collectinfo_json`; `cf_dir` is not passed in).

---

## Part A — Collection side

Primary file: [lib/live_cluster/collectinfo_controller.py](lib/live_cluster/collectinfo_controller.py)

### A1. `collectinfo_meta.json` schema

```jsonc
{
  "meta_format_version": 1,
  "bundle": { "ascinfo_schema": "1.0", "asadm_version": "3.x.y", "asadm_build": "<sha>", "generated_by": "asadm collectinfo" },
  "collection": {
    "host": "<socket.gethostname()>",
    "start_ts_utc": "...", "end_ts_utc": "...",
    "snapshot_count": 1,
    "flags": { "enable_ssh": false, "effective_node_timeout_sec": 5, "requested_node_timeout_sec": 5,
               "sleep_between_snapshots_sec": 5, "output_prefix": "", "asconfig_file": "...", "ignore_errors": false },
    "seeds": [ {"addr": "...", "port": 3000, "tls_name": null} ]   // from get_seed_nodes(), sorted for determinism
  },
  "snapshots": [ {
    "timestamp": "...", "cluster_name": "prod",
    "expected_nodes": ["ip:port", ...],   // per snapshot: computed per _get_collectinfo_data_json call, can differ between snapshots
    "responded_nodes": [...], "no_data_nodes": [...],
    "nodes": { "ip:port": { "node_id": "BB9...", "responded": true, "sysinfo_source": "local|ssh|none",
                            "errors": [ {"section": "statistics", "error_class": "timeout", "message": "...", "recovered_on_retry": false} ] } },
    "discrepancies": {
      "missing_from_collection": [ {"node_key": "...", "reason": "seen in peers of <node> but not collected"} ],
      "dropped_during_collection": [ {"node_key": "...", "reason": "unreachable"} ],
      "cluster_down_nodes": [...], "visibility_error_nodes": [...]
    }
  } ]
}
```
`error_class ∈ {timeout, unreachable, auth, corrupt, other}`; `section ∈ {statistics, config, metadata, histogram, latency, acl, user_agents, masking, sysinfo}`.

### A2. Capture per-node errors before scrub (controller-side ledger)

`async_return_exceptions` returns the exception **object** as the section value, so the class survives to every scrub site. Add a per-snapshot `node_errors` ledger and:
- `_classify_exception(exc)` mapping (done in OUR classifier, not the decorator): `asyncio.TimeoutError`→timeout (before OSError; subclasses it on 3.11+), `(ASInfoNotAuthenticatedError, ASProtocolConnectionError)`→auth, `OSError`→unreachable, `(ASInfoError, ASInfoResponseError)`→corrupt, else other. **Note:** the decorator has no corrupt branch (ASInfoError falls to its catch-all with `alive=True`); we classify corrupt ourselves. Import types from [lib/live_cluster/client/types.py](lib/live_cluster/client/types.py) (`ASProtocolConnectionError:196`, `ASInfoNotAuthenticatedError:332`, `ASInfoError:220`).
- `_record_node_error(ledger, node_key, section, exc)` — de-duped per `(node_key, section, error_class)`.

Thread the ledger through the existing exception checks (verified call sites, all in-file, no external callers — add params with defaults):
- `_remove_exception_from_section_output` ([:250](lib/live_cluster/collectinfo_controller.py#L250)) — 3 call sites (`:283,:284` statistics/config; `:431` acl). Add `section_label`+`ledger`.
- `_check_for_exception_and_set` ([:314](lib/live_cluster/collectinfo_controller.py#L314)) — 13 call sites in `_get_as_metadata`, section `metadata`.
- `isinstance(...,Exception)` guards in `_get_as_histograms`/`_get_as_latency`/`_get_as_user_agents`/`_get_as_masking_rules`, plus the sysinfo re-raise at [:526-529](lib/live_cluster/collectinfo_controller.py#L526) (record before raising).

### A3. Discrepancy detection at collect time (live calls available here)

`_get_collectinfo_data_json` ([:468](lib/live_cluster/collectinfo_controller.py#L468)) returns `(snp_map, snapshot_meta)`. New `_detect_node_discrepancies(...)`:
- `responded_nodes` = expected nodes with real data (reuse module fn `_as_stat_has_aerospike_data`, [:63](lib/live_cluster/collectinfo_controller.py#L63)).
- `cluster_down_nodes` = `await self.cluster.get_down_nodes()` (async, [cluster.py:269](lib/live_cluster/client/cluster.py#L269), returns `ip:port` keys via live info calls).
- `visibility_error_nodes` = `self.cluster.get_visibility_error_nodes()` (**sync, do not await**, [cluster.py:250](lib/live_cluster/client/cluster.py#L250)).
- `missing_from_collection`: union each surviving node's `meta_data.services` value (peers = `info_peers_flat_list`, a **list of `[ip,port,tls]` triples**), map each to a key via `Node.create_key(ip, port)` ([node.py:863](lib/live_cluster/client/node.py#L863)), **then canonicalize through `self.cluster.aliases`** (`aliases.get(peer_key, peer_key)`, [cluster.py:79](lib/live_cluster/client/cluster.py#L79) — maps alias `ip:port` to the canonical `node.key`), subtract `expected_node_keys`. Without the alias hop, multi-homed clusters (seeded via localhost/FQDN while peers advertise internal IPs, IPv6 forms) produce false "missing node" entries baked permanently into meta.
- `dropped_during_collection` = expected − responded; reason from worst recorded `error_class`.
- `sysinfo_source` per node: `local` if `node.localhost`, else `ssh` if `enable_ssh` and no sysinfo error, else `none`. Reuse the `self.cluster.get_nodes(self.nodes)` set captured for `expected_node_keys` ([:482](lib/live_cluster/collectinfo_controller.py#L482)).
- **Fail-safe (hard rule): diagnostics must never break the bundle they diagnose.** `_detect_node_discrepancies` runs inside `_get_collectinfo_data_json`; any raise propagates to the `except Exception` at [:1066](lib/live_cluster/collectinfo_controller.py#L1066) and aborts collection when `--ignore-errors` unset. Wrap the whole discrepancy pass (including the live `get_down_nodes()` call) in try/except: `logger.warning`, emit `"discrepancies": {"detection_error": "<msg>"}`, continue.

### A4. Bounded timeout-only retry (one pass) — corrected for real helper signatures

The `_get_as_*` helpers currently take **no `nodes` arg** (they hardcode `self.nodes`). Add an optional `nodes=None` param (defaulting to `self.nodes`) to the node-scoped, retry-eligible helpers: `_get_as_data_json` (passes straight to `get_all(nodes=...)`, [:279](lib/live_cluster/collectinfo_controller.py#L279)), `_get_as_metadata`, `_get_as_histograms`, `_get_as_latency`, `_get_as_user_agents`. Exclude `_get_as_access_control_list` (calls `get_all()` unscoped) and `_get_as_masking_rules` (`nodes="principal"`) from subset retry.

After the three batches, if `node_errors` has any `timeout` entries, run **one** retry pass calling only the affected helpers scoped to the timed-out node subset; merge into the section maps before `_build_dump_map`; on success set `recovered_on_retry: true`. Add `COLLECTINFO_MAX_RETRIES = 1` near `COLLECTINFO_NODE_TIMEOUT` ([:60](lib/live_cluster/collectinfo_controller.py#L60)). No full-snapshot re-run.

### A5. Assemble + write meta

`_dump_collectinfo_json` ([:647](lib/live_cluster/collectinfo_controller.py#L647)) accumulates each `snapshot_meta`, builds the object via `_build_collectinfo_meta(...)`, writes `as_logfile_prefix + "collectinfo_meta.json"` via `_dump_in_json_file` (ledger stores only `str(exc)` + class string, so `json.dumps` is safe). Thread `original_timeout`, `output_prefix`, `asconfig_file`, `ignore_errors` from `_run_collectinfo` ([:997](lib/live_cluster/collectinfo_controller.py#L997)); seeds via `self.cluster.get_seed_nodes()` (a set → sort); host via `socket.gethostname()`.

**Fail-safe:** wrap meta assembly + write in its own try/except (`logger.warning`, continue). A meta bug must not abort collection or trip the `ignore_errors` path; `ascinfo.json` write stays outside this guard, unchanged.

### A6. asadm build threading

`asadm_build` is computed at [asadm.py:749](asadm.py#L749) but only used for `--version`. Add `asadm_build` class attr on `BaseController` ([base_controller.py:264](lib/base_controller.py#L264)), set it in `LiveClusterRootController` ([:75](lib/live_cluster/live_cluster_root_controller.py#L75)) and `CollectinfoRootController` ([:34](lib/collectinfo_analyzer/collectinfo_root_controller.py#L34)), pass from `asadm.py` shell construction.

### A7. Constants

[lib/utils/constants.py](lib/utils/constants.py) near the `COLLECTINFO_*` block: `COLLECTINFO_META_FILENAME`, `COLLECTINFO_META_FORMAT_VERSION`, `COLLECTINFO_ASCINFO_SCHEMA`, `COLLECTINFO_MAX_RETRIES`, `error_class` set.

---

## Part B — Analyzer side (diagnostics banner)

### B1. New module `lib/collectinfo_analyzer/collectinfo_handler/collectinfo_diagnostics.py`

- `DiagSeverity(Enum)`; `@dataclass BundleWarning { category, severity, title, lines[], table? }`.
- `class CollectinfoDiagnostics(log_handler, snapshot, timestamp, running_version, meta=None)` with `analyze() -> list[BundleWarning]` (fixed order, short-circuit on zero-nodes).
- `render_banner(warnings, use_color=True) -> str` and `emit_to_log(warnings, logger)`.

### B2. Rendering (reuse existing machinery — no shared accumulator exists, use the list[str] idiom)

- **`--execute` mode**: emit each warning via `logger.warning(...)` ([logger.py:129](lib/utils/logger.py#L129)) — stderr, auto-yellow, `WARNING:` prefix. **Do not** also wrap in `terminal.fg_yellow()` (formatter already colors). Wire an `else:` branch at [asadm.py:169-170](asadm.py#L169) (guard var `execute_only_mode`, [asadm.py:795](asadm.py#L795)) calling `log_handler.emit_diagnostics_to_log()`.
- **Interactive mode**: append `render_banner(...)` to `CollectinfoLogHandler.__str__` ([log_handler.py:71](lib/collectinfo_analyzer/collectinfo_handler/log_handler.py#L71)); build the string with `terminal.fg_yellow/fg_red/fg_clear/bold` ([lib/view/terminal/terminal.py](lib/view/terminal/terminal.py)). For the per-node error table, `sheet.render(...)` ([lib/view/sheet/render/__init__.py:47](lib/view/sheet/render/__init__.py#L47)) **returns a string — embed it directly into the banner string**. Do NOT route through `self.view.print_result`: the log handler has no `view`, and `__str__` must return, not print. (Sheet declaration itself can mirror the one used by `show_best_practices`, [view.py:1334](lib/view/view.py#L1334).)
- Version compare via `version.LooseVersion` ([lib/utils/version.py:267](lib/utils/version.py#L267), already used at [collectinfo_controller.py:776](lib/live_cluster/collectinfo_controller.py#L776)); guard `development`/`N/E`/unparseable → unknown.

### B3. `_CollectinfoSnapshot` helpers ([collectinfo_log.py](lib/collectinfo_analyzer/collectinfo_handler/collectinfo_log.py))

Add read-only: `has_sys_data(node)` (check raw `cinfo_data[node]["sys_stat"]`, NOT stanza-specific `get_sys_data`), `nodes_without_as_stat()`, `get_advertised_peers()`/`get_own_endpoints()` (consume the `[ip,port,tls]` **triples** from meta_data services/endpoints — the existing `.split(";")` at [collectinfo_log.py:321](lib/collectinfo_analyzer/collectinfo_handler/collectinfo_log.py#L321) is dead code and always returns the raw list; build keys via `ip:port`).

### B4. `CollectinfoLogHandler` wiring

`__init__` ([:57](lib/collectinfo_analyzer/collectinfo_handler/log_handler.py#L57)): add `asadm_version=""`; `self.collectinfo_meta = self._load_collectinfo_meta()` (defensive `.get`, tolerate absent/partial). Add `_load_collectinfo_meta`, `_iter_bundle_files(suffixes)` (walk `cinfo_path` + `collectinfo_dir` — `_get_valid_files` keeps only `.json`/`.conf`, version scan needs `.log`), `_scan_bundle_for_asadm_version` (regex `asadm version\s+(\S+)` over `ascollectinfo.log`/`summary.log`, capped read), `get_bundle_diagnostics` (cached, newest snapshot), `diagnostics_banner`, `emit_diagnostics_to_log`. Pass `asadm_version` from `CollectinfoRootController.__init__` ([:38](lib/collectinfo_analyzer/collectinfo_root_controller.py#L38)).

**Mid-collection instantiation:** collection itself constructs a `CollectinfoRootController` over the half-written bundle dir ([collectinfo_controller.py:1074](lib/live_cluster/collectinfo_controller.py#L1074)) to dump summary/health — at that point `collectinfo_meta.json` exists but `ascollectinfo.log`/`summary.log` do not. `_load_collectinfo_meta` and `_scan_bundle_for_asadm_version` must tolerate missing files silently (no warning spam into the collect run); nothing auto-emits the banner there (banner fires only via `str()` in the analyzer intro or the explicit execute-mode call). Cover with a unit test.

### B5. Checks

**Collection-integrity / provenance (primary — the ticket):**
- **Collector version** — meta `bundle.asadm_version` → else log-scan → else unknown; compare to running version. Variants: older (may omit sections / dropped nodes; re-collect), newer (analyzer may not render all sections), equal (INFO), unknown (treat counts with caution).
- **Dropped/missing nodes** — new bundle: read meta `discrepancies.*` (authoritative, computed live at collect time). Old bundle: derive from (a) `cluster_size` (service stat) vs present-node count, (b) advertised-peer triples minus present nodes, (c) `cluster_integrity` false. Phrase with "may".
- **Missing sysinfo** — per node `not has_sys_data(node)` → "collected remotely without --enable-ssh"; absence of any `sysinfo.log`/`aerospike.conf` → "collected from non-localhost node".
- **Per-node collection errors** — meta `node_errors` → table [Node, Failed sections, Reason].
- **Zero usable nodes** (short-circuit); **present-but-empty nodes**; **missing config/statistics** per node.

**Curated high-signal anomalies (currently hidden or live-only; keep to one line each, point to the relevant command). Stat names verified against server source (`aerospike-server`):**
- **Active stop-writes** — reuse `common.create_stop_writes_summary` (already wired in collectinfo `show stop-writes`, [show_controller.py:1818](lib/collectinfo_analyzer/show_controller.py#L1818)); "→ run `show stop-writes`". Server: ns stat `stop_writes` (thr_info.c:4200), ns `clock_skew_stop_writes` (thr_info.c:4196).
- **cluster_integrity false / cluster_key split / cluster_size mismatch / orphan node** (service stats; captured proxies for the live-only visibility/down checks, already computed by `info network`). Server: `cluster_integrity` + `cluster_is_member` (thr_info.c:3379-3382; `cluster_is_member` false = orphan), `cluster_size`/`cluster_key`/`cluster_principal` (exchange.c:3809-3813).
- **Multiple principals** (`cluster_principal` mismatch; relocate the inline `logger.warning` at [log_handler.py:124](lib/collectinfo_analyzer/collectinfo_handler/log_handler.py#L124) here). **Deliberate behavior change:** today it fires on every `get_principal` call; after relocation it fires once at startup. Note in PR description.
- **Migrations in progress** (`migrate_partitions_remaining` > 0, thr_info.c:3530) — caveat that usage/object counts are transient.
- **Mixed server build / mixed edition** (`meta_data.asd_build`/`edition` set size > 1) — rolling upgrade / misconfig.
- **best_practices failures** — meta_data path: `meta_data.best_practices` non-empty (already read at [show_controller.py:1653](lib/collectinfo_analyzer/show_controller.py#L1653), server info command `best-practices`, thr_info.c:384). Fallback for bundles missing that meta key: service stat `failed_best_practices` bool (thr_info.c:3372) in plain statistics. Plus **health-outliers** (`meta_data.health`; net-new analyzer consumption) — server-flagged, otherwise buried behind on-demand commands.
- **dead_partitions / unavailable_partitions** != 0 (ns stats, thr_info.c:4191-4193; emitted unconditionally, nonzero only meaningful in SC) — data-availability / SC data loss.
- **Multiple snapshots collapsed** — bundle has N>1 snapshots but summary/health show only newest; **stale bundle age** — newest snapshot vs now.

**Do NOT duplicate** (point to the command, don't reimplement): full watermark/defrag/roster/SC rule set → `health`; node/version/OS/device/memory/license/namespace-count → `summary`; stop-writes detail → `show stop-writes`; best-practice detail → `show best-practices`.

**Not derivable from a bundle** (verified — do not promise): live down-node/visibility reconstruction (alumni/peers not structural; use proxies above), feature-key expiry (info response has no expiry), collector-host-vs-node clock skew (no per-node wall clock stored; surface intra-cluster `cluster_clock_skew_ms` instead — service stat, thr_info.c:3386).

---

## Files touched

Collection: `collectinfo_controller.py` (primary), `constants.py`, `base_controller.py`, `live_cluster_root_controller.py`, `collectinfo_root_controller.py`, `asadm.py`. Analyzer: new `collectinfo_diagnostics.py`, `log_handler.py`, `collectinfo_log.py`, `collectinfo_root_controller.py`, `asadm.py`. Preserve (do not modify behavior): `collectinfo_parser.py`.

## Sequencing

1. Constants + thread `asadm_build`.
2. `_classify_exception`/`_record_node_error` + ledger plumbing (no output change).
3. `_detect_node_discrepancies` + per-snapshot `snapshot_meta` (fix async/sync calls; consume peer triples).
4. Write `collectinfo_meta.json`.
5. Add `nodes=` param to node-scoped helpers + bounded timeout-only retry.
6. Analyzer: snapshot helpers → handler plumbing → `collectinfo_diagnostics.py` → wire `__str__` + execute-mode emit + root controller arg.

## Verification

- **New bundle**: `asadm ... -e "collectinfo"`; confirm `collectinfo_meta.json` in the tgz with version, expected/responded nodes, and (with a node stubbed to time out) an `errors` entry showing `recovered_on_retry` after the retry pass.
- **Backward compat (critical)**: a **current released** `asadm -cf <new-bundle>` must load normally and ignore `collectinfo_meta.json`.
- **New analyzer / old bundle** (no meta): version-unknown banner + proxy-derived missing-node warning (cluster_size vs present, peer triples, cluster_integrity) + missing-sysinfo warning.
- **New analyzer / new bundle**: exact collector version, meta-driven missing/dropped nodes, per-node error table, plus any curated anomalies.
- **Execute mode**: `asadm -cf <bundle> -e "info network"` re-emits warnings via stderr `logger.warning`.
- **Unit tests**: new `test/unit/collectinfo_analyzer/test_collectinfo_diagnostics.py` (each check with synthetic snapshot+meta incl. peer triples), extend `test_log_handler.py` (meta load, version scan, banner, **missing-log tolerance for mid-collection instantiation**); collection-side tests for `_classify_exception` (incl. corrupt=ASInfoError), discrepancy detection (sync/async calls, **alias canonicalization: peer advertises internal IP while node collected under seed address → no false missing entry**), retry merge with `nodes=` subset, meta assembly, **fail-safe paths: `_detect_node_discrepancies` raising and meta write raising both leave collection successful with `ascinfo.json` intact**.
