# JSON output format (`fgaudit/report@1`)

`fgaudit ... --json` prints one JSON object to standard output. The format is stable within the
schema version `fgaudit/report@1`: fields may be added, but existing fields keep their name, type
and meaning. A breaking change gets a new schema version.

Secrets are removed and `--anonymize` is applied before the JSON is built, exactly as for the
terminal and HTML output.

Example: [sample-report.json](sample-report.json) (output of `fgaudit --demo --json`).

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `"fgaudit/report@1"`. |
| `tool` | object | `{"name": "fgaudit", "version": "1.0.0"}` |
| `mode` | string | `"audit"`, `"change"`, `"timeline"` or `"demo"`. |
| `lang` | string | `"en"` or `"de"`. Affects `title`, `detail`, `next_step`, `verdict` and notice texts only. Codes never change with the language. |
| `anonymized` | bool | `true` if `--anonymize` was used. |
| `inputs` | array | One object per input file, see below. |
| `summary` | object | See below. |
| `findings` | array | Sorted by severity (high → info), then by check and VDOM. See below. |
| `notices` | array | `{"code", "text"}`: general remarks, e.g. `version-unsupported`, `no-tz`, `uuid-ignored`, `policy-mode`, `unused-scope`. |
| `stats` | object | Mode-specific counters, see below. |
| `timeline` | object or null | Only in timeline mode. |
| `sections` | array | Only in demo mode: one complete report (without `schema` and `tool`, with an extra `title`) per demo part. |

### `inputs[]`

- Config: `{"kind": "config", "file", "model", "version", "supported", "vdom_mode", "vdoms": [...], "policies"}`
- Log: `{"kind": "log", "file", "lines"}`

`version` is `null` when the header could not be read. `supported` is `true` for 7.4, 7.6 and 8.0.

### `summary`

| Field | Type | Meaning |
|---|---|---|
| `counts` | object | `{"high", "medium", "low", "info"}` as integers. |
| `has_findings` | bool | `true` if there is at least one finding that is not `info`. |
| `verdict` | string | One human-readable summary line. |
| `exit_code` | int | The process exit code (0 or 1; `--demo` always 0). |

### `findings[]`

| Field | Type | Meaning |
|---|---|---|
| `id` | string | `F001`, `F002`, … in output order. Only stable within one report. |
| `check` | string | `shadow`, `unused`, `overlap`, `change` or `timeline`. |
| `code` | string | Machine-readable finding type, see the list below. |
| `severity` | string | `high`, `medium`, `low` or `info`. |
| `vdom` | string or null | The VDOM, or `null` for global and log findings. |
| `title`, `detail`, `next_step` | string | Localised text. |
| `objects` | array | `{"type", "name", "vdom"?, "id"?}`: the policies, objects, interfaces or devices involved. Types include `policy`, `address`, `service`, `interface`, `dhcp`, `ippool`, `vip`, `phase2`, `route`, `admin`, `device`. |
| `params` | object | Code-specific raw values (IDs, positions, ranges, profile differences, the trigger and chain of an incident). Keys within one code are stable. |

### Finding codes

- **shadow**: `shadow.conflict` (high), `shadow.redundant` (medium/low), `shadow.duplicate` (low),
  `shadow.uncertain` (info, "not reliably checkable"). `params.later` and `params.earlier` are the
  policy IDs, `later_pos`/`earlier_pos` their positions in the file, `profiles` the security
  profile differences. For `shadow.uncertain`, `dims` lists the dimensions that could not be
  decided and `dyn` the dynamic objects involved.
- **unused**: `unused.object` (low). `params.otype` names the object type, `params.names` the objects.
- **overlap**: `overlap.interface`, `overlap.interface-self`, `overlap.interface-vdom`,
  `overlap.interface-vrf`, `overlap.dhcp-outside`, `overlap.dhcp-interface`, `overlap.dhcp-dhcp`,
  `overlap.dhcp-vip`, `overlap.dhcp-ippool`, `overlap.ippool`, `overlap.vip`,
  `overlap.p2-local-net`, `overlap.p2-self`, `overlap.p2-p2`. `params` holds both sides
  (`a_kind`, `a_name`, `a_range`, `a_vdom`, and the same with `b_`) and the overlapping range in
  `overlap`.
- **change**: `change.lockout-allowaccess`, `change.lockout-admin-port`, `change.lockout-admin`,
  `change.lockout-local-in`, `change.lockout-interface-ip`, `change.insecure-allowaccess`,
  `change.interface`, `change.interface-added`, `change.interface-removed`,
  `change.interface-status`, `change.default-route`, `change.routing`, `change.sdwan`,
  `change.ha`, `change.vpn`, `change.nat`, `change.admin`, `change.global`, `change.logging`,
  `change.logging-disabled`, `change.object`, `change.object-added`, `change.broad-accept`,
  `change.policy-added`, `change.policy-removed`, `change.policy-action`,
  `change.policy-status`, `change.policy-match`, `change.policy-other`, `change.order`,
  `change.order-conflict`, `change.order-unknown`, `change.order-same`, `change.order-none`,
  `change.secret-not-comparable`, `change.vdom-added`, `change.vdom-removed`, `change.cosmetic`,
  `change.other`.
- **timeline**: `timeline.incident`. `params.trigger` is the trigger event, `params.chain` the
  follow-up events with `reason` and `delay` (seconds), `params.confidence` is `high`, `medium`
  or `low`.

### `stats`

- audit: `{"policies", "vdoms"}`
- change: `{"changes", "ignored_uuid", "not_comparable", "risk"}`
- timeline: `{"events", "devices"}`

### `timeline`

| Field | Meaning |
|---|---|
| `events[]` | Collapsed timeline rows: `time`, `last` (end of a collapsed repeat), `ts` (epoch seconds or `null`), `absolute` (false when the time zone is unknown), `device`, `category`, `kind`, `state`, `object`, `severity`, `count`, `flapping`, `logid`, `source`, `line`, `user`. |
| `unknown[]` | Unrecognised log IDs: `{"logid", "count", "subtype", "logdesc"}`. |
| `stats` | `lines`, `unparseable`, `classified`, `rows`, `unknown`, `traffic`, `no_time`, `devices`, `tz_missing`. |
