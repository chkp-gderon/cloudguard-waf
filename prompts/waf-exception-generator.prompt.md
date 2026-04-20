---
description: "Generate Check Point WAF exception proposals from a pre-classified critical events CSV. Use when: an analyst has labelled WAF events as benign or malicious and you need to produce a consolidated, deployment-ready exception rule list."
name: "WAF Exception Generator"
argument-hint: "Path to the *_classified.csv file (e.g. ./events_classified.csv)"
agent: "agent"
tools: ["read_file", "run_in_terminal"]
---

# WAF Exception Generator

## Goal

You receive a classified CSV export of Check Point WAF (Check Point Infinity Next) critical-severity events. Your task is to:

1. Parse all rows labelled `benign` in the `Analyst Label` column.
2. Group them by meaningful signature patterns (host, method, URI, matched location, parameter name).
3. Produce a consolidated, deployment-ready exception plan following the strict rule conventions documented below.
4. Output two artefacts:
   - `waf_exception_priority_list.md` — condensed, deployment-ready ruleset (primary deliverable).
   - `waf_false_positive_exception_plan.csv` — exhaustive per-signature reference table.

---

## Input File Format

The input file is a CSV with the following columns (order may vary — always use column headers):

| Column | Description |
|---|---|
| `Time` | Event timestamp |
| `Event Severity` | Always `Critical` for this workflow |
| `Asset Name` | WAF asset / site name |
| `Security Action` | `Detect` or `Prevent` |
| `Incident Type` | Comma-separated list of matched threat categories |
| `Source Identifier` | Client identifier (IP or fingerprint) |
| `Source IP` | Raw client IP |
| `Proxy IP` | Upstream proxy IP if present |
| `HTTP Host` | Virtual host (e.g. `www.example.com`) |
| `Http Method` | `GET`, `POST`, etc. |
| `Http Response Code` | HTTP status of the response |
| `Http URI Path` | Request URI path |
| `Protection Name` | WAF protection rule name that fired |
| `Matched Location` | Where the match occurred: `body`, `header`, `cookie`, `url` |
| `Matched Parameter` | Name of the matched parameter/header/cookie |
| `Matched Sample` | Snippet of the matched content |
| `Asset ID` | WAF asset UUID |
| `Found Indicators` | Comma-separated list of matched signatures/indicators |
| `Analyst Label` | **`benign`** or `malicious` — filter on this |
| `Label Reason` | Human analyst free-text reasoning |
| `Needs Header Review` | `yes` / `no` flag |
| `Review Category` | Optional analyst tag |

**Only process rows where `Analyst Label` == `benign`.**

---

## Check Point WAF Exception Rule Conventions

All rules must strictly follow these conventions. Deviating from them will produce rules the WAF cannot parse correctly.

### Action Types

| Action | When to Use |
|---|---|
| `SKIP` | A specific named parameter can be targeted (body param, header name, cookie name). The WAF skips inspection of that parameter only; the rest of the request is still inspected. **Always prefer SKIP.** |
| `ACCEPT` | No specific parameter can be targeted (e.g. whole-body match with no discriminating parameter name). The WAF accepts the entire request without inspection. Use only as a last resort. |

### Rule Field Conventions

```
Action: SKIP | ACCEPT
Host: <virtual-host>
Method: GET | POST | ...
URI: /exact/path/             ← use for exact paths
URI Pattern: ^\/path\/.*$     ← use for prefix/wildcard matches (regex)
Matched Location: body | header | cookie | url
Parameter Name: <exact-name>  ← required for SKIP; omit for ACCEPT
Parameter Value: .*           ← always include when using Parameter Name (required by WAF UI even when not filtering by value)
Scope Keys: <conditions>      ← optional; omit if no discriminating scope can be determined
```

### URI Patterns — Regex Rules

- The WAF regex engine uses `/` as a delimiter. **Always escape forward slashes** in URI patterns: use `\/` not `/`.
- Anchor patterns: `^` at start, `$` at end.
- One or more leading slashes: use `^\/+` to handle edge cases with normalised paths.
- Example — exact path: `^\/logincheck\/$`
- Example — prefix: `^\/magazin(\/.*)?$`
- Example — alternation: `^\/+(media\/i\/.*|assets\/binaryImages\/.*)$`

### Scope Keys — Logic Operators

- Use **`OR`** between `sourceIdentifier` and `sourceIP` for the same IP — a request has only one source, not both.
  - Correct: `sourceIdentifier=1.2.3.4 OR sourceIP=1.2.3.4`
  - Wrong: `sourceIdentifier=1.2.3.4 AND sourceIP=1.2.3.4`
- Use **`AND`** between different key types (e.g. a header AND a URI scope on the same rule).
- Omit scope keys entirely when the false positive genuinely originates from many diverse clients (e.g. a widely-used browser cookie). Do not invent overly broad header-based scopes that appear on every request site-wide.

### Consolidation Guidelines

1. **Merge by common signature** — if multiple events share the same host, method, matched location, and parameter name but differ only in URI, use a URI Pattern with alternation or a common prefix pattern.
2. **Merge parameter names with OR logic** — if the same URI/method/location combination has multiple distinct parameter names, document them as a "Parameter Name matches ANY of:" list and note that in the WAF UI you create one exception entry per parameter name under the same rule grouping.
3. **Never merge rules across different matched locations** — body, header, cookie, and URL parameters are handled separately.
4. **Pin to source IP/identifier only when warranted** — use a source scope only if all benign events for a given rule consistently originate from a single known IP (e.g. an admin workstation or backend service). Do not pin if diverse client IPs are observed.

### Parameter Value Field

- Always include `Parameter Value: .*` when a `Parameter Name` is specified.
- This is required by the WAF UI when creating an exception targeted at a named parameter.
- Do not add ` Parameter Value` without a `Parameter Name`.

---

## Generation Process

### Step 1 — Parse and Filter

Run a Python script to load the CSV, filter `Analyst Label == benign`, and group by:
- `HTTP Host`
- `Http Method`
- `Http URI Path`
- `Matched Location`
- `Matched Parameter`
- `Source IP` / `Source Identifier`

Count events per group to establish frequency/priority.

### Step 2 — Classify Action Type

For each group:
- If `Matched Location` is `body`, `header`, or `cookie` **and** `Matched Parameter` is non-empty → **SKIP** candidate.
- If `Matched Parameter` is empty or the match is on the full request body with no discriminating name → **ACCEPT** candidate.

### Step 3 — Consolidate

Apply the consolidation guidelines above:
- Merge URI variants into a common regex pattern where safe.
- Merge multiple parameter names under the same rule block.
- Group SKIP rules first; ACCEPT rules last.

### Step 4 — Generate Artefacts

**`waf_false_positive_exception_plan.csv`** — one row per unique (host, method, URI, location, parameter) combination:

```
Host,Method,URI,Matched Location,Parameter Name,Source IPs,Event Count,Recommended Action,Notes
```

**`waf_exception_priority_list.md`** — consolidated deployment guide using the template below.

---

## Output Template — `waf_exception_priority_list.md`

```markdown
# WAF Exception Priority List (Consolidated)

This version consolidates the benign false-positive handling into a minimal rule set using OR and URI patterns where safe.

## 1) Consolidated SKIP Rules

1. Action: SKIP
   - Host: <host>
   - Method: <method>
   - URI Pattern: <regex>   ← or URI: /exact/path/ for exact paths
   - Matched Location: <body|header|cookie|url>
   - Parameter Name: <name>
   - Parameter Value: .*
   - Scope Keys: sourceIdentifier=<ip> OR sourceIP=<ip>   ← omit if not warranted

   [If multiple parameter names apply:]
   - Parameter Name matches ANY of:
     - <name1>
     - <name2>
   - Parameter Value: .*

[... additional SKIP rules ...]

## 2) Consolidated ACCEPT Rules (Only Where SKIP Is Not Feasible)

1. Action: ACCEPT
   - Host: <host>
   - Method: <method>
   - URI Pattern: <regex>
   - Matched Location: <body|header|cookie|url>

## 3) Deployment Order

1. Create SKIP rules first.
2. Monitor Important Events for 24-48 hours.
3. Add ACCEPT rules only if remaining noise is critical and confirmed benign.
4. Validate that malicious probes to unrelated URIs are still blocked.
```

---

## Quality Checklist Before Delivering Output

Before finalising the output, verify each rule against this checklist:

- [ ] Every URI regex has all forward slashes escaped as `\/`
- [ ] Every URI regex is anchored with `^` and `$`
- [ ] Every SKIP rule has `Parameter Value: .*`
- [ ] `OR` is used between `sourceIdentifier` and `sourceIP` (never `AND`)
- [ ] `AND` is used only between genuinely different scope key types
- [ ] No ACCEPT rule is proposed where a SKIP would suffice
- [ ] Source IP pinning is only applied when all events in the group share a single IP
- [ ] No source scope is applied for widely-used browser cookies/headers that are non-discriminative
- [ ] ACCEPT rules do not include a `Parameter Name` (they accept the whole request)
- [ ] Consolidation does not merge rules across different `Matched Location` types

---

## Notes on WAF Platform

- **Platform**: Check Point  WAF (Infinity Next)
- **Documentation**: https://waf-doc.inext.checkpoint.com
- Exception rules are created under the asset's **Exception** tab.
- SKIP exceptions continue processing the remainder of the request.
- ACCEPT exceptions bypass all inspection for the matched request.
- When using "Parameter Name" in the UI, always set a Parameter Value (even `.*`) — the field is required.
