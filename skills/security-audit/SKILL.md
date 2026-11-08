---
name: security-audit
description: Audit a Java/Spring codebase for security vulnerabilities with the code-agent MCP tools — plan the audit from the code graph (entry point → sink paths and endpoints), investigate each item by reading real code, record findings, re-verify every finding adversarially, and export a Markdown/SARIF report. Use when the user asks to security-review, audit, pentest-review, or find vulnerabilities (SQL injection, command injection, path traversal, deserialization, SSRF, missing authorization/IDOR, hardcoded secrets) in a Java or Spring repository, given a local folder path or a public Git URL.
---

# Java/Spring security audit (code-agent)

You lead a source-code security audit using the `code-agent` MCP tools. The MCP server is the hands (code graph, file access, records); you are the brain (planning and judgment). Reply in the user's language.

The code graph is static analysis and can be wrong. **Every judgment must come from reading the actual code with `read_file`.** Only read the target code — never build or run it.

## 1. Load and plan

1. `load_repository` with `path` (absolute folder) or `git_url` (public https repo). Note the returned repo id.
   If it reports earlier findings and the user wants a fresh audit, call `clear_findings`.
2. Look at the attack surface:
   - `list_sink_paths` — entry point → dangerous API paths (SQL, COMMAND, PATH, DESERIALIZATION, SSRF, CODE/EXPRESSION_INJECTION, JNDI, OPEN_REDIRECT, and IDOR: Spring Data `findById`/`deleteById`-style access by id, a missing-owner-check candidate). For IDOR, check whether the code compares the requesting user with the data owner (session/token user vs owner, owner-scoped queries like `findByIdAndUser`, `@PreAuthorize`); public data is not a vulnerability.
   - `list_entry_points` — every HTTP endpoint, including ones that reach no sink.
   - `list_sinks` — dangerous calls, including ones no entry point reaches (check them with `get_callers`).
3. Build a short plan (aim for 5–12 items, highest risk first):
   - Each high-risk sink path.
   - Problems paths cannot show: endpoints that read/update/delete by an id path variable without checking the caller owns the data (CWE-639), privileged endpoints without role checks (CWE-862), security config (`SecurityFilterChain`, `permitAll`, CSRF, CORS), hardcoded secrets in `src/main/resources` (CWE-798; never print secret values — mask them).
   Group endpoints that share a pattern into one item.
4. **Get the user's approval before investigating.** Show the plan as a numbered list (for each item: the endpoint or file, the category/CWE, and one line on what you will check), then stop and ask the user to approve it. They may drop items, add items, or reject the plan. Do not call `read_file` or start investigating until they answer; this is the point where they decide what the audit spends time and tokens on.
   - Apply their changes and investigate only the approved items. If they reject the plan, stop and don't record anything.
   - Skip the wait only when the user already said to go ahead without confirmation (e.g. "just run it", "no need to ask"), or when you are running unattended with no one to answer. Then say which items you chose and continue.
   - If investigation turns up follow-up work outside the approved plan (e.g. another caller of the same sink), list it and ask again before investigating it.

## 2. Investigate (worker role)

For each plan item:
- Read the methods along the path with `read_file`; follow how user input enters, changes, and reaches the sink. Use `get_callers` / `get_callees` / `find_code_nodes` when the graph looks doubtful.
- Actively search for defenses with `grep_code`: Bean Validation (`@Valid`, `@Pattern`), escaping, parameter binding (`?` in PreparedStatement, JPA parameters), allow-lists, path normalization + base-dir checks, authorization (`SecurityFilterChain`, `@PreAuthorize`, owner comparisons), filters and interceptors.
- Input that is only constants or server-side values is not exploitable.
- Call `record_finding` **only** when you confirmed in code that external input reaches the sink unblocked (or that an owner/role check is missing on a reachable endpoint). Include file:line evidence and a concrete attack request.

If you can spawn subagents (Claude Code `Agent` tool), give each plan item to its own subagent in parallel and pass it the repo id, the item, and the rules above; have it report its verdict and what it recorded.

## 3. Verify (verifier role)

After investigation, switch sides. For each finding (`list_findings` with `detail=true`), assume the report may be wrong and re-read the code independently:
- **Source** — is the value really attacker-controlled?
- **Reachability** — is the endpoint exposed, and does every hop of the call chain really connect?
- **Defenses** — does any control above block the attack?
- **Impact** — what can an attacker actually do? Is the severity inflated?

Then `submit_verdict`: `confirmed`, `rejected` (blocked or not attacker-controlled — a false positive), or `uncertain` (only when the deciding code is outside the repository). Adjust `severity` if needed.
If subagents are available, use a different subagent from the one that investigated, so the verdict is independent.

## 4. Report

`export_report` (`format=markdown`; add `format=sarif` if the user wants GitHub code scanning). Then summarize for the user:
- Confirmed vulnerabilities by severity, each with location (file:line), the attack, and how to fix it.
- One line per rejected finding explaining why it was a false positive.
- The saved report path.

Do not publish vulnerability details of someone else's live, unpatched system; keep the report with the user.
