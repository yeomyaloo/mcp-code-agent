# Benchmark

An evaluation harness that measures how well an audit with this plugin finds vulnerabilities, and whether repeated audits of the same code reach the same conclusions. The same benchmark lives in cotcha-net, where `run.py` drives the backend; here you run the audit in Claude Code and score the exported SARIF.

| File | What it is |
|---|---|
| `shop-app/` | A small Spring + React shop with **11 real vulnerabilities** and **10 safe look-alikes** (traps): each vulnerable spot has a safe twin of the same category. There are no hint comments in the code. |
| `node-shop/` | A Node.js (Express) shop API with **12 real vulnerabilities** and **9 safe look-alikes**, including Node-specific ones (NoSQL operator injection, prototype pollution, `node-serialize`). No hint comments either. |
| `node-shop.expected.json` | Its answer key, in the same format and also outside the app folder. |
| `go-shop/` | A Go (gin + database/sql) shop API with **11 real vulnerabilities** and **8 safe look-alikes**, including Go-specific ones (`template.HTML`, template injection, `InsecureSkipVerify`, interface calls into the store). |
| `go-shop.expected.json` | Its answer key. |
| `php-shop/` | A PHP (Laravel) shop API with **11 real vulnerabilities** and **8 safe look-alikes**, including PHP-specific ones (`unserialize`, XXE with `LIBXML_NOENT`, `eval`, calls through a repository interface). |
| `php-shop.expected.json` | Its answer key. |
| `ruby-shop/` | A Ruby (Rails) shop API with **11 real vulnerabilities** and **7 safe look-alikes**, including Ruby-specific ones (`Kernel#open` pipe, `Marshal.load`, ERB template injection, `html_safe`, `allow_other_host: true`). |
| `ruby-shop.expected.json` | Its answer key. |
| `cs-shop/` | A C# (ASP.NET Core) shop API with **11 real vulnerabilities** and **8 safe look-alikes**, including .NET-specific ones (`FromSqlRaw` vs `FromSqlInterpolated`, JSON.NET `TypeNameHandling`, `XmlUrlResolver`, `CSharpScript`, `Redirect` vs `LocalRedirect`). |
| `cs-shop.expected.json` | Its answer key. |
| `shop-app.expected.json` | The answer key: file, line range, sink line, accepted CWEs and entry point of each item. It lives **outside** `shop-app/` so Claude cannot read it while auditing. |
| `score.py` | Scores one or more SARIF reports against the answer key: recall, precision, trap false positives, wrong CWE, duplicates and, for several runs, consistency. |
| `test_score.py` | Tests for the scoring rules. |

`BenchmarkTest` (part of `./gradlew test`, runs in CI) checks, for every app, that every vulnerability and trap shows up in `list_sinks`, nothing else does, and each vulnerability with an entry point shows up in `list_sink_paths`.

## Scoring an audit (manual)

1. In Claude Code, start a fresh session for each run and ask: "Audit `<absolute path>/benchmark/shop-app` for security vulnerabilities". Approve the plan.
2. At the end, have Claude call `export_report` with `format: sarif` and save it as `report-1.sarif`. Run `clear_findings` before the next run so findings don't carry over.
3. Score:

```bash
python benchmark/score.py benchmark/shop-app.expected.json report-1.sarif report-2.sarif report-3.sarif
python benchmark/score.py benchmark/shop-app.expected.json report-*.sarif --confirmed-only
```

Rules: a finding points at an item when one of its locations is inside the item's file and line range. With an accepted CWE it is a hit, with another CWE a wrong category. Pointing at a trap is a trap false positive; pointing at nothing is another false positive. Rejected findings are ignored. Consistency is the share of items that got the same outcome in every run, plus the mean Jaccard similarity between runs.

## Results: node-shop (blind)

Three blind runs (plugin 0.21.0, cotcha-trail 0.18.0). Each run was a separate agent that audited a copy of `node-shop/` with the plugin tools and could not read the answer key. `check_dependencies` was not used.

- Recall 100%, 100%, 100%. Precision 100%. Trap false positives 0/9 in every run. The same outcome for 21/21 items, mean Jaccard 1.00.
- The first scoring found two bugs in the answer key, not in the audits, and they are fixed. All three runs reported the reset token as CWE-330, but the key accepted only CWE-338 (the shop-app key accepts 330/338/340). A trap's line range also covered the whole handler, so that wrong-CWE hit was counted as a trap.
- All three runs also noticed that lodash `^4.17.21` already blocks `__proto__` in `merge`, so the prototype-pollution item was only marked uncertain/low. `package.json` now pins lodash 4.17.4, where `merge` is exploitable (fixed in 4.17.5).

**Rerun on the fixed app (lodash 4.17.4):** three new blind runs under the same instructions. Recall 100%, 100%, 100%. Precision 100%. Trap false positives 0/9 in every run. All 12 findings in each run were confirmed, and prototype pollution is now confirmed as high instead of left uncertain. The same outcome for 21/21 items, mean Jaccard 1.00 (also with `--confirmed-only`).


## Results: go-shop (blind)

Three blind runs (plugin 0.22.0, cotcha-trail 0.19.0), same instructions as node-shop. Recall 100%, 100%, 100%. Precision 100%. Trap false positives 0/8 in every run. All 11 findings confirmed in each run, the same outcome for 19/19 items, mean Jaccard 1.00. Every run followed the search query through the `Store` interface into the SQL string and judged the payment-status request safe because its host comes from config and the id is escaped. Two runs lowered the `template.HTML` XSS to low because the route needs a Bearer header, which a browser following a link does not send.

## Results: php-shop (blind)

Three blind runs (plugin 0.23.0, cotcha-trail 0.20.0), same instructions as the other apps. Recall 100%, 100%, 100%. Precision 100%. Trap false positives 0/8 in every run. All 11 findings confirmed in each run, the same outcome for 19/19 items, mean Jaccard 1.00. Every run followed the search query through the repository interface into the SQL string, noted that `unserialize` had no `allowed_classes` limit, and judged the `escapeshellarg` + allow-list report command safe. No run tripped over `reason`/`reasoning` (accepted as an alias since 0.22.1).

## Results: ruby-shop (blind)

Three blind runs (plugin 0.24.0, cotcha-trail 0.21.0), same instructions as the other apps. Recall 100%, 100%, 100%. Precision 100%. Trap false positives 0/7 in every run. All 11 findings confirmed in each run, the same outcome for 18/18 items, mean Jaccard 1.00. Every run recognized the `Kernel#open` pipe (`|cmd`) as command injection, noted that `allow_other_host: true` turns off Rails 7's redirect protection, and judged the allow-listed `system('pg_dump', ...)` with separate arguments safe.

## Results: cs-shop (blind)

Three blind runs (plugin 0.25.0, cotcha-trail 0.22.0), same instructions as the other apps. Recall 100%, 100%, 100%. Precision 100%. Trap false positives 0/8 in every run. All 11 findings confirmed in each run, the same outcome for 19/19 items, mean Jaccard 1.00. Every run told `FromSqlRaw` (vulnerable) apart from `FromSqlInterpolated` (parameterized), flagged JSON.NET only because of `TypeNameHandling.Auto` and `XmlDocument` only because of `XmlUrlResolver`, and followed the search query through the repository interface injected by the primary constructor. All three also noticed that the JWT setup skips issuer and audience checks and chose not to report it, since the signing key is still validated.

## Results: OWASP Juice Shop (real-world, blind)

A real application, not one written for this benchmark. [`juice-shop/prepare.py`](juice-shop/prepare.py) makes a blind copy of [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (commit `c9f9922`). Juice Shop marks its vulnerable lines with `vuln-code-snippet` comments; the script blanks those comments (line numbers unchanged) and removes the challenge list, solutions, code-fix explanations, tests and AI-assistant folders. [`juice-shop/juice-shop.expected.json`](juice-shop/juice-shop.expected.json) is built from the same markers: 18 code items (SQL/NoSQL injection, XSS, redirects, missing authorization, passkeys, rate limiting, mass assignment…) and 4 frontend hidden-route items. IaC, web3 and security-question items are left out. There are no traps, so precision against the key means little: Juice Shop has many more real vulnerabilities than its markers.

Running the engine on it first exposed gaps the small apps never hit, fixed in cotcha-trail 0.23.0: handler factories (`app.post('/login', login())`), path-scoped `app.use` middleware as guards, infrastructure middleware out of guards, NoSQL `update`. Entry points went from 17 to 99.

Three blind runs (plugin 0.25.1), each ~220k tokens and ~18 minutes, 58–64 confirmed findings each:

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Code items found (18) | 16 | 16 | 14 |
| Hidden-route items (4) | 0 | 0 | 0 |
| Recall against the key as written | 64% | 64% | 55% |

- The scorer's numbers are lower than the "found" row because the key points the MD5 password hash at its caller (`models/user.ts:73`) and the admin registration at `server.ts:550`, while the runs reported the hash function (`lib/insecurity.ts:41`) and the mass-assignment line nearby. With those two ranges widened, the runs score 73%, 73% and 59%.
- Missed in every run: the outdated crypto-address entries in the redirect allow-list (a stale-config issue) and `/metrics` exposed without authentication. Run 3 also missed both passkey flaws. No run reported the four frontend hidden routes (they are security through obscurity, not code flaws).
- Beyond the key, each run reported about 45 more issues, almost all real Juice Shop vulnerabilities: `eval` of the username, JWT `alg: none` / key confusion, hardcoded RSA key, XXE, Zip Slip, YAML deserialization, SSRF, basket and address IDOR, `$where` NoSQL injection, null-byte file bypass, free deluxe upgrade, password change without the old password, stored and DOM XSS, CSRF.
- Engine gaps the runs pointed out: finale-rest's generated `/api/*` routes and `app.use('/ftp', serveIndex(...))`-style static routes were not listed as entry points; the runs covered them by reading `server.ts`. Fixed in cotcha-trail 0.24.0 (entry points 99 → 175, including `/ftp`, `/encryptionkeys`, `/support/logs` and `/metrics`), and plugin 0.25.2 tells the planner to check operational endpoints (metrics, logs, directory listings, debug pages) for missing authentication. These runs predate both changes.

### Second round (plugin 0.25.3, cotcha-trail 0.25.0)

After the engine fixes above (finale-rest routes, path-scoped `app.use` endpoints, middleware order) and the new operational-endpoint guidance, three more blind runs on a freshly prepared copy (the first copy still had `SOLUTIONS.md` and other hint files because `prepare.py` stopped on a long Windows path; the script now handles long paths). Each run took ~20 minutes and ~200k tokens.

The key now has `alsoAt` for items whose flaw shows in two places, and the scorer accepts either: `/metrics` is registered twice and only the first registration (`server.ts:715`, before the Angular catch-all) is reachable; the redirect allow-list bypass can be reported at the `includes()` check or at `res.redirect`; the MD5 hash at the hash function; admin registration at the `role` attribute of the user model.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Confirmed findings | 61 | 68 | 58 |
| Code items found (18) | 13 | 15 | 15 |
| Hidden-route items (4) | 0 | 0 | 0 |
| Recall (22 items) | 59% | 68% | 68% |

- Found in every run now: `/metrics` without authentication (0/3 before), plus `/ftp`, `/encryptionkeys` and `/support/logs` listings.
- Still missed in every run: the stale crypto-currency addresses in the redirect allow-list.
- Varied between runs: passkey flaws (run 2 only), rate-limit bypass via `X-Forwarded-For` (run 3 only), chatbot coupon (run 3; run 2 reported it as CWE-1039, which the key does not list).
- Consistency 82% (18 of 22 items with the same outcome in all runs), mean Jaccard 0.83.

### Third round (plugin 0.25.4, redirect allow-list guidance)

The guidance now also asks for a bypassable redirect check and for allow-list entries nothing links to any more. Three blind runs, ~20 minutes and ~220k tokens each (run 3's first pass stopped before its verdicts and was resumed to finish them). The key gained `server.ts:540` (the finale resource that creates `POST /api/Users`) as another location for admin registration, and CWE-1426 for the chatbot coupon.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Confirmed findings | 65 | 45 | 58 |
| Code items found (18) | 15 | 14 | 17 |
| Hidden-route items (4) | 0 | 0 | 0 |
| Recall (22 items) | 68% | 64% | 77% |

- The stale crypto-currency entries in the redirect allow-list were found for the first time (run 1). The frontend still has the links, but only inside `@if (false)` blocks; runs 2 and 3 saw the links and called the entries in use. The guidance now says links in UI that never renders do not count.
- Found in every run: `/metrics`, `/ftp`, `/encryptionkeys`, `/support/logs`, the `includes()` redirect bypass, the X-Forwarded-For rate-limit bypass.
- Varied: passkey flaws and the chatbot coupon (run 3 only).
- Consistency 82%, mean Jaccard 0.84. No run reported the four hidden frontend routes.

### Fourth round (plugin 0.25.5, links in UI that never renders)

Same instructions; the only change is the sentence that links in UI that never renders (`@if (false)` and the like) do not keep an allow-list entry in use. ~20 minutes and ~220–270k tokens per run. The key also accepts `server.ts:440` (the registration pre-handler that passes the body to finale) for admin registration.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Confirmed findings | 69 | 74 (+2 uncertain) | 57 |
| Code items found (18) | 18 | 16 | 15 |
| Hidden-route items (4) | 0 | 0 | 0 |
| Recall (22 items) | 82% | 73% | 68% |

- The stale redirect allow-list entries were found in every run (1 of 3 in the third round, 0 of 3 before). Run 1 found every code item in the key.
- Varied: passkey flaws (run 1 only), chatbot coupon (runs 1 and 2).
- Consistency 86% (19 of 22 items), mean Jaccard 0.89. No run reported the four hidden frontend routes; they are security through obscurity rather than a code flaw, and the instructions do not ask for them.

### Fifth round (plugin 0.25.6, passkey / OTP / OAuth guidance)

The only change: read passkey (WebAuthn), OTP and OAuth handlers to the end (credential saved for the session user, existing credential ids not re-bound, session only after a verified signature, failures that fall through to the token). ~19 minutes and ~220–245k tokens per run.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Confirmed findings | 64 (1 rejected) | 64 | 66 |
| Code items found (18) | 17 | 17 | 18 |
| Hidden-route items (4) | 0 | 0 | 0 |
| Recall (22 items) | 77% | 77% | 82% |

- Both passkey flaws were found in every run (1 of 3 in the fourth round). Run 1 also checked and rejected an origin taken from `X-Forwarded-Host`, since the authenticator only signs for the real origin.
- Misses: admin registration in run 1 (reported one line off, at the Product entry of the generated-model list), chatbot coupon in run 2. Run 3 found every code item.
- Consistency 91% (20 of 22 items), mean Jaccard 0.93.

Across the rounds (same key, same instructions; each round changed one piece of guidance):

| Round | Plugin | Recall (mean, min–max) | Consistency |
|---|---|---|---|
| 2 | 0.25.3 | 65% (59–68%) | 82% |
| 3 | 0.25.4 | 70% (64–77%) | 82% |
| 4 | 0.25.5 | 74% (68–82%) | 86% |
| 5 | 0.25.6 | 79% (77–82%) | 91% |

The 4 hidden frontend routes are never reported, so 82% (18 of 22) is the ceiling for the code items.

### Sixth round (plugin 0.25.7, cotcha-trail 0.25.1)

No guidance change. cotcha-trail 0.25.1 fixes a slow path in the Node analyzer (each function's local names were rebuilt on every call lookup, which was quadratic in Juice Shop's large `server.ts`): loading the repository went from ~2 minutes to ~12 seconds, and each run from ~19 to ~10–11 minutes (~230–245k tokens).

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Confirmed findings | 78 | 72 | 60 (1 rejected) |
| Code items found (18) | 18 | 18 | 18 |
| Hidden-route items (4) | 0 | 0 | 0 |
| Recall (22 items) | 82% | 82% | 82% |

- Every run found every code item in the key; consistency 100% (all 22 items with the same outcome), mean Jaccard 1.00.
- Run 2 said most of its verdict reasons were generic text written in one batch, so its confirmations carry less weight than the others'.

| Round | Plugin | Recall (mean, min–max) | Consistency | Minutes per run |
|---|---|---|---|---|
| 6 | 0.25.7 | 82% (82–82%) | 100% | ~10–11 |

### Seventh round (plugin 0.26.0, independent verification)

Plugin 0.26.0 asks for verifier subagents that did not investigate, records `verifier` on each verdict, and rejects reasoning without a re-read `file:line` or that only repeats the finding. The run instructions changed in one step: "verify as SKILL.md section 3 describes" instead of "re-verify every finding yourself", and any subagent gets the same blind rules.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Findings recorded | 88 | 70 | 91 |
| Confirmed / rejected / uncertain | 88 / 0 / 0 | 69 / 0 / 1 | 89 / 1 / 1 |
| Verifier subagents (all verdicts independent) | 6 | 5 | 7 |
| Code items found (18) | 18 | 18 | 17 |
| Recall (22 items) | 82% | 82% | 77% |
| Wall time | ~3 h 10 min | ~3 h 10 min | ~3 h 17 min |

- Every run also split the investigation across 4–5 subagents and used separate verifier subagents; all 249 verdicts are `independent`, each with its own reasoning (240–500 characters on average, no repeated text).
- The verifiers lowered many severities (14 in run 2) and marked library-dependent findings uncertain (finale-rest PATCH, the transitive `jws` version), but rejected almost nothing (2 of 249).
- Run 3 folded the stale redirect allow-list entries into the `includes()` finding instead of recording them separately, so that item counts as missed.
- Cost: about 18 times the wall time of round 6 (~10–11 min); the token count reported for each run covers only its top-level agent, not the subagents. Independent verification is worth it when the findings must be trusted, but it is not free.
- Consistency 95% (21 of 22 items), mean Jaccard 0.96.

---

# 벤치마크

이 플러그인으로 한 보안 분석이 취약점을 얼마나 잘 찾는지, 같은 코드를 다시 분석해도 같은 결론을 내는지 재는 평가 하네스다. cotcha-net 에도 같은 벤치마크가 있고 거기서는 `run.py` 가 백엔드를 돌린다. 여기서는 Claude Code 에서 분석하고 내보낸 SARIF 를 채점한다.

| 파일 | 내용 |
|---|---|
| `shop-app/` | 작은 Spring + React 쇼핑몰. **진짜 취약점 11개**와 비슷하게 생겼지만 **안전한 코드 10개**(함정)를 섞었다. 취약한 곳마다 같은 분류의 안전한 짝이 있다. 코드에 힌트 주석은 없다. |
| `node-shop/` | Node.js(Express) 쇼핑몰 API. **진짜 취약점 12개**와 **안전한 함정 9개**, Node 에만 있는 것(NoSQL 연산자 주입, 프로토타입 오염, `node-serialize`)도 들어 있다. 힌트 주석은 없다. |
| `node-shop.expected.json` | 그 정답 파일. 형식이 같고 역시 앱 폴더 밖에 둔다. |
| `go-shop/` | Go(gin + database/sql) 쇼핑몰 API. **진짜 취약점 11개**와 **안전한 함정 8개**, Go 에만 있는 것(`template.HTML`, 템플릿 주입, `InsecureSkipVerify`, 저장소 인터페이스 호출)도 들어 있다. |
| `go-shop.expected.json` | 그 정답 파일. |
| `php-shop/` | PHP(Laravel) 쇼핑몰 API. **진짜 취약점 11개**와 **안전한 함정 8개**, PHP 에만 있는 것(`unserialize`, `LIBXML_NOENT` XXE, `eval`, 저장소 인터페이스 호출)도 들어 있다. |
| `php-shop.expected.json` | 그 정답 파일. |
| `ruby-shop/` | Ruby(Rails) 쇼핑몰 API. **진짜 취약점 11개**와 **안전한 함정 7개**, Ruby 에만 있는 것(`Kernel#open` 파이프, `Marshal.load`, ERB 템플릿 주입, `html_safe`, `allow_other_host: true`)도 들어 있다. |
| `ruby-shop.expected.json` | 그 정답 파일. |
| `cs-shop/` | C#(ASP.NET Core) 쇼핑몰 API. **진짜 취약점 11개**와 **안전한 함정 8개**, .NET 에만 있는 것(`FromSqlRaw` 와 `FromSqlInterpolated`, JSON.NET `TypeNameHandling`, `XmlUrlResolver`, `CSharpScript`, `Redirect` 와 `LocalRedirect`)도 들어 있다. |
| `cs-shop.expected.json` | 그 정답 파일. |
| `shop-app.expected.json` | 정답 파일. 항목마다 파일, 줄 범위, 위험 지점 줄, 인정하는 CWE, 진입점을 적었다. Claude 가 분석 중에 읽지 못하도록 `shop-app/` **밖**에 둔다. |
| `score.py` | SARIF 보고서를 정답과 비교해 채점한다. 재현율, 정밀도, 함정 오탐, 분류 틀림, 중복, 그리고 여러 번 돌렸으면 일관성. |
| `test_score.py` | 채점 규칙 테스트. |

`BenchmarkTest`(`./gradlew test` 에 포함, CI 에서 돈다)는 앱마다 정답의 취약점과 함정이 모두 `list_sinks` 에 나오고 그 밖의 것은 없으며, 진입점이 있는 취약점은 `list_sink_paths` 에도 나오는지 확인한다.

## 분석 채점하기 (수동)

1. 실행마다 Claude Code 새 세션에서 "`<절대 경로>/benchmark/shop-app` 보안 취약점 분석해줘"라고 하고 계획을 승인한다.
2. 끝나면 `export_report` 를 `format: sarif` 로 불러 `report-1.sarif` 로 저장한다. 다음 실행 전에 `clear_findings` 로 발견을 비운다.
3. 채점한다.

```bash
python benchmark/score.py benchmark/shop-app.expected.json report-1.sarif report-2.sarif report-3.sarif
python benchmark/score.py benchmark/shop-app.expected.json report-*.sarif --confirmed-only
```

규칙: 발견의 위치 중 하나가 항목의 파일·줄 범위 안에 있으면 그 항목을 가리킨 것이다. CWE 가 인정 목록에 있으면 맞힌 것, 다르면 분류 틀림이다. 함정을 가리키면 함정 오탐, 아무것도 가리키지 않으면 기타 오탐이다. 기각된 발견은 빼고 센다. 일관성은 모든 실행에서 같은 결론이 난 항목의 비율과 실행 간 평균 자카드 유사도다.

## 결과: node-shop (블라인드)

블라인드로 3번 돌렸다(플러그인 0.21.0, cotcha-trail 0.18.0). 실행마다 다른 에이전트가 `node-shop/` 복사본을 플러그인 도구로 분석했고, 정답 파일은 읽을 수 없었다. `check_dependencies` 는 쓰지 않았다.

- 재현율 100%, 100%, 100%. 정밀도 100%. 함정 오탐은 매번 0/9. 21개 항목 모두 세 번 같은 결론, 평균 자카드 1.00.
- 처음 채점할 때 분석이 아니라 정답 파일에서 버그 두 개가 나와서 고쳤다. 세 번 모두 재설정 토큰을 CWE-330 으로 보고했는데, 정답은 CWE-338 만 인정했다(shop-app 정답은 330·338·340 을 인정한다). 또 함정 하나의 줄 범위가 처리기 전체를 덮어서, CWE 가 다른 그 발견이 함정 오탐으로 잡혔다.
- 세 번 모두 lodash `^4.17.21` 은 `merge` 에서 `__proto__` 를 이미 막는다고 짚어서, 프로토타입 오염 항목을 불확실·낮음으로만 남겼다. 그래서 `package.json` 에서 lodash 를 4.17.4 로 고정했다. 이 버전의 `merge` 는 공격할 수 있다(4.17.5 에서 고쳐짐).

**고친 앱으로 다시 돌린 결과 (lodash 4.17.4):** 같은 지시로 블라인드 3번을 새로 돌렸다. 재현율 100%, 100%, 100%. 정밀도 100%. 함정 오탐은 매번 0/9. 실행마다 발견 12개를 모두 확정했고, 프로토타입 오염도 이제 불확실이 아니라 높음으로 확정한다. 21개 항목 모두 세 번 같은 결론, 평균 자카드 1.00(`--confirmed-only` 로도 같다).

## 결과: go-shop (블라인드)

node-shop 과 같은 지시로 블라인드 3번을 돌렸다(플러그인 0.22.0, cotcha-trail 0.19.0). 재현율 100%, 100%, 100%. 정밀도 100%. 함정 오탐은 매번 0/8. 실행마다 발견 11개를 모두 확정했고, 19개 항목 모두 세 번 같은 결론, 평균 자카드 1.00. 세 번 모두 검색어를 `Store` 인터페이스를 거쳐 SQL 문자열까지 따라갔고, 결제 상태 요청은 호스트가 설정 값이고 id 를 이스케이프해서 안전하다고 봤다. 두 번은 `template.HTML` XSS 를 낮음으로 내렸다. 그 라우트는 Bearer 헤더가 필요해서, 링크를 따라간 브라우저는 그 헤더를 보내지 않기 때문이다.

## 결과: php-shop (블라인드)

다른 앱과 같은 지시로 블라인드 3번을 돌렸다(플러그인 0.23.0, cotcha-trail 0.20.0). 재현율 100%, 100%, 100%. 정밀도 100%. 함정 오탐은 매번 0/8. 실행마다 발견 11개를 모두 확정했고, 19개 항목 모두 세 번 같은 결론, 평균 자카드 1.00. 세 번 모두 검색어를 저장소 인터페이스를 거쳐 SQL 문자열까지 따라갔고, `unserialize` 에 `allowed_classes` 제한이 없다고 짚었으며, `escapeshellarg` + 허용 목록을 쓰는 리포트 명령은 안전하다고 봤다. `reason`·`reasoning` 인자 실수는 한 번도 없었다(0.22.1 부터 별칭으로 받는다).

## 결과: ruby-shop (블라인드)

다른 앱과 같은 지시로 블라인드 3번을 돌렸다(플러그인 0.24.0, cotcha-trail 0.21.0). 재현율 100%, 100%, 100%. 정밀도 100%. 함정 오탐은 매번 0/7. 실행마다 발견 11개를 모두 확정했고, 18개 항목 모두 세 번 같은 결론, 평균 자카드 1.00. 세 번 모두 `Kernel#open` 파이프(`|명령`)를 명령 주입으로 봤고, `allow_other_host: true` 가 Rails 7 의 리다이렉트 보호를 끈다고 짚었으며, 허용 목록과 인자를 나눈 `system('pg_dump', ...)` 은 안전하다고 봤다.

## 결과: cs-shop (블라인드)

다른 앱과 같은 지시로 블라인드 3번을 돌렸다(플러그인 0.25.0, cotcha-trail 0.22.0). 재현율 100%, 100%, 100%. 정밀도 100%. 함정 오탐은 매번 0/8. 실행마다 발견 11개를 모두 확정했고, 19개 항목 모두 세 번 같은 결론, 평균 자카드 1.00. 세 번 모두 `FromSqlRaw`(취약)와 `FromSqlInterpolated`(매개변수화)를 구분했고, JSON.NET 은 `TypeNameHandling.Auto` 때문에, `XmlDocument` 는 `XmlUrlResolver` 때문에만 취약하다고 봤으며, 기본 생성자로 주입한 저장소 인터페이스를 거쳐 검색어를 따라갔다. 세 번 모두 JWT 설정이 발급자·대상 검사를 끈 것도 봤지만, 서명 키는 검사하므로 보고하지 않았다.

## 결과: OWASP Juice Shop (실제 앱, 블라인드)

이 벤치마크용으로 만든 앱이 아니라 실제 앱이다. [`juice-shop/prepare.py`](juice-shop/prepare.py) 가 [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)(커밋 `c9f9922`)의 블라인드 사본을 만든다. Juice Shop 은 취약한 줄에 `vuln-code-snippet` 주석을 달아 두는데, 스크립트가 그 주석을 줄 번호 그대로 지우고 문제 목록·풀이·코드 수정 해설·테스트·AI 도구 폴더를 뺀다. [`juice-shop/juice-shop.expected.json`](juice-shop/juice-shop.expected.json) 은 같은 주석에서 뽑았다: 코드 항목 18개(SQL·NoSQL 주입, XSS, 리다이렉트, 권한 누락, passkey, 횟수 제한, 대량 할당…)와 프런트 숨긴 라우트 4개. IaC·web3·보안 질문 항목은 뺐다. 함정이 없어서 정답 기준 정밀도는 의미가 적다: Juice Shop 에는 표시된 것보다 훨씬 많은 진짜 취약점이 있다.

엔진을 먼저 돌려 보니 작은 앱에서는 안 나오던 빈틈이 드러나서 cotcha-trail 0.23.0 에서 고쳤다: 처리기를 만드는 함수(`app.post('/login', login())`), 경로를 준 `app.use` 미들웨어를 guards 로, 기반 미들웨어는 guards 에서 뺌, NoSQL `update`. 진입점이 17개에서 99개로 늘었다.

블라인드 3번(플러그인 0.25.1), 실행마다 약 22만 토큰·18분, 확정 발견 58~64개:

| | 1번 | 2번 | 3번 |
|---|---|---|---|
| 코드 항목 찾음 (18개) | 16 | 16 | 14 |
| 숨긴 라우트 항목 (4개) | 0 | 0 | 0 |
| 정답 그대로 채점한 재현율 | 64% | 64% | 55% |

- 채점 숫자가 "찾음" 줄보다 낮은 건, 정답이 MD5 비밀번호 해시를 호출하는 줄(`models/user.ts:73`)에, 관리자 가입을 `server.ts:550` 에 두었는데 실행들은 해시 함수(`lib/insecurity.ts:41`)와 근처의 대량 할당 줄에 보고했기 때문이다. 이 두 범위를 넓히면 73%, 73%, 59% 다.
- 세 번 모두 놓친 것: 리다이렉트 허용 목록에 남은 옛 암호화폐 주소(오래된 설정 문제)와 인증 없이 열린 `/metrics`. 3번은 passkey 문제 두 개도 놓쳤다. 숨긴 프런트 라우트 4개는 어느 실행도 보고하지 않았다(코드 결함이 아니라 숨겨서 지키는 방식이다).
- 정답 밖으로 실행마다 45개쯤 더 보고했고 거의 모두 Juice Shop 의 진짜 취약점이다: 사용자 이름 `eval`, JWT `alg: none`·키 혼동, 하드코딩한 RSA 키, XXE, Zip Slip, YAML 역직렬화, SSRF, 장바구니·주소 IDOR, `$where` NoSQL 주입, 널 바이트 파일 우회, 무료 디럭스 등급, 기존 비밀번호 없는 비밀번호 변경, 저장형·DOM XSS, CSRF.
- 실행들이 짚은 엔진 빈틈: finale-rest 가 만드는 `/api/*` 라우트와 `app.use('/ftp', serveIndex(...))` 같은 정적 경로가 진입점 목록에 없었다. 실행들은 `server.ts` 를 직접 읽어 다뤘다. cotcha-trail 0.24.0 에서 고쳤고(진입점 99 → 175, `/ftp`·`/encryptionkeys`·`/support/logs`·`/metrics` 포함), 플러그인 0.25.2 는 계획 단계에서 운영용 엔드포인트(지표, 로그, 디렉터리 목록, 디버그 페이지)의 인증 누락을 보게 한다. 위 실행들은 두 변경 전이다.

### 2회차 (플러그인 0.25.3, cotcha-trail 0.25.0)

위 엔진 수정(finale-rest 라우트, 경로를 준 `app.use` 끝점, 미들웨어 순서)과 운영용 엔드포인트 지침을 넣은 뒤, 새로 만든 사본으로 블라인드 3번을 더 돌렸다(첫 사본은 `prepare.py` 가 Windows 긴 경로에서 멈춰 `SOLUTIONS.md` 같은 힌트 파일이 남아 있었다. 지금은 긴 경로도 처리한다). 실행마다 약 20분·20만 토큰.

같은 약점이 두 곳에 드러나는 항목은 정답에 `alsoAt` 을 두고 채점기가 둘 다 받는다: `/metrics` 는 두 번 등록되는데 Angular catch-all 앞의 첫 등록(`server.ts:715`)만 닿는다. 리다이렉트 허용 목록 우회는 `includes()` 검사나 `res.redirect` 어느 쪽에 보고해도 된다. MD5 는 해시 함수에, 관리자 가입은 사용자 모델의 `role` 속성에 보고해도 된다.

| | 1번 | 2번 | 3번 |
|---|---|---|---|
| 확정 발견 | 61 | 68 | 58 |
| 코드 항목 찾음 (18개) | 13 | 15 | 15 |
| 숨긴 라우트 항목 (4개) | 0 | 0 | 0 |
| 재현율 (22개) | 59% | 68% | 68% |

- 이제 세 번 모두 찾음: 인증 없는 `/metrics`(전에는 0/3), `/ftp`·`/encryptionkeys`·`/support/logs` 목록.
- 여전히 세 번 모두 놓침: 리다이렉트 허용 목록에 남은 옛 암호화폐 주소.
- 실행마다 다름: passkey 문제(2번만), `X-Forwarded-For` 로 횟수 제한 우회(3번만), 챗봇 쿠폰(3번. 2번은 정답에 없는 CWE-1039 로 보고).
- 일관성 82%(22개 중 18개가 모든 실행에서 같은 결론), 평균 자카드 0.83.

### 3회차 (플러그인 0.25.4, 리다이렉트 허용 목록 지침)

지침에 우회되는 리다이렉트 검사와, 아무도 링크하지 않는 허용 목록 항목을 보라는 내용을 더했다. 블라인드 3번, 실행마다 약 20분·22만 토큰(3번은 첫 실행이 판정 전에 멈춰 이어서 마쳤다). 정답에는 관리자 가입의 다른 위치로 `server.ts:540`(`POST /api/Users` 를 만드는 finale resource)을, 챗봇 쿠폰에 CWE-1426 을 더했다.

| | 1번 | 2번 | 3번 |
|---|---|---|---|
| 확정 발견 | 65 | 45 | 58 |
| 코드 항목 찾음 (18개) | 15 | 14 | 17 |
| 숨긴 라우트 항목 (4개) | 0 | 0 | 0 |
| 재현율 (22개) | 68% | 64% | 77% |

- 리다이렉트 허용 목록의 옛 암호화폐 주소를 처음 찾았다(1번). 프런트엔드에 링크가 남아 있지만 `@if (false)` 안에만 있다. 2·3번은 링크를 보고 쓰는 항목이라고 판단했다. 그래서 그려지지 않는 화면의 링크는 쓰는 것이 아니라고 지침에 더했다.
- 세 번 모두 찾음: `/metrics`, `/ftp`, `/encryptionkeys`, `/support/logs`, `includes()` 리다이렉트 우회, X-Forwarded-For 횟수 제한 우회.
- 실행마다 다름: passkey 문제와 챗봇 쿠폰(3번만).
- 일관성 82%, 평균 자카드 0.84. 숨긴 프런트 라우트 4개는 어느 실행도 보고하지 않았다.

### 4회차 (플러그인 0.25.5, 그려지지 않는 화면의 링크)

지시는 같고, 바뀐 것은 그려지지 않는 화면(`@if (false)` 등)의 링크는 허용 목록 항목을 쓰는 것이 아니라는 한 문장뿐이다. 실행마다 약 20분·22만~27만 토큰. 정답은 관리자 가입 위치로 `server.ts:440`(요청 본문을 finale 에 넘기는 가입 전처리기)도 받는다.

| | 1번 | 2번 | 3번 |
|---|---|---|---|
| 확정 발견 | 69 | 74 (+불확실 2) | 57 |
| 코드 항목 찾음 (18개) | 18 | 16 | 15 |
| 숨긴 라우트 항목 (4개) | 0 | 0 | 0 |
| 재현율 (22개) | 82% | 73% | 68% |

- 리다이렉트 허용 목록의 옛 항목을 세 번 모두 찾았다(3회차 1/3, 그 전 0/3). 1번은 정답의 코드 항목을 모두 찾았다.
- 실행마다 다름: passkey 문제(1번만), 챗봇 쿠폰(1·2번).
- 일관성 86%(22개 중 19개), 평균 자카드 0.89. 숨긴 프런트 라우트 4개는 어느 실행도 보고하지 않았다. 코드 결함이 아니라 숨겨서 지키는 방식이고 지시에서도 찾으라고 하지 않는다.

### 5회차 (플러그인 0.25.6, passkey·OTP·OAuth 지침)

바뀐 것은 하나: passkey(WebAuthn)·OTP·OAuth 처리기를 끝까지 읽으라는 지침(자격 증명은 세션 사용자에게, 기존 자격 증명 id 를 다시 묶지 않음, 서명 검증이 성공했을 때만 세션, 실패가 토큰 발급으로 넘어가는 곳). 실행마다 약 19분·22만~24.5만 토큰.

| | 1번 | 2번 | 3번 |
|---|---|---|---|
| 확정 발견 | 64 (기각 1) | 64 | 66 |
| 코드 항목 찾음 (18개) | 17 | 17 | 18 |
| 숨긴 라우트 항목 (4개) | 0 | 0 | 0 |
| 재현율 (22개) | 77% | 77% | 82% |

- passkey 문제 두 개를 세 번 모두 찾았다(4회차 1/3). 1번은 `X-Forwarded-Host` 로 만든 origin 도 살펴봤지만, 인증기가 실제 origin 에만 서명하므로 기각했다.
- 놓친 것: 1번의 관리자 가입(자동 생성 모델 목록의 Product 줄로 한 줄 어긋나게 보고), 2번의 챗봇 쿠폰. 3번은 코드 항목을 모두 찾았다.
- 일관성 91%(22개 중 20개), 평균 자카드 0.93.

회차별(같은 정답·같은 지시, 회차마다 지침 하나만 바꿈):

| 회차 | 플러그인 | 재현율 (평균, 최저~최고) | 일관성 |
|---|---|---|---|
| 2 | 0.25.3 | 65% (59~68%) | 82% |
| 3 | 0.25.4 | 70% (64~77%) | 82% |
| 4 | 0.25.5 | 74% (68~82%) | 86% |
| 5 | 0.25.6 | 79% (77~82%) | 91% |

숨긴 프런트 라우트 4개는 보고되지 않으므로 코드 항목만으로는 82%(22개 중 18개)가 상한이다.

### 6회차 (플러그인 0.25.7, cotcha-trail 0.25.1)

지침은 그대로. cotcha-trail 0.25.1 이 Node 분석기의 느린 부분을 고쳤다(함수마다 지역 이름 표를 호출을 풀 때마다 다시 만들어서, Juice Shop 의 큰 `server.ts` 에서 제곱으로 느려졌다). 저장소 불러오기가 약 2분에서 약 12초로, 실행 한 번이 약 19분에서 약 10~11분(23만~24.5만 토큰)으로 줄었다.

| | 1번 | 2번 | 3번 |
|---|---|---|---|
| 확정 발견 | 78 | 72 | 60 (기각 1) |
| 코드 항목 찾음 (18개) | 18 | 18 | 18 |
| 숨긴 라우트 항목 (4개) | 0 | 0 | 0 |
| 재현율 (22개) | 82% | 82% | 82% |

- 세 번 모두 정답의 코드 항목을 다 찾았다. 일관성 100%(22개 모두 같은 결론), 평균 자카드 1.00.
- 2번은 판정 이유 대부분을 한 번에 일반 문구로 썼다고 밝혔으니, 그 확정은 다른 실행보다 가볍게 본다.

| 회차 | 플러그인 | 재현율 (평균, 최저~최고) | 일관성 | 실행당 시간 |
|---|---|---|---|---|
| 6 | 0.25.7 | 82% (82~82%) | 100% | 약 10~11분 |

### 7회차 (플러그인 0.26.0, 독립 검증)

플러그인 0.26.0 은 조사하지 않은 검증 서브에이전트를 쓰게 하고, 판정마다 `verifier` 를 남기고, 다시 읽은 `파일:줄`이 없거나 발견을 되풀이한 근거는 받지 않는다. 실행 지시는 한 단계만 바꿨다: "직접 다시 검증" 대신 "SKILL.md 3절대로 검증", 그리고 서브에이전트에도 같은 블라인드 규칙을 넘긴다.

| | 1번 | 2번 | 3번 |
|---|---|---|---|
| 기록한 발견 | 88 | 70 | 91 |
| 확정 / 기각 / 판단 불가 | 88 / 0 / 0 | 69 / 0 / 1 | 89 / 1 / 1 |
| 검증 서브에이전트 (판정 모두 독립) | 6 | 5 | 7 |
| 코드 항목 찾음 (18개) | 18 | 18 | 17 |
| 재현율 (22개) | 82% | 82% | 77% |
| 걸린 시간 | 약 3시간 10분 | 약 3시간 10분 | 약 3시간 17분 |

- 세 실행 모두 조사도 서브에이전트 4~5개로 나눴고, 검증은 따로 띄운 검증 서브에이전트가 했다. 판정 249개가 모두 `independent` 이고 근거도 모두 달랐다(평균 240~500자, 같은 문장 없음).
- 검증 쪽은 심각도를 많이 낮추고(2번은 14개) 라이브러리에 달린 발견은 판단 불가로 두었지만(finale-rest PATCH, 간접 의존성 `jws` 버전), 기각은 거의 없었다(249개 중 2개).
- 3번은 리다이렉트 허용 목록의 옛 항목을 `includes()` 발견에 합쳐 적어서 그 항목은 놓친 것으로 센다.
- 비용: 6회차(약 10~11분)의 약 18배 시간. 실행마다 보고된 토큰은 맨 위 에이전트 것만이고 서브에이전트 몫은 빠져 있다. 발견을 믿고 써야 할 때는 독립 검증이 값어치가 있지만 공짜는 아니다.
- 일관성 95%(22개 중 21개), 평균 자카드 0.96.
