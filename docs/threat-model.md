\# STRIDE Threat Model — Juice Shop DevSecOps Pipeline



Architecture reference: `Public Internet -> nginx (public-net) -> internal-net -> juice-shop`

See `docker-compose.yml` for the two-container boundary this model assumes.



Trust boundaries:

\- \*\*TB1 — Public internet / DMZ\*\*: between the client browser and nginx.

\- \*\*TB2 — Internal network\*\*: between nginx and the juice-shop container (no direct host exposure).

\- \*\*TB3 — Application / data\*\*: within juice-shop, between request handlers and the SQLite datastore.



| # | STRIDE Category | Threat (application-specific) | Likelihood | Impact | Rating | Control (mitigates) | Where it lives |

|---|---|---|---|---|---|---|---|

| 1 | Spoofing | Attacker bypasses login authentication via SQL injection in the login form's email field (`' OR 1=1--`), authenticating as an arbitrary user without knowing any valid credentials — confirmed via testing: submitting this payload with any password value against the unmodified `/rest/user/login` endpoint returned a valid authenticated session for the first matching user account | High — the payload is publicly documented, requires no special tooling (a browser is sufficient), and the endpoint is reachable without any prior authentication or rate limiting | High — full account takeover, including the admin account, since the injected condition (`1=1`) matches the first row returned regardless of which account was targeted | \*\*Critical\*\* | Replaced the raw, string-concatenated SQL query with a parameterised query using Sequelize's `replacements` binding, so user input is always treated as literal data rather than executable SQL syntax | `juice-shop/routes/login.ts` (fix, verified: the identical payload was re-tested post-fix and returned `401 Invalid email or password`, while a legitimate login with correct credentials continued to succeed); `.github/workflows/security-pipeline.yml` SAST gate (Semgrep) provides ongoing regression coverage against this class of vulnerability |

| 2 | Elevation of Privilege | Authenticated user accesses another user's basket by changing the numeric basket ID in the API request (`GET /rest/basket/:id`) — confirmed via testing: an authenticated token for basket ID 1 successfully retrieved baskets 2 and 3, which belong to other user accounts | High — no special tooling required, only a valid login and the ability to increment an integer in the request path; the endpoint performed no ownership check prior to the fix | High — full disclosure of another user's basket contents (products, quantities), and the same pattern would extend to order history if unaddressed elsewhere | \*\*Critical\*\* | Server-side authorization check comparing the requested basket ID against the authenticated user's own basket ID (`user.bid`), rejecting mismatches with `403 Forbidden` | `juice-shop/routes/basket.ts` (fix, verified: `/rest/basket/2` and `/rest/basket/3` returned `403 Access to this basket is forbidden` post-fix, while the user's own basket continued to resolve normally) |

| 3 | Tampering / Information Disclosure | Stored XSS in a product review field executes attacker JS in other users'/admin's browsers, enabling session-token theft | Medium — needs a review submission accepted and viewed by a victim | High — session hijack, admin compromise | \*\*High\*\* | Output encoding of user-supplied review text before rendering; input sanitisation on submit | `juice-shop/routes/\*review\*` handler + frontend render path |

| 4 | Information Disclosure | Excessive data exposure: an API endpoint returns full user records (including password hashes) instead of the fields the client needs | Medium — depends on endpoint reachability without extra privilege | Medium–High — credential exposure at scale if hashes are weak | \*\*High\*\* | Response field whitelisting (DTO/serializer) on user-facing endpoints; confirm password hashing is not reversible MD5 | `juice-shop/routes/\*user\*` |

| 5 | Denial of Service | Large/unbounded file upload (e.g. profile image, complaint attachment) exhausts disk/memory since no size or type limit is enforced | Low–Medium — requires authenticated access in most flows | Medium — service degradation | \*\*Medium\*\* | File size limit + MIME-type allowlist enforced server-side before write | upload handler route |

| 6 | Repudiation | No audit log of admin actions (e.g. deleting a product/review), so a compromised admin session leaves no trace | Low — requires prior privilege escalation (#2) to matter | Medium — hampers incident response | \*\*Medium\*\* | Structured audit logging of privileged mutations, written outside app-writable storage | admin route middleware (stretch goal, optional) |



\*\*Risk matrix key\*\* (5x5 simplified to 3-band): Likelihood {Low, Medium, High} × Impact {Low, Medium, High} → Rating {Low, Medium, High, Critical} where High×High = Critical.



\## Notes for the report

\- Threats #1 and #2 are backed by evidence actually captured during testing (see `docs/evidence/`): exploit screenshots, the fixed code, and the re-test confirming the fix. Threats #3 and #4 map to the other two team members' assigned vulnerabilities and should be updated the same way once they complete their exploit/fix/re-test cycle.

\- Threats #5–#6 are included to show breadth (DoS, Repudiation) beyond the four fully remediated vulnerabilities; noted as "identified, not remediated in this iteration."

