\# STRIDE Threat Model — Juice Shop DevSecOps Pipeline



Architecture reference: Public Internet -> nginx (public-net) -> internal-net -> juice-shop

See docker-compose.yml for the two-container boundary this model assumes.



\## Trust Boundaries



\- TB1 — Public internet / DMZ: between the client browser and nginx.

\- TB2 — Internal network: between nginx and the juice-shop container (no direct host exposure).

\- TB3 — Application / data: within juice-shop, between request handlers and the SQLite datastore.



\## Threat 1 — Spoofing (SQL Injection Login Bypass)



Description: An attacker bypasses login authentication by injecting ' OR 1=1-- into the login form's email field, authenticating as an arbitrary user without knowing any valid credentials. This was confirmed through testing: submitting this payload with any password value against the unmodified login endpoint returned a valid authenticated session for the first matching user account.



Likelihood: High — the payload is publicly documented, requires no special tooling (a browser is sufficient), and the endpoint is reachable without any prior authentication or rate limiting.



Impact: High — full account takeover, including the admin account, since the injected condition matches the first row returned regardless of which account was targeted.



Overall Rating: Critical



Control Applied: Replaced the raw, string-concatenated SQL query with a parameterised query using Sequelize's replacements binding, so user input is always treated as literal data rather than executable SQL syntax.



Where It Lives: juice-shop/routes/login.ts — verified fixed: the identical payload was re-tested after the fix and correctly returned "Invalid email or password," while a legitimate login with correct credentials continued to succeed. The Semgrep SAST gate in the CI/CD pipeline provides ongoing regression coverage against this class of vulnerability.



\## Threat 2 — Elevation of Privilege (Insecure Direct Object Reference on Basket)



Description: An authenticated user can access another user's shopping basket simply by changing the numeric basket ID in the API request. This was confirmed through testing: an authenticated token belonging to basket ID 1 successfully retrieved baskets 2 and 3, which belong to entirely different user accounts.



Likelihood: High — no special tooling is required, only a valid login and the ability to change a number in the request path; the endpoint performed no ownership check prior to the fix.



Impact: High — full disclosure of another user's basket contents, including products and quantities, and the same underlying flaw pattern would extend to order history if left unaddressed elsewhere in the application.



Overall Rating: Critical



Control Applied: Added a server-side authorization check that compares the requested basket ID against the authenticated user's own basket ID, rejecting any mismatch with a 403 Forbidden response.



Where It Lives: juice-shop/routes/basket.ts — verified fixed: after the fix, requests for other users' basket IDs correctly returned "Access to this basket is forbidden," while the user's own basket continued to load normally.



\## Threat 3 — Tampering / Information Disclosure (Stored XSS in Product Review)



Description: Stored XSS in a product review field executes attacker JavaScript in other users' or the admin's browser, enabling session-token theft.



Likelihood: Medium — needs a malicious review submission to be accepted and later viewed by a victim.



Impact: High — session hijack, potentially leading to admin account compromise.



Overall Rating: High



Control Applied: Output encoding of user-supplied review text before rendering, plus input sanitisation on submission.



Where It Lives: juice-shop/routes (review handler) and the frontend render path. Status: identified, assigned to another team member, not yet remediated.



\## Threat 4 — Information Disclosure (Excessive Data Exposure via User API)



Description: An API endpoint returns full user records, including password hashes, instead of only the fields the client actually needs.



Likelihood: Medium — depends on the endpoint being reachable without extra privilege.



Impact: Medium to High — credential exposure at scale if the password hashes are weak.



Overall Rating: High



Control Applied: Response field whitelisting (a DTO or serializer) on user-facing endpoints, and confirming the password hashing algorithm is not a reversible one like MD5.



Where It Lives: juice-shop/routes (user handler). Status: identified, assigned to another team member, not yet remediated.



\## Threat 5 — Denial of Service (Unbounded File Upload)



Description: A large or unbounded file upload (such as a profile image or complaint attachment) can exhaust disk or memory, since no size or type limit is enforced.



Likelihood: Low to Medium — requires authenticated access in most upload flows.



Impact: Medium — service degradation.



Overall Rating: Medium



Control Applied: A file size limit plus a MIME-type allow list enforced server-side before the file is written.



Where It Lives: the upload handler route. Status: identified, not remediated in this iteration.



\## Threat 6 — Repudiation (No Audit Log of Admin Actions)



Description: There is no audit log of admin actions, such as deleting a product or review, so a compromised admin session leaves no trace.



Likelihood: Low — this threat only matters after a prior privilege escalation (see Threat 2) has already occurred.



Impact: Medium — hampers incident response and forensic investigation after a breach.



Overall Rating: Medium



Control Applied: Structured audit logging of privileged mutations, written to storage the application itself cannot modify.



Where It Lives: admin route middleware. Status: identified, not remediated in this iteration (stretch goal).



\## Notes for the Report



Threats 1 and 2 are backed by evidence actually captured during testing (see docs/evidence/): exploit screenshots, the fixed code, and the re-test confirming the fix. Threats 3 and 4 map to the other two team members' assigned vulnerabilities and should be updated the same way once they complete their exploit, fix, and re-test cycle. Threats 5 and 6 are included to show breadth beyond the four vulnerabilities being fully remediated.

