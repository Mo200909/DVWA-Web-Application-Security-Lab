# DVWA Web Application Security Lab

A hands-on lab using Damn Vulnerable Web Application (DVWA) in Docker to practice identifying, exploiting, and defending against common web vulnerabilities.

**Security level tested: Low** (DVWA's minimum sanitization tier — noted here so results are read in the right context; Medium/High require actual filter bypass and are not yet covered by this lab).

---

## Setup

```
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Go to `http://localhost/setup.php`, click Create / Reset Database, log in with `admin` / `password`.

**Environment:** DVWA v1.10 "Development," MariaDB backend, tested via browser (no proxy/interception tooling used).

---

## Labs

### Brute Force

**Vulnerability:** No account lockout, no rate limiting, and credentials submitted via GET — exposing them in plaintext in the URL.

Tested the login form with an incorrect password to confirm the error path, then logged in successfully with the correct credentials. The GET-based form means every login attempt appears in the browser's address bar and in server access logs, in plaintext.

**Detection/mitigation notes:** Switching the form to POST removes credentials from the URL and browser history, but doesn't fix the underlying issue — rate limiting and account lockout after N failed attempts (or a backoff/CAPTCHA) are what actually stop brute forcing. Concretely: lock the account (or throttle with exponential backoff) after 5 failed attempts in a rolling 5-minute window, keyed on username, not just source IP — attackers rotate IPs but reuse the same target account. Detection query, expressed generically: `count(failed_login) by src_ip, username where window=5m having count > 5` — this is a standard correlation rule in any SIEM (Splunk `stats count by` / Sentinel KQL `summarize count() by`). The credentials-in-URL issue additionally shows up passively in web server access logs and browser history with zero attacker effort required, which is its own separate finding worth flagging in a real assessment.

---

### Command Injection

**Vulnerability:** The "ping a device" form passes user input directly to a shell command with no sanitization, allowing command chaining.

Submitted a normal IP to confirm baseline behavior, then chained an additional command with `&&` to execute arbitrary shell commands on the server.

```
127.0.0.1 && cat /etc/passwd
```

**Detection/mitigation notes:** The fix is input validation via allow-list, not blacklisting shell metacharacters (blacklists are routinely bypassed with `;`, `|`, backticks, newline, or encoding tricks). Concretely, validate against a strict IPv4/IPv6 pattern before the input ever reaches a shell call — e.g. `^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$` for IPv4 — and reject anything that doesn't fully match, rather than stripping bad characters out. Better still, avoid shelling out at all and use a language-native ping/ICMP library instead of `system()`/`exec()`. On the detection side, this is a process-tree anomaly: a web server worker process (`www-data`/`apache`/`nginx`) spawning `/bin/sh` or `/bin/bash`, which then spawns `cat`, `ping`, or similar, is not normal behavior for that process and is exactly the parent-child relationship EDR tools (e.g. Sysmon Event ID 1 process creation chained to a web server parent) are built to flag.

---

### SQL Injection

**Vulnerability:** The User ID field concatenates raw input into a SQL query with no parameterization, allowing UNION-based injection to read arbitrary columns/tables.

Confirmed the baseline query returns a single user, then used a UNION-based injection to enumerate all users and password hashes, and separately to pull the database version string.

```
' UNION SELECT user, password FROM users #
' UNION SELECT null, version() #
```

**Detection/mitigation notes:** Parameterized queries / prepared statements close this off entirely, e.g. in PHP/MySQLi: `$stmt = $mysqli->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param("i", $id);` — the input is bound as data, never concatenated into the query string, so a payload like `' UNION SELECT...` is treated as a literal (and fails) rather than executed. String concatenation into SQL should never happen regardless of input filtering. On the detection side, a WAF rule matching `UNION\s+SELECT` combined with a comment terminator (`#`, `--`, `/*`) in the same parameter is a standard signature (this is close to what ModSecurity's OWASP CRS rule 942100-series already does). Absent a WAF, the same thing is visible at the log/analytics layer as a request parameter whose length or character composition is a statistical outlier compared to that field's normal baseline (a numeric ID field suddenly containing quotes, keywords, and 40+ characters).

---

## What I Learned

- How the absence of rate limiting and lockout policy — not password strength alone — is what makes brute forcing feasible
- How command injection stems from passing user input to a shell without validation, and why blacklisting specific characters is a weak defense compared to allow-listing expected input format
- How SQL injection via string concatenation can expose an entire database, and why parameterized queries eliminate the vulnerability class rather than just filtering known-bad patterns
- The value of thinking through detection signatures (logs, EDR, WAF rules) alongside the exploit itself, rather than stopping at "it worked"

---

## Disclaimer

This lab was conducted against a local, intentionally vulnerable Docker container (DVWA) for educational purposes only. None of these techniques were used against systems without authorization.

---

## Author

Mofolorunsho Adeleke — [github.com/Mo200909](https://github.com/Mo200909)
