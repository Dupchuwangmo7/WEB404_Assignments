# WEB404 Practical Assignment 1 — Command Injection Report

**Name:** Dupchu Wangmo

## 1. Aim

Develop a web application that demonstrates command injection risks and implement safeguards to prevent untrusted user input from being interpreted as operating-system commands.

## 2. Objectives

- Build a Flask web application with a DNS lookup feature.
- Demonstrate how unsafe shell command construction allows command injection.
- Implement a secure version using Python libraries and subprocess best practices.
- Write 42 automated tests covering valid input, invalid characters, shell metacharacters, injection attempts, and safe error handling.

## 3. Introduction

Command injection occurs when an application passes untrusted user input to an operating-system shell command. If the input is not properly validated and the shell interprets special characters, an attacker can execute arbitrary commands on the server. OWASP classifies injection as one of the most critical web application security risks.

## 4. Background and Command Injection Mechanism

When a web application uses `subprocess.run(f"nslookup {hostname}", shell=True)`, the user-supplied `hostname` is embedded directly into a shell command string. Shell metacharacters like `;`, `&&`, `|`, and backticks have special meaning:

- `;` — terminates the current command and starts a new one
- `&&` — runs the next command if the first succeeds
- `|` — pipes output to another command
- `\`cmd\`` or `$(cmd)` — executes cmd and substitutes its output

An attacker entering `google.com; cat /etc/passwd` would cause the shell to run both `nslookup google.com` AND `cat /etc/passwd`.

## 5. Tools and Technologies

| Component | Technology |
|-----------|-----------|
| Language | Python 3 |
| Framework | Flask 3.1.1 |
| CSRF protection | Flask-WTF 1.2.2 |
| Testing | pytest 8.3.5 |
| DNS resolution | Python socket library |
| OS | macOS (MacBook Air M4) |

## 6. System Requirements and Lab Environment

The application runs entirely on localhost. No external servers, Kali Linux, or Docker are required. Python 3.10+ and pip are the only prerequisites.

## 7. Project Structure

```
Assignment1_Command-Injection/
├── app/
│   ├── __init__.py
│   ├── routes.py          # Flask routes (secure endpoint only)
│   ├── security.py        # Validation, safe_lookup, safe_ping, vulnerable_lookup
│   └── templates/
│       └── index.html     # DNS lookup form
├── tests/
│   └── test_command_injection.py   # 42 automated tests
├── screenshots/
├── report/
│   └── command-injection-report.md
├── requirements.txt
└── README.md
```

![Project structure](../screenshots/01-project-structure.png)

## 8. Methodology

1. Built a vulnerable function (`vulnerable_lookup`) that uses `shell=True` with string concatenation — isolated in the test module, never exposed as a web route.
2. Built a secure function (`safe_lookup`) that uses Python's `socket.gethostbyname()` — no shell, no subprocess.
3. Built a second secure function (`safe_ping`) that uses `subprocess.run` with an argument list and `shell=False`.
4. Implemented strict hostname validation with an allowlist regex.
5. Wrote 42 automated tests demonstrating both the vulnerability and the defence.

## 9. Vulnerable Implementation (Controlled Demonstration)

The vulnerable function is in `app/security.py` but is NOT exposed as a web route:

```python
def vulnerable_lookup(hostname):
    result = subprocess.run(
        f"nslookup {hostname}",   # string concatenation
        shell=True,                # shell interprets metacharacters
        capture_output=True, text=True, timeout=10,
    )
```

The test suite proves this is exploitable by checking that the shell command string contains the injected payload:

```python
def test_vulnerable_constructs_shell_string(self, mock_run):
    vulnerable_lookup("google.com; whoami")
    cmd = mock_run.call_args.args[0]
    assert "; whoami" in cmd   # injection IS in the command
    assert call_kwargs.kwargs["shell"] is True
```

## 10. Secure Implementation and Preventive Measures

### Approach 1: Use a library (preferred)

```python
def safe_lookup(hostname):
    valid, error = validate_hostname(hostname)
    if not valid:
        return {"success": False, "error": error}
    ip = socket.gethostbyname(hostname)  # no shell involved
    return {"success": True, "hostname": hostname, "ip": ip}
```

### Approach 2: subprocess with shell=False

```python
def safe_ping(hostname, count=1):
    valid, error = validate_hostname(hostname)
    if not valid:
        return {"success": False, "error": error}
    result = subprocess.run(
        ["ping", "-c", str(count), hostname],  # argument LIST
        shell=False,  # no shell interpreter
        timeout=10,
    )
```

### Why input validation alone is not enough

Even with strict regex validation, using `shell=True` remains dangerous because:
- Edge cases in the regex could allow unexpected characters through.
- Future changes to the regex could introduce bypasses.
- `shell=False` removes the attack surface entirely — metacharacters have no special meaning without a shell interpreter.

![Secure implementation](../screenshots/06-secure-implementation.png)

## 11. Security Testing Methodology

42 tests across 9 categories:

| Category | Tests | What It Proves |
|----------|-------|----------------|
| Valid input | 6 | Legitimate hostnames are accepted |
| Empty input | 3 | Empty/whitespace inputs are rejected |
| Invalid characters | 8 | Spaces, slashes, underscores, etc. blocked |
| Shell metacharacters | 10 | ;  &&  \|  \`  $() all blocked |
| Injection attempts | 8 | Full injection payloads rejected; no command output leaked |
| Safe error handling | 2 | Internal errors not exposed to user |
| No shell invocation | 2 | safe_lookup uses no subprocess; safe_ping uses shell=False |
| Vulnerable vs secure | 2 | Same payload succeeds against vulnerable, fails against secure |
| Recovery | 1 | App works normally after rejecting bad input |

## 12. Actual Test Results

![alt text](../screenshots/07-automated-tests.png)

## 13. Screenshot Evidence

| Screenshot | Evidence |
|-----------|----------|
| `01-project-structure.png` | Project layout |
| `02-application-running.png` | App in browser |
| `03-valid-input.png` | Successful DNS lookup |
| `04-invalid-input-rejected.png` | Shell metacharacters rejected |
| `05-injection-test.png` | Injection payload blocked |
| `06-secure-implementation.png` | Safe code using socket library |
| `07-automated-tests.png` | All 42 tests passing |

![Application running](../screenshots/02-application-running.png)
![Valid input](../screenshots/03-valid-input.png)
![Invalid input rejected](../screenshots/04-invalid-input-rejected.png)
![Injection test](../screenshots/05-injection-test.png)

## 14. Limitations

- **No real vulnerable endpoint.** The vulnerable function is test-only; a live demo would require careful isolation.
- **DNS resolution depends on network.** Tests mock the socket call to avoid network dependency.
- **Allowlist regex may not cover all edge cases.** Internationalised domain names (IDN) are not supported.
- **No rate limiting.** Repeated lookups are not throttled.
- **No HTTPS.** Lab runs over HTTP.

## 15. Recommendations

1. Always prefer language libraries over shell commands.
2. When subprocess is necessary, use argument lists with `shell=False`.
3. Validate input with allowlists, not blocklists.
4. Apply timeouts to prevent denial-of-service.
5. Never expose internal error details to users.
6. Conduct regular code review and automated security testing.

## 16. Conclusion

This assignment demonstrates that command injection is caused by passing untrusted input to a shell interpreter. The secure implementation eliminates the attack surface entirely by using Python's socket library instead of shell commands. When subprocess is necessary, using an argument list with `shell=False` prevents metacharacter interpretation. The 42 automated tests confirm that all injection payloads are rejected while legitimate inputs work correctly.

## 17. References

1. OWASP. "Command Injection." https://owasp.org/www-community/attacks/Command_Injection
2. OWASP. "OS Command Injection Defence Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
3. CWE-78: OS Command Injection. MITRE. https://cwe.mitre.org/data/definitions/78.html
4. Python Documentation. "subprocess — Subprocess management." https://docs.python.org/3/library/subprocess.html
5. Python Documentation. "socket — Low-level networking interface." https://docs.python.org/3/library/socket.html
6. Flask Documentation. https://flask.palletsprojects.com/en/stable/
