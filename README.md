# PayloadsAllTheThings — Claude Skill

A Claude Code Skill built from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), enabling Claude to look up attack payloads and bypass techniques on demand during penetration testing, bug bounty hunting, and CTF challenges.

## Background

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) is a well-known collection of web application security payloads covering SQL injection, XSS, SSRF, SSTI, command injection, and dozens of other vulnerability classes.

This project reformats the original content for use as a Claude Skill. The following changes were made:

- Removed all image references (not useful in an AI context)
- Removed `## References` sections (external citation links)
- Removed `## Labs` sections (PortSwigger / RootMe exercise links)
- Removed `## Summary` sections (in-document TOCs, unnecessary in a skill)
- Retained all payload code blocks, technique descriptions, and WAF bypass tricks
- Retained Burp Suite Intruder `.txt` wordlist files

## Directory Structure

```
payloads-ref/
├── SKILL.md              # Skill entry point — vulnerability index and usage instructions
├── references/           # 64 cleaned Markdown files, one per vulnerability type
│   ├── sql-injection.md
│   ├── xss-injection.md
│   ├── server-side-template-injection.md
│   └── ... (64 total)
└── intruder/             # Burp Intruder wordlists (12 vulnerability types)
    ├── sql-injection/
    ├── xss-injection/
    ├── command-injection/
    └── ... (12 total)
```

## Coverage

| Vulnerability | Intruder Wordlists |
|---|:---:|
| Account Takeover | |
| API Key Leaks | |
| Brute Force / Rate Limit | |
| Business Logic Errors | |
| Clickjacking | |
| Client Side Path Traversal | |
| Command Injection | Yes |
| CORS Misconfiguration | |
| CRLF Injection | |
| Cross-Site Request Forgery (CSRF) | |
| CSS Injection | |
| CSV Injection | |
| CVE Exploits | |
| Denial of Service | |
| Dependency Confusion | |
| Directory Traversal | Yes |
| DNS Rebinding | |
| DOM Clobbering | |
| Encoding Transformations | |
| External Variable Modification | |
| File Inclusion (LFI/RFI) | Yes |
| GraphQL Injection | |
| HTTP Parameter Pollution | |
| Insecure Deserialization | |
| Insecure Direct Object References (IDOR) | |
| Insecure Management Interface | Yes |
| Insecure Randomness | |
| JSON Web Token (JWT) | |
| LDAP Injection | Yes |
| Mass Assignment | |
| NoSQL Injection | Yes |
| OAuth Misconfiguration | |
| Open Redirect | Yes |
| Prototype Pollution | |
| Race Condition | |
| Request Smuggling | |
| Reverse Proxy Misconfigurations | |
| SAML Injection | |
| Server Side Include Injection (SSI) | |
| Server Side Request Forgery (SSRF) | |
| Server Side Template Injection (SSTI) | Yes |
| SQL Injection | Yes |
| Type Juggling | |
| Upload Insecure Files | |
| Web Cache Deception | Yes |
| XPATH Injection | |
| XS-Leak | |
| XSLT Injection | |
| XSS Injection | Yes |
| XXE Injection | Yes |
| Zip Slip | |
| ...and more | |

See [SKILL.md](./SKILL.md) for the complete index.

## Installation

Copy the `payloads-ref/` directory into your Claude Code skills folder:

```bash
# macOS / Linux
cp -r payloads-ref ~/.claude/skills/

# Windows
xcopy /E /I payloads-ref %USERPROFILE%\.claude\skills\payloads-ref
```

Claude Code will detect the skill automatically. Whenever you ask about web security payloads, Claude will load the relevant reference file and return targeted results.

## Usage Examples

Just ask naturally in Claude Code:

```
Give me XSS payloads that bypass WAF
```
```
What are common MySQL UNION-based injection payloads?
```
```
How do I achieve RCE via Jinja2 SSTI?
```
```
What are the common SSRF techniques for bypassing IP restrictions?
```
```
Give me a Burp Intruder wordlist for SQL injection auth bypass
```
```
What are the main JWT attack techniques?
```

Claude will read the corresponding `references/*.md` file and return only the content relevant to your context — not a raw dump of the entire file.

## Credits

All content is sourced from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), maintained by [swisskyrepo](https://github.com/swisskyrepo) and community contributors, under the MIT License.

## Disclaimer

This project is intended for authorized security testing, vulnerability research, CTF competitions, and security education only. Do not use it for any unauthorized attack activity. You are solely responsible for how you use this tool.
