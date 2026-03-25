# PayloadsAllTheThings — Skill

This skill provides curated attack payloads and bypass techniques for web application security testing (pentests, bug bounties, CTF challenges). Content is sourced from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) is a well-known collection of web application security payloads covering SQL injection, XSS, SSRF, SSTI, command injection, and dozens of other vulnerability classes.


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

## Vulnerability Index

| Vulnerability                     | Reference File                                    | Has Intruder Payloads |
| --------------------------------- | ------------------------------------------------- | :-------------------: |
| Account Takeover                  | `references/account-takeover.md`                  |                       |
| API Key Leaks                     | `references/api-key-leaks.md`                     |                       |
| Brute Force Rate Limit            | `references/brute-force-rate-limit.md`            |                       |
| Business Logic Errors             | `references/business-logic-errors.md`             |                       |
| Clickjacking                      | `references/clickjacking.md`                      |                       |
| Client Side Path Traversal        | `references/client-side-path-traversal.md`        |                       |
| Command Injection                 | `references/command-injection.md`                 |          Yes          |
| CORS Misconfiguration             | `references/cors-misconfiguration.md`             |                       |
| CRLF Injection                    | `references/crlf-injection.md`                    |                       |
| Cross-Site Request Forgery        | `references/cross-site-request-forgery.md`        |                       |
| CSS Injection                     | `references/css-injection.md`                     |                       |
| CSV Injection                     | `references/csv-injection.md`                     |                       |
| CVE Exploits                      | `references/cve-exploits.md`                      |                       |
| Denial of Service                 | `references/denial-of-service.md`                 |                       |
| Dependency Confusion              | `references/dependency-confusion.md`              |                       |
| Directory Traversal               | `references/directory-traversal.md`               |          Yes          |
| DNS Rebinding                     | `references/dns-rebinding.md`                     |                       |
| DOM Clobbering                    | `references/dom-clobbering.md`                    |                       |
| Encoding Transformations          | `references/encoding-transformations.md`          |                       |
| External Variable Modification    | `references/external-variable-modification.md`    |                       |
| File Inclusion                    | `references/file-inclusion.md`                    |          Yes          |
| Google Web Toolkit                | `references/google-web-toolkit.md`                |                       |
| GraphQL Injection                 | `references/graphql-injection.md`                 |                       |
| Headless Browser                  | `references/headless-browser.md`                  |                       |
| Hidden Parameters                 | `references/hidden-parameters.md`                 |                       |
| HTTP Parameter Pollution          | `references/http-parameter-pollution.md`          |                       |
| Insecure Deserialization          | `references/insecure-deserialization.md`          |                       |
| Insecure Direct Object References | `references/insecure-direct-object-references.md` |                       |
| Insecure Management Interface     | `references/insecure-management-interface.md`     |          Yes          |
| Insecure Randomness               | `references/insecure-randomness.md`               |                       |
| Insecure Source Code Management   | `references/insecure-source-code-management.md`   |                       |
| Java RMI                          | `references/java-rmi.md`                          |                       |
| JSON Web Token                    | `references/json-web-token.md`                    |                       |
| LaTeX Injection                   | `references/latex-injection.md`                   |                       |
| LDAP Injection                    | `references/ldap-injection.md`                    |          Yes          |
| Mass Assignment                   | `references/mass-assignment.md`                   |                       |
| Methodology and Resources         | `references/methodology-and-resources.md`         |                       |
| NoSQL Injection                   | `references/nosql-injection.md`                   |          Yes          |
| OAuth Misconfiguration            | `references/oauth-misconfiguration.md`            |                       |
| Open Redirect                     | `references/open-redirect.md`                     |          Yes          |
| ORM Leak                          | `references/orm-leak.md`                          |                       |
| Prompt Injection                  | `references/prompt-injection.md`                  |                       |
| Prototype Pollution               | `references/prototype-pollution.md`               |                       |
| Race Condition                    | `references/race-condition.md`                    |                       |
| Regular Expression                | `references/regular-expression.md`                |                       |
| Request Smuggling                 | `references/request-smuggling.md`                 |                       |
| Reverse Proxy Misconfigurations   | `references/reverse-proxy-misconfigurations.md`   |                       |
| SAML Injection                    | `references/saml-injection.md`                    |                       |
| Server Side Include Injection     | `references/server-side-include-injection.md`     |                       |
| Server Side Request Forgery       | `references/server-side-request-forgery.md`       |                       |
| Server Side Template Injection    | `references/server-side-template-injection.md`    |          Yes          |
| SQL Injection                     | `references/sql-injection.md`                     |          Yes          |
| Tabnabbing                        | `references/tabnabbing.md`                        |                       |
| Type Juggling                     | `references/type-juggling.md`                     |                       |
| Upload Insecure Files             | `references/upload-insecure-files.md`             |                       |
| Virtual Hosts                     | `references/virtual-hosts.md`                     |                       |
| Web Cache Deception               | `references/web-cache-deception.md`               |          Yes          |
| Web Sockets                       | `references/web-sockets.md`                       |                       |
| XPATH Injection                   | `references/xpath-injection.md`                   |                       |
| XS-Leak                           | `references/xs-leak.md`                           |                       |
| XSLT Injection                    | `references/xslt-injection.md`                    |                       |
| XSS Injection                     | `references/xss-injection.md`                     |          Yes          |
| XXE Injection                     | `references/xxe-injection.md`                     |          Yes          |
| Zip Slip                          | `references/zip-slip.md`                          |                       |


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
