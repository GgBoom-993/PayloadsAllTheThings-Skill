---
name: payloads-ref
description: >
  Web application security payload reference for penetration testing and CTF challenges.
  Use this skill whenever the user asks for payloads, bypass techniques, injection vectors,
  or exploitation methods for any web vulnerability — XSS, SQL injection, SSRF, SSTI,
  command injection, XXE, IDOR, file inclusion, deserialization, JWT attacks, OAuth flaws,
  CORS misconfigurations, path traversal, open redirect, prototype pollution, and many more.
  Also trigger for WAF bypass, Burp Intruder wordlists, or any security testing payload
  lookup. If the user mentions a CVE class, attack category, or says "give me payloads for X",
  use this skill.
---

# Payload Reference — Web Application Security

This skill provides curated attack payloads and bypass techniques for web application
security testing (pentests, bug bounties, CTF challenges). Content is sourced from
PayloadsAllTheThings.

## How to use

1. Identify the vulnerability type the user needs payloads for.
2. Read the corresponding `references/<slug>.md` file from the table below.
3. If the user needs Burp Intruder wordlists, check `intruder/<slug>/` — files ending
   in `.txt` are ready to paste into Intruder.
4. Present only the relevant payloads/techniques for the user's specific context.
   Don't dump the entire file; filter by injection context, target DB, WAF type, etc.

## Vulnerability Index

| Vulnerability | Reference File | Has Intruder Payloads |
|---|---|:---:|
| Account Takeover | `references/account-takeover.md` |  |
| API Key Leaks | `references/api-key-leaks.md` |  |
| Brute Force Rate Limit | `references/brute-force-rate-limit.md` |  |
| Business Logic Errors | `references/business-logic-errors.md` |  |
| Clickjacking | `references/clickjacking.md` |  |
| Client Side Path Traversal | `references/client-side-path-traversal.md` |  |
| Command Injection | `references/command-injection.md` | Yes |
| CORS Misconfiguration | `references/cors-misconfiguration.md` |  |
| CRLF Injection | `references/crlf-injection.md` |  |
| Cross-Site Request Forgery | `references/cross-site-request-forgery.md` |  |
| CSS Injection | `references/css-injection.md` |  |
| CSV Injection | `references/csv-injection.md` |  |
| CVE Exploits | `references/cve-exploits.md` |  |
| Denial of Service | `references/denial-of-service.md` |  |
| Dependency Confusion | `references/dependency-confusion.md` |  |
| Directory Traversal | `references/directory-traversal.md` | Yes |
| DNS Rebinding | `references/dns-rebinding.md` |  |
| DOM Clobbering | `references/dom-clobbering.md` |  |
| Encoding Transformations | `references/encoding-transformations.md` |  |
| External Variable Modification | `references/external-variable-modification.md` |  |
| File Inclusion | `references/file-inclusion.md` | Yes |
| Google Web Toolkit | `references/google-web-toolkit.md` |  |
| GraphQL Injection | `references/graphql-injection.md` |  |
| Headless Browser | `references/headless-browser.md` |  |
| Hidden Parameters | `references/hidden-parameters.md` |  |
| HTTP Parameter Pollution | `references/http-parameter-pollution.md` |  |
| Insecure Deserialization | `references/insecure-deserialization.md` |  |
| Insecure Direct Object References | `references/insecure-direct-object-references.md` |  |
| Insecure Management Interface | `references/insecure-management-interface.md` | Yes |
| Insecure Randomness | `references/insecure-randomness.md` |  |
| Insecure Source Code Management | `references/insecure-source-code-management.md` |  |
| Java RMI | `references/java-rmi.md` |  |
| JSON Web Token | `references/json-web-token.md` |  |
| LaTeX Injection | `references/latex-injection.md` |  |
| LDAP Injection | `references/ldap-injection.md` | Yes |
| Mass Assignment | `references/mass-assignment.md` |  |
| Methodology and Resources | `references/methodology-and-resources.md` |  |
| NoSQL Injection | `references/nosql-injection.md` | Yes |
| OAuth Misconfiguration | `references/oauth-misconfiguration.md` |  |
| Open Redirect | `references/open-redirect.md` | Yes |
| ORM Leak | `references/orm-leak.md` |  |
| Prompt Injection | `references/prompt-injection.md` |  |
| Prototype Pollution | `references/prototype-pollution.md` |  |
| Race Condition | `references/race-condition.md` |  |
| Regular Expression | `references/regular-expression.md` |  |
| Request Smuggling | `references/request-smuggling.md` |  |
| Reverse Proxy Misconfigurations | `references/reverse-proxy-misconfigurations.md` |  |
| SAML Injection | `references/saml-injection.md` |  |
| Server Side Include Injection | `references/server-side-include-injection.md` |  |
| Server Side Request Forgery | `references/server-side-request-forgery.md` |  |
| Server Side Template Injection | `references/server-side-template-injection.md` | Yes |
| SQL Injection | `references/sql-injection.md` | Yes |
| Tabnabbing | `references/tabnabbing.md` |  |
| Type Juggling | `references/type-juggling.md` |  |
| Upload Insecure Files | `references/upload-insecure-files.md` |  |
| Virtual Hosts | `references/virtual-hosts.md` |  |
| Web Cache Deception | `references/web-cache-deception.md` | Yes |
| Web Sockets | `references/web-sockets.md` |  |
| XPATH Injection | `references/xpath-injection.md` |  |
| XS-Leak | `references/xs-leak.md` |  |
| XSLT Injection | `references/xslt-injection.md` |  |
| XSS Injection | `references/xss-injection.md` | Yes |
| XXE Injection | `references/xxe-injection.md` | Yes |
| Zip Slip | `references/zip-slip.md` |  |

## Usage examples

- *"Give me XSS payloads that bypass WAF"* → read `references/xss-injection.md`, focus on WAF bypass section
- *"SQL injection for MySQL UNION-based"* → read `references/sql-injection.md` + `references/sql-injection/MySQL Injection.md`
- *"SSTI payloads for Jinja2"* → read `references/server-side-template-injection.md`, Python/Jinja2 section
- *"Burp Intruder list for SQLi auth bypass"* → point to `intruder/sql-injection/Auth_Bypass.txt`
- *"JWT attack payloads"* → read `references/json-web-token.md`
- *"SSRF bypass techniques"* → read `references/server-side-request-forgery.md`
