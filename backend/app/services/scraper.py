import re
import logging
from typing import Optional, Callable, Awaitable
from urllib.parse import urlparse, urljoin

from playwright.async_api import async_playwright, Page, Request, Response
from bs4 import BeautifulSoup

from app.schemas.analysis import LoginFormField, LoginFormInfo, DiscoveredDomain
from app.config import settings

logger = logging.getLogger(__name__)


class WebScraper:
    def __init__(self):
        self.redirect_chain: list[str] = []
        self.network_requests: list[dict] = []
        self.cookies_by_domain: dict[str, list[str]] = {}
        self.domains_seen: set[str] = set()
        self.auth_endpoints: list[str] = []

    async def analyze_url(
        self,
        url: str,
        callback: Optional[Callable[[str], Awaitable[None]]] = None,
    ) -> dict:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=settings.playwright_headless)
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,
            )

            page = await context.new_page()

            page.on("request", self._on_request)
            page.on("response", self._on_response)

            # Step 1: Navigate
            if callback:
                await callback("Navigating to target URL...")

            await page.goto(url, wait_until="networkidle", timeout=settings.playwright_timeout)
            await page.wait_for_timeout(3000)

            # Step 2: Extract page content
            if callback:
                await callback("Extracting page content...")

            html_content = await page.content()
            page_title = await page.title()

            # Extract domains from inline JavaScript
            self._extract_domains_from_js(html_content)

            # Step 3: Detect login forms
            if callback:
                await callback("Detecting login forms...")

            login_forms = await self._detect_login_forms(page, html_content, url)

            # Step 4: Capture cookies
            if callback:
                await callback("Capturing cookies...")

            cookies = await context.cookies()
            for cookie in cookies:
                domain = cookie["domain"]
                if domain not in self.cookies_by_domain:
                    self.cookies_by_domain[domain] = []
                if cookie["name"] not in self.cookies_by_domain[domain]:
                    self.cookies_by_domain[domain].append(cookie["name"])

            # Step 5: Identify auth endpoints
            if callback:
                await callback("Identifying auth endpoints...")

            self._classify_auth_endpoints()

            # Step 6: Build domain map
            if callback:
                await callback("Building domain map...")

            discovered_domains = self._build_domain_map(url)

            # Step 7: Additional detection
            if callback:
                await callback("Finalizing analysis...")

            post_login_url = self._detect_post_login_url()
            has_mfa = self._detect_mfa_indicators(html_content)
            uses_js_auth = self._detect_js_auth(html_content)

            await browser.close()

            parsed = urlparse(url)
            return {
                "target_url": url,
                "base_domain": parsed.netloc,
                "discovered_domains": discovered_domains,
                "login_forms": login_forms,
                "cookies_observed": self.cookies_by_domain,
                "redirect_chain": self.redirect_chain,
                "post_login_url": post_login_url,
                "login_path": parsed.path or "/",
                "has_mfa": has_mfa,
                "uses_javascript_auth": uses_js_auth,
                "auth_api_endpoints": self.auth_endpoints,
                "page_title": page_title,
                "network_requests": self.network_requests,
                "html_content": html_content,
            }

    def _on_request(self, request: Request):
        parsed = urlparse(request.url)
        if parsed.netloc:
            self.domains_seen.add(parsed.netloc)
        self.network_requests.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
        })
        if request.is_navigation_request():
            self.redirect_chain.append(request.url)

    def _on_response(self, response: Response):
        headers = response.headers
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            parsed = urlparse(response.url)
            domain = parsed.netloc
            cookie_names = re.findall(r"^([^=]+)=", set_cookie, re.MULTILINE)
            if domain not in self.cookies_by_domain:
                self.cookies_by_domain[domain] = []
            for name in cookie_names:
                name = name.strip()
                if name and name not in self.cookies_by_domain[domain]:
                    self.cookies_by_domain[domain].append(name)

    async def _detect_login_forms(
        self, page: Page, html: str, base_url: str
    ) -> list[LoginFormInfo]:
        soup = BeautifulSoup(html, "html.parser")
        forms: list[LoginFormInfo] = []

        # Strategy 1: <form> elements with password inputs
        for form in soup.find_all("form"):
            password_inputs = form.find_all("input", {"type": "password"})
            if not password_inputs:
                continue

            action = form.get("action", "")
            if action and not action.startswith("http"):
                action = urljoin(base_url, action)

            fields: list[LoginFormField] = []
            for inp in form.find_all("input"):
                input_type = inp.get("type", "text")
                if input_type in ("submit", "button"):
                    continue

                label_text = None
                field_id = inp.get("id")
                if field_id:
                    label_el = soup.find("label", attrs={"for": field_id})
                    if label_el:
                        label_text = label_el.get_text(strip=True)
                if not label_text:
                    label = inp.find_previous("label")
                    if label:
                        label_text = label.get_text(strip=True)

                fields.append(LoginFormField(
                    field_name=inp.get("name", ""),
                    field_type=input_type,
                    field_id=inp.get("id"),
                    placeholder=inp.get("placeholder"),
                    label=label_text,
                ))

            submit = form.find("button", {"type": "submit"}) or form.find("input", {"type": "submit"})
            submit_text = None
            if submit:
                submit_text = submit.get_text(strip=True) or submit.get("value", "")

            forms.append(LoginFormInfo(
                action_url=action or base_url,
                method=form.get("method", "POST").upper(),
                fields=fields,
                submit_button_text=submit_text,
            ))

        # Strategy 2: Playwright selectors for SPA login forms
        if not forms:
            password_field = await page.query_selector(
                'input[type="password"], input[name*="pass"], input[name*="pwd"]'
            )
            if password_field:
                email_field = await page.query_selector(
                    'input[type="email"], input[name*="email"], '
                    'input[name*="user"], input[name*="login"]'
                )
                fields = []
                if email_field:
                    fields.append(LoginFormField(
                        field_name=await email_field.get_attribute("name") or "email",
                        field_type=await email_field.get_attribute("type") or "email",
                        field_id=await email_field.get_attribute("id"),
                        placeholder=await email_field.get_attribute("placeholder"),
                    ))
                fields.append(LoginFormField(
                    field_name=await password_field.get_attribute("name") or "password",
                    field_type="password",
                    field_id=await password_field.get_attribute("id"),
                    placeholder=await password_field.get_attribute("placeholder"),
                ))
                forms.append(LoginFormInfo(
                    action_url=base_url,
                    method="POST",
                    fields=fields,
                    submit_button_text="Sign In",
                ))

        return forms

    def _classify_auth_endpoints(self):
        auth_patterns = [
            r"/login", r"/signin", r"/auth", r"/oauth", r"/token",
            r"/session", r"/api/auth", r"/api/login", r"/authenticate",
            r"/sso", r"/saml", r"/adfs", r"/common/oauth2",
            r"/ppsecure", r"/credential", r"/v2\.0/authorize",
        ]
        for req in self.network_requests:
            url_lower = req["url"].lower()
            for pattern in auth_patterns:
                if re.search(pattern, url_lower):
                    if req["url"] not in self.auth_endpoints:
                        self.auth_endpoints.append(req["url"])
                    break

    def _build_domain_map(self, target_url: str) -> list[DiscoveredDomain]:
        target_parsed = urlparse(target_url)
        base_domain = self._extract_base_domain(target_parsed.netloc)

        domain_map: dict[str, DiscoveredDomain] = {}

        cdn_indicators = ["cdn", "static", "assets", "img", "fonts", "media"]
        auth_indicators = [
            "login", "auth", "sso", "oauth", "account", "id",
            "adfs", "sts", "microsoftonline", "okta",
        ]

        for full_domain in self.domains_seen:
            bd = self._extract_base_domain(full_domain)
            subdomain = full_domain.replace(f".{bd}", "").replace(bd, "")
            if subdomain.endswith("."):
                subdomain = subdomain[:-1]

            if bd not in domain_map:
                domain_map[bd] = DiscoveredDomain(
                    domain=bd,
                    subdomains=[],
                    is_auth_related=False,
                    is_cdn=False,
                )

            if subdomain and subdomain not in domain_map[bd].subdomains:
                domain_map[bd].subdomains.append(subdomain)

            domain_lower = full_domain.lower()
            if any(ind in domain_lower for ind in auth_indicators):
                domain_map[bd].is_auth_related = True
            if any(ind in domain_lower for ind in cdn_indicators):
                domain_map[bd].is_cdn = True

        # Ensure the target domain is marked as auth-related
        if base_domain in domain_map:
            domain_map[base_domain].is_auth_related = True

        return list(domain_map.values())

    def _detect_post_login_url(self) -> Optional[str]:
        common_post_login = [
            "/dashboard", "/home", "/main", "/portal",
            "/account", "/app", "/inbox", "/feed",
            "/my", "/workspace", "/console", "/admin",
            "/profile", "/overview", "/callback",
            "/signin-oidc", "/auth/complete", "/oauth/callback",
        ]
        # Check redirect chain in reverse (most likely post-login)
        for url in reversed(self.redirect_chain):
            parsed = urlparse(url)
            for pattern in common_post_login:
                if parsed.path.lower().startswith(pattern):
                    return parsed.path

        # Fallback to network requests
        for req in self.network_requests:
            if req.get("resource_type") == "document":
                parsed = urlparse(req["url"])
                for pattern in common_post_login:
                    if parsed.path.lower().startswith(pattern):
                        return parsed.path
        return None

    def _detect_mfa_indicators(self, html: str) -> bool:
        mfa_patterns = [
            r"two.?factor", r"2fa", r"mfa", r"multi.?factor",
            r"verification.?code", r"authenticator", r"otp",
            r"one.?time.?password", r"security.?code",
        ]
        html_lower = html.lower()
        return any(re.search(p, html_lower) for p in mfa_patterns)

    def _extract_domains_from_js(self, html: str):
        """Extract domain references from inline scripts and script src attributes."""
        soup = BeautifulSoup(html, "html.parser")

        # From script src attributes
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if src.startswith("//"):
                src = "https:" + src
            parsed = urlparse(src)
            if parsed.netloc:
                self.domains_seen.add(parsed.netloc)

        # From inline script content: find URLs with domains
        url_pattern = re.compile(
            r'(?:https?://|//)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
        )
        for script in soup.find_all("script"):
            if script.string:
                for match in url_pattern.finditer(script.string):
                    domain = match.group(1)
                    if "." in domain and not domain.endswith((".js", ".css", ".png", ".jpg")):
                        self.domains_seen.add(domain)

    def _detect_js_auth(self, html: str) -> bool:
        js_auth_patterns = [
            r"fetch\s*\(.*/login", r"fetch\s*\(.*/auth",
            r"XMLHttpRequest.*login", r"axios.*login",
            r"\.post\s*\(.*/api/auth", r"firebase\.auth",
        ]
        return any(re.search(p, html, re.IGNORECASE) for p in js_auth_patterns)

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
