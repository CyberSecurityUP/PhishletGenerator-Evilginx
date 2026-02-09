import json
import logging
from typing import Optional

import litellm

from app.config import settings
from app.schemas.phishlet import Phishlet
from app.schemas.analysis import AnalysisResult

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert Evilginx phishlet developer for authorized red team security testing.
You understand the Evilginx v3 phishlet YAML format thoroughly, including proxy_hosts, sub_filters,
auth_tokens, credentials, auth_urls, login, force_post, and js_inject sections.

Given a rule-based phishlet draft and the analysis data of a target website, your job is to:
1. Identify missing or incorrect proxy_hosts (domains/subdomains)
2. Suggest better auth_token cookie names based on the target platform
3. Improve credential field mappings
4. Add necessary sub_filters for cross-domain scenarios
5. Add force_post entries if needed
6. Add js_inject if the site uses SPA/JavaScript authentication
7. Ensure the phishlet follows Evilginx best practices

Return ONLY a valid JSON object matching the Phishlet schema. No explanations."""

KNOWN_PLATFORMS_HINT = """
Known platform patterns:
- Microsoft 365/Azure: login.microsoftonline.com, login.live.com, aadcdn.msftauth.net
  Cookies: ESTSAUTH, ESTSAUTHPERSISTENT, SignInStateCookie
  Creds: loginfmt (username), passwd (password)

- Google: accounts.google.com, myaccount.google.com
  Cookies: SID, HSID, SSID, APISID, SAPISID
  Creds: identifier (email), Passwd (password)

- Okta: {tenant}.okta.com
  Cookies: sid, idx
  Creds: username, password

- GitHub: github.com
  Cookies: user_session, _gh_sess, logged_in
  Creds: login (username), password

- AWS: signin.aws.amazon.com
  Cookies: aws-creds, aws-userInfo
"""


class AIService:
    def __init__(self):
        self.model = settings.ai_model
        self.api_key = settings.ai_api_key

    async def refine_phishlet(
        self, phishlet: Phishlet, analysis: AnalysisResult
    ) -> Optional[Phishlet]:
        if not settings.ai_enabled:
            return None

        phishlet_json = phishlet.model_dump_json(indent=2)
        analysis_summary = self._build_analysis_summary(analysis)

        user_prompt = f"""Here is a rule-based phishlet draft and the analysis data.
Refine the phishlet for accuracy.

## Current Phishlet Draft
```json
{phishlet_json}
```

## Target Analysis
{analysis_summary}

## Known Platform Patterns
{KNOWN_PLATFORMS_HINT}

Return the improved phishlet as a single JSON object.
Preserve the same schema structure. Only modify values that need improvement.
Do NOT add explanations - return ONLY the JSON."""

        try:
            response = await litellm.acompletion(
                model=self.model,
                api_key=self.api_key,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=4000,
            )

            content = response.choices[0].message.content

            # Extract JSON from response (handle markdown code blocks)
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            refined_data = json.loads(content.strip())
            refined_phishlet = Phishlet.model_validate(refined_data)
            return refined_phishlet

        except Exception as e:
            logger.error(f"AI refinement failed: {e}")
            return None

    def _build_analysis_summary(self, analysis: AnalysisResult) -> str:
        domains = ", ".join([d.domain for d in analysis.discovered_domains])
        cookies = "; ".join([
            f"{domain}: {', '.join(names)}"
            for domain, names in analysis.cookies_observed.items()
        ])
        forms = ""
        for form in analysis.login_forms:
            fields = ", ".join([f"{f.field_name} ({f.field_type})" for f in form.fields])
            forms += f"  Action: {form.action_url}, Fields: [{fields}]\n"

        return f"""Target URL: {analysis.target_url}
Base Domain: {analysis.base_domain}
Page Title: {analysis.page_title}
Login Path: {analysis.login_path}
Domains Involved: {domains}
Cookies Observed: {cookies}
Login Forms:
{forms}
Auth Endpoints: {', '.join(analysis.auth_api_endpoints[:10])}
Has MFA: {analysis.has_mfa}
Uses JS Auth: {analysis.uses_javascript_auth}
Post-Login URL: {analysis.post_login_url or 'Not detected'}"""

    async def check_connection(self) -> bool:
        try:
            await litellm.acompletion(
                model=self.model,
                api_key=self.api_key,
                messages=[{"role": "user", "content": "Reply with 'ok'"}],
                max_tokens=5,
            )
            return True
        except Exception:
            return False
