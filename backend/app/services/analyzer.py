import re
import logging
from typing import Optional, Callable, Awaitable
from urllib.parse import urlparse

from app.schemas.analysis import AnalysisResult, AuthFlowStep
from app.services.scraper import WebScraper

logger = logging.getLogger(__name__)


class SiteAnalyzer:
    def __init__(self):
        self.scraper = WebScraper()

    async def analyze(
        self,
        url: str,
        callback: Optional[Callable[[str], Awaitable[None]]] = None,
    ) -> AnalysisResult:
        raw = await self.scraper.analyze_url(url, callback=callback)

        auth_flow = self._build_auth_flow(raw)
        suggested_name = self._suggest_name(raw["page_title"], raw["base_domain"])

        return AnalysisResult(
            target_url=raw["target_url"],
            base_domain=raw["base_domain"],
            discovered_domains=raw["discovered_domains"],
            login_forms=raw["login_forms"],
            auth_flow_steps=auth_flow,
            cookies_observed=raw["cookies_observed"],
            redirect_chain=raw["redirect_chain"],
            post_login_url=raw["post_login_url"],
            login_path=raw["login_path"],
            has_mfa=raw["has_mfa"],
            uses_javascript_auth=raw["uses_javascript_auth"],
            auth_api_endpoints=raw["auth_api_endpoints"],
            page_title=raw["page_title"],
            suggested_name=suggested_name,
        )

    def _build_auth_flow(self, raw: dict) -> list[AuthFlowStep]:
        steps = []
        for i, url in enumerate(raw["redirect_chain"]):
            parsed = urlparse(url)
            cookies_set = raw["cookies_observed"].get(parsed.netloc, [])
            steps.append(AuthFlowStep(
                step_number=i + 1,
                url=url,
                method="GET",
                is_redirect=(i > 0),
                status_code=302 if i < len(raw["redirect_chain"]) - 1 else 200,
                sets_cookies=cookies_set,
                description=f"{'Redirect to' if i > 0 else 'Initial navigation to'} {parsed.netloc}",
            ))
        return steps

    @staticmethod
    def _suggest_name(title: str, domain: str) -> str:
        if title:
            name = re.sub(r"\s*[-|]\s*(login|sign\s*in|log\s*in).*$", "", title, flags=re.I)
            name = re.sub(r"[^a-zA-Z0-9\s]", "", name).strip().lower()
            name = re.sub(r"\s+", "_", name)
            if len(name) > 3:
                return name[:30]
        return domain.split(".")[0].lower()
