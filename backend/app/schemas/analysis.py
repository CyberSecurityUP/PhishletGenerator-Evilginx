from pydantic import BaseModel, Field
from typing import Optional


class AnalysisRequest(BaseModel):
    url: str
    author: str = "@rtlphishletgen"
    use_ai: bool = False
    custom_name: Optional[str] = None


class DiscoveredDomain(BaseModel):
    domain: str
    subdomains: list[str] = []
    is_auth_related: bool = False
    is_cdn: bool = False


class LoginFormField(BaseModel):
    field_name: str
    field_type: str
    field_id: Optional[str] = None
    placeholder: Optional[str] = None
    label: Optional[str] = None


class LoginFormInfo(BaseModel):
    action_url: str
    method: str = "POST"
    fields: list[LoginFormField] = []
    submit_button_text: Optional[str] = None


class AuthFlowStep(BaseModel):
    step_number: int
    url: str
    method: str = "GET"
    content_type: Optional[str] = None
    is_redirect: bool = False
    status_code: int = 200
    sets_cookies: list[str] = []
    description: str = ""


class AnalysisResult(BaseModel):
    target_url: str
    base_domain: str
    discovered_domains: list[DiscoveredDomain] = []
    login_forms: list[LoginFormInfo] = []
    auth_flow_steps: list[AuthFlowStep] = []
    cookies_observed: dict[str, list[str]] = Field(default_factory=dict)
    redirect_chain: list[str] = []
    post_login_url: Optional[str] = None
    login_path: str = "/"
    has_mfa: bool = False
    uses_javascript_auth: bool = False
    auth_api_endpoints: list[str] = []
    page_title: str = ""
    suggested_name: str = ""
