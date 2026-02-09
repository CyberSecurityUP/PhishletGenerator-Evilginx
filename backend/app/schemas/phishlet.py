from pydantic import BaseModel
from typing import Optional, Union


class ProxyHost(BaseModel):
    phish_sub: str = ""
    orig_sub: str = ""
    domain: str
    session: bool = True
    is_landing: bool = False
    auto_filter: bool = True


class SubFilter(BaseModel):
    triggers_on: str
    orig_sub: str = ""
    domain: str
    search: str = "{hostname}"
    replace: str = "{hostname}"
    mimes: list[str] = ["text/html", "application/json", "application/javascript"]
    redirect_only: bool = False


class AuthTokenCookie(BaseModel):
    domain: str
    keys: list[str]
    type: str = "cookie"


class AuthTokenBody(BaseModel):
    domain: str
    path: str
    name: str
    search: str
    type: str = "body"


class AuthTokenHeader(BaseModel):
    domain: str
    path: str
    name: str
    header: str
    type: str = "http"


AuthToken = Union[AuthTokenCookie, AuthTokenBody, AuthTokenHeader]


class CredentialField(BaseModel):
    key: str
    search: str = "(.*)"
    type: str = "post"


class Credentials(BaseModel):
    username: Optional[CredentialField] = None
    password: Optional[CredentialField] = None
    custom: Optional[list[CredentialField]] = None


class ForcePostSearch(BaseModel):
    key: str
    search: str = ".*"


class ForcePostForce(BaseModel):
    key: str
    value: str


class ForcePost(BaseModel):
    path: str
    search: list[ForcePostSearch] = []
    force: Optional[list[ForcePostForce]] = None
    type: str = "post"


class JsInject(BaseModel):
    trigger_domains: list[str] = []
    trigger_paths: list[str] = []
    trigger_params: list[str] = []
    script: str = ""


class LoginConfig(BaseModel):
    domain: str
    path: str = "/"


class Phishlet(BaseModel):
    name: str
    author: str = "@rtlphishletgen"
    min_ver: str = "3.2.0"
    proxy_hosts: list[ProxyHost] = []
    sub_filters: list[SubFilter] = []
    auth_tokens: list[AuthToken] = []
    credentials: Credentials = Credentials()
    auth_urls: list[str] = []
    login: LoginConfig
    force_post: list[ForcePost] = []
    js_inject: list[JsInject] = []
    redirect_url: Optional[str] = None


class PhishletGenerateResponse(BaseModel):
    yaml_content: str
    phishlet: Phishlet
    warnings: list[str] = []
    suggestions: list[str] = []
