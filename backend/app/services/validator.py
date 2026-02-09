import logging
from io import StringIO
from dataclasses import dataclass, field

from ruamel.yaml import YAML

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class PhishletValidator:
    REQUIRED_SECTIONS = ["name", "min_ver", "proxy_hosts", "auth_tokens", "credentials", "login"]

    def validate_yaml(self, yaml_content: str) -> ValidationResult:
        result = ValidationResult()

        # Step 1: Parse YAML
        yaml = YAML()
        try:
            data = yaml.load(StringIO(yaml_content))
        except Exception as e:
            result.valid = False
            result.errors.append(f"YAML parse error: {str(e)}")
            return result

        if not isinstance(data, dict):
            result.valid = False
            result.errors.append("YAML root must be a mapping/dictionary.")
            return result

        # Step 2: Required sections
        for section in self.REQUIRED_SECTIONS:
            if section not in data:
                result.valid = False
                result.errors.append(f"Missing required section: '{section}'")

        if not result.valid:
            return result

        # Step 3: Validate each section
        self._validate_proxy_hosts(data.get("proxy_hosts", []), result)
        self._validate_auth_tokens(data.get("auth_tokens", []), result)
        self._validate_credentials(data.get("credentials", {}), result)
        self._validate_login(data.get("login", {}), result)

        if "sub_filters" in data:
            self._validate_sub_filters(data["sub_filters"], result)
        if "force_post" in data:
            self._validate_force_post(data["force_post"], result)
        if "js_inject" in data:
            self._validate_js_inject(data["js_inject"], result)

        # Step 4: Cross-section logical checks
        self._logical_checks(data, result)

        return result

    def _validate_proxy_hosts(self, hosts, result: ValidationResult):
        if not isinstance(hosts, list) or len(hosts) == 0:
            result.valid = False
            result.errors.append("proxy_hosts must be a non-empty list.")
            return

        landing_count = 0
        session_count = 0
        for i, host in enumerate(hosts):
            for key in ["phish_sub", "orig_sub", "domain", "session", "is_landing"]:
                if key not in host:
                    result.valid = False
                    result.errors.append(f"proxy_hosts[{i}]: missing '{key}'")

            if host.get("is_landing"):
                landing_count += 1
            if host.get("session"):
                session_count += 1

        if landing_count == 0:
            result.valid = False
            result.errors.append("At least one proxy_host must have is_landing: true")
        if landing_count > 1:
            result.warnings.append("Multiple proxy_hosts have is_landing: true. Only one is recommended.")
        if session_count == 0:
            result.warnings.append("No proxy_host has session: true. Session cookies may not be captured.")

    def _validate_auth_tokens(self, tokens, result: ValidationResult):
        if not isinstance(tokens, list) or len(tokens) == 0:
            result.valid = False
            result.errors.append("auth_tokens must be a non-empty list.")
            return

        for i, token in enumerate(tokens):
            if "domain" not in token:
                result.valid = False
                result.errors.append(f"auth_tokens[{i}]: missing 'domain'")
            if "keys" not in token and "name" not in token:
                result.valid = False
                result.errors.append(f"auth_tokens[{i}]: missing 'keys' (cookie) or 'name' (body/header)")

    def _validate_credentials(self, creds, result: ValidationResult):
        if not isinstance(creds, dict):
            result.valid = False
            result.errors.append("credentials must be a mapping.")
            return

        if "username" not in creds and "password" not in creds:
            result.warnings.append("No username or password defined in credentials.")

        for field_name in ["username", "password"]:
            if field_name in creds:
                f = creds[field_name]
                if "key" not in f:
                    result.valid = False
                    result.errors.append(f"credentials.{field_name}: missing 'key'")
                if "search" not in f:
                    result.warnings.append(f"credentials.{field_name}: missing 'search', defaults to '(.*)'")

    def _validate_login(self, login, result: ValidationResult):
        if not isinstance(login, dict):
            result.valid = False
            result.errors.append("login must be a mapping.")
            return
        if "domain" not in login:
            result.valid = False
            result.errors.append("login: missing 'domain'")
        if "path" not in login:
            result.valid = False
            result.errors.append("login: missing 'path'")

    def _validate_sub_filters(self, filters, result: ValidationResult):
        if not isinstance(filters, list):
            result.errors.append("sub_filters must be a list.")
            return
        for i, sf in enumerate(filters):
            for key in ["triggers_on", "orig_sub", "domain", "search", "replace", "mimes"]:
                if key not in sf:
                    result.warnings.append(f"sub_filters[{i}]: missing '{key}'")

    def _validate_force_post(self, force_posts, result: ValidationResult):
        if not isinstance(force_posts, list):
            result.errors.append("force_post must be a list.")
            return
        for i, fp in enumerate(force_posts):
            if "path" not in fp:
                result.errors.append(f"force_post[{i}]: missing 'path'")
            if "search" not in fp:
                result.errors.append(f"force_post[{i}]: missing 'search'")

    def _validate_js_inject(self, injects, result: ValidationResult):
        if not isinstance(injects, list):
            result.errors.append("js_inject must be a list.")
            return
        for i, ji in enumerate(injects):
            if "trigger_domains" not in ji:
                result.errors.append(f"js_inject[{i}]: missing 'trigger_domains'")
            if "script" not in ji:
                result.errors.append(f"js_inject[{i}]: missing 'script'")

    def _logical_checks(self, data, result: ValidationResult):
        proxy_domains: set[str] = set()
        for host in data.get("proxy_hosts", []):
            d = host.get("domain", "")
            s = host.get("orig_sub", "")
            full = f"{s}.{d}" if s else d
            proxy_domains.add(full)
            proxy_domains.add(d)

        login = data.get("login", {})
        login_domain = login.get("domain", "")
        if login_domain:
            found = any(login_domain in pd or pd in login_domain for pd in proxy_domains)
            if not found:
                result.warnings.append(
                    f"login.domain '{login_domain}' not found in proxy_hosts. "
                    "Ensure it matches one of the proxy_host entries."
                )

        for token in data.get("auth_tokens", []):
            td = token.get("domain", "").lstrip(".")
            found = any(td in pd or pd in td for pd in proxy_domains)
            if not found:
                result.warnings.append(
                    f"auth_token domain '{td}' not covered by any proxy_host."
                )
