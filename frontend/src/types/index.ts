// Analysis types
export interface AnalysisRequest {
  url: string;
  author?: string;
  use_ai?: boolean;
  custom_name?: string;
}

export interface DiscoveredDomain {
  domain: string;
  subdomains: string[];
  is_auth_related: boolean;
  is_cdn: boolean;
}

export interface LoginFormField {
  field_name: string;
  field_type: string;
  field_id?: string;
  placeholder?: string;
  label?: string;
}

export interface LoginFormInfo {
  action_url: string;
  method: string;
  fields: LoginFormField[];
  submit_button_text?: string;
}

export interface AuthFlowStep {
  step_number: number;
  url: string;
  method: string;
  content_type?: string;
  is_redirect: boolean;
  status_code: number;
  sets_cookies: string[];
  description: string;
}

export interface AnalysisResult {
  target_url: string;
  base_domain: string;
  discovered_domains: DiscoveredDomain[];
  login_forms: LoginFormInfo[];
  auth_flow_steps: AuthFlowStep[];
  cookies_observed: Record<string, string[]>;
  redirect_chain: string[];
  post_login_url?: string;
  login_path: string;
  has_mfa: boolean;
  uses_javascript_auth: boolean;
  auth_api_endpoints: string[];
  page_title: string;
  suggested_name: string;
}

// Phishlet types
export interface ProxyHost {
  phish_sub: string;
  orig_sub: string;
  domain: string;
  session: boolean;
  is_landing: boolean;
  auto_filter?: boolean;
}

export interface SubFilter {
  triggers_on: string;
  orig_sub: string;
  domain: string;
  search: string;
  replace: string;
  mimes: string[];
}

export interface AuthToken {
  domain: string;
  keys?: string[];
  name?: string;
  type?: string;
}

export interface CredentialField {
  key: string;
  search: string;
  type: string;
}

export interface Credentials {
  username?: CredentialField;
  password?: CredentialField;
  custom?: CredentialField[];
}

export interface ForcePost {
  path: string;
  search: { key: string; search: string }[];
  force?: { key: string; value: string }[];
  type: string;
}

export interface JsInject {
  trigger_domains: string[];
  trigger_paths: string[];
  trigger_params: string[];
  script: string;
}

export interface LoginConfig {
  domain: string;
  path: string;
}

export interface Phishlet {
  name: string;
  author: string;
  min_ver: string;
  proxy_hosts: ProxyHost[];
  sub_filters: SubFilter[];
  auth_tokens: AuthToken[];
  credentials: Credentials;
  auth_urls: string[];
  login: LoginConfig;
  force_post: ForcePost[];
  js_inject: JsInject[];
}

export interface PhishletGenerateResponse {
  yaml_content: string;
  phishlet: Phishlet;
  warnings: string[];
  suggestions: string[];
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface ProgressUpdate {
  status: "pending" | "scraping" | "analyzing" | "generating" | "complete" | "error";
  step: number;
  total_steps: number;
  message: string;
  detail?: string;
}

export interface AIStatus {
  enabled: boolean;
  model: string | null;
  connected: boolean;
}

export type WizardStep = "input" | "analyzing" | "review" | "editor";

// Saved Phishlet types
export interface SavedPhishlet {
  id: string;
  name: string;
  author: string;
  target_url: string;
  description: string;
  tags: string[];
  yaml_content: string;
  created_at: string;
  updated_at: string;
  validation_status: "valid" | "invalid" | "unknown";
}

export interface SavedPhishletCreate {
  name: string;
  author?: string;
  target_url?: string;
  description?: string;
  tags?: string[];
  yaml_content: string;
}

export interface SavedPhishletList {
  phishlets: SavedPhishlet[];
  total: number;
}
