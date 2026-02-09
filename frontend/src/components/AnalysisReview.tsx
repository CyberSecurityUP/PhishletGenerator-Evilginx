import { useState } from "react";
import {
  Globe,
  FormInput,
  Cookie,
  ArrowRight,
  Shield,
  AlertTriangle,
  Zap,
  Loader2,
} from "lucide-react";
import type { AnalysisResult } from "@/types";

interface AnalysisReviewProps {
  analysis: AnalysisResult;
  onGenerate: () => void;
  isGenerating: boolean;
  onBack: () => void;
}

type Tab = "domains" | "forms" | "cookies" | "flow";

export default function AnalysisReview({
  analysis,
  onGenerate,
  isGenerating,
  onBack,
}: AnalysisReviewProps) {
  const [activeTab, setActiveTab] = useState<Tab>("domains");

  const tabs = [
    { id: "domains" as Tab, label: "Domains", icon: Globe, count: analysis.discovered_domains.length },
    { id: "forms" as Tab, label: "Login Forms", icon: FormInput, count: analysis.login_forms.length },
    { id: "cookies" as Tab, label: "Cookies", icon: Cookie, count: Object.keys(analysis.cookies_observed).length },
    { id: "flow" as Tab, label: "Auth Flow", icon: ArrowRight, count: analysis.auth_flow_steps.length },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium text-zinc-200">Analysis Results</h3>
          <p className="text-sm text-zinc-400">
            {analysis.page_title} - {analysis.base_domain}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {analysis.has_mfa && (
            <span className="px-2.5 py-1 rounded-full bg-yellow-500/10 text-yellow-400 text-xs font-medium flex items-center gap-1">
              <Shield className="w-3 h-3" /> MFA Detected
            </span>
          )}
          {analysis.uses_javascript_auth && (
            <span className="px-2.5 py-1 rounded-full bg-purple-500/10 text-purple-400 text-xs font-medium">
              JS Auth
            </span>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 bg-zinc-900 rounded-lg">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm transition-colors ${
                activeTab === tab.id
                  ? "bg-zinc-700 text-zinc-100"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
              <span className="text-xs bg-zinc-800 px-1.5 py-0.5 rounded">
                {tab.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      <div className="bg-zinc-900 rounded-lg border border-zinc-800 p-4 min-h-[300px] max-h-[400px] overflow-auto">
        {activeTab === "domains" && (
          <div className="space-y-3">
            {analysis.discovered_domains.map((d) => (
              <div
                key={d.domain}
                className="flex items-center justify-between p-3 bg-zinc-800/50 rounded-lg"
              >
                <div>
                  <p className="text-sm font-medium text-zinc-200">{d.domain}</p>
                  {d.subdomains.length > 0 && (
                    <p className="text-xs text-zinc-500 mt-1">
                      Subdomains: {d.subdomains.join(", ")}
                    </p>
                  )}
                </div>
                <div className="flex gap-2">
                  {d.is_auth_related && (
                    <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 text-xs">
                      Auth
                    </span>
                  )}
                  {d.is_cdn && (
                    <span className="px-2 py-0.5 rounded bg-zinc-700 text-zinc-400 text-xs">
                      CDN
                    </span>
                  )}
                </div>
              </div>
            ))}
            {analysis.discovered_domains.length === 0 && (
              <p className="text-sm text-zinc-500 text-center py-8">
                No domains discovered
              </p>
            )}
          </div>
        )}

        {activeTab === "forms" && (
          <div className="space-y-4">
            {analysis.login_forms.map((form, i) => (
              <div key={i} className="p-3 bg-zinc-800/50 rounded-lg space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-zinc-400">
                    {form.method} {form.action_url}
                  </span>
                  {form.submit_button_text && (
                    <span className="text-xs text-zinc-500">
                      Button: "{form.submit_button_text}"
                    </span>
                  )}
                </div>
                <div className="space-y-1">
                  {form.fields.map((field, j) => (
                    <div
                      key={j}
                      className="flex items-center gap-3 text-sm text-zinc-300"
                    >
                      <span className="px-1.5 py-0.5 rounded bg-zinc-700 text-xs font-mono">
                        {field.field_type}
                      </span>
                      <span className="font-mono text-zinc-400">
                        {field.field_name || "(unnamed)"}
                      </span>
                      {field.placeholder && (
                        <span className="text-zinc-600 text-xs">
                          "{field.placeholder}"
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
            {analysis.login_forms.length === 0 && (
              <div className="text-center py-8">
                <AlertTriangle className="w-8 h-8 text-yellow-500 mx-auto mb-2" />
                <p className="text-sm text-zinc-400">
                  No login forms detected. The phishlet may need manual
                  credential field configuration.
                </p>
              </div>
            )}
          </div>
        )}

        {activeTab === "cookies" && (
          <div className="space-y-3">
            {Object.entries(analysis.cookies_observed).map(([domain, cookies]) => (
              <div
                key={domain}
                className="p-3 bg-zinc-800/50 rounded-lg space-y-2"
              >
                <p className="text-sm font-medium text-zinc-300">{domain}</p>
                <div className="flex flex-wrap gap-1.5">
                  {cookies.map((cookie) => (
                    <span
                      key={cookie}
                      className="px-2 py-0.5 rounded bg-zinc-700 text-zinc-300 text-xs font-mono"
                    >
                      {cookie}
                    </span>
                  ))}
                </div>
              </div>
            ))}
            {Object.keys(analysis.cookies_observed).length === 0 && (
              <p className="text-sm text-zinc-500 text-center py-8">
                No cookies observed
              </p>
            )}
          </div>
        )}

        {activeTab === "flow" && (
          <div className="space-y-2">
            {analysis.auth_flow_steps.map((step) => (
              <div
                key={step.step_number}
                className="flex items-start gap-3 p-3 bg-zinc-800/50 rounded-lg"
              >
                <div className="w-6 h-6 rounded-full bg-zinc-700 flex items-center justify-center text-xs text-zinc-300 shrink-0 mt-0.5">
                  {step.step_number}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-zinc-300 truncate">{step.url}</p>
                  <p className="text-xs text-zinc-500 mt-0.5">
                    {step.description}
                    {step.sets_cookies.length > 0 && (
                      <span className="text-yellow-500">
                        {" "}
                        | Sets cookies: {step.sets_cookies.join(", ")}
                      </span>
                    )}
                  </p>
                </div>
                <span
                  className={`px-1.5 py-0.5 rounded text-xs ${
                    step.status_code < 400
                      ? "bg-green-500/10 text-green-400"
                      : "bg-red-500/10 text-red-400"
                  }`}
                >
                  {step.status_code}
                </span>
              </div>
            ))}
            {analysis.auth_flow_steps.length === 0 && (
              <p className="text-sm text-zinc-500 text-center py-8">
                No auth flow steps captured
              </p>
            )}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-3">
        <button
          onClick={onBack}
          className="px-4 py-2.5 rounded-lg border border-zinc-700 text-zinc-300 hover:bg-zinc-800 text-sm transition-colors"
        >
          Back
        </button>
        <button
          onClick={onGenerate}
          disabled={isGenerating}
          className="flex-1 flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-zinc-700 disabled:cursor-not-allowed text-white font-medium text-sm transition-colors"
        >
          {isGenerating ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Generating...
            </>
          ) : (
            <>
              <Zap className="w-4 h-4" />
              Generate Phishlet
            </>
          )}
        </button>
      </div>
    </div>
  );
}
