import { Link } from "react-router-dom";
import {
  Zap,
  Shield,
  Sparkles,
  CheckCircle2,
  Globe,
  FileCode,
} from "lucide-react";

const features = [
  {
    icon: Globe,
    title: "Automated Analysis",
    description:
      "Playwright-powered browser analysis detects login forms, authentication flows, cookies, and all involved domains automatically.",
  },
  {
    icon: Sparkles,
    title: "AI Enhancement",
    description:
      "Optional AI integration (DeepSeek, Claude, OpenAI) refines phishlet accuracy with platform-specific knowledge.",
  },
  {
    icon: CheckCircle2,
    title: "Built-in Validation",
    description:
      "Schema validation and cross-section logical checks ensure your phishlet is Evilginx v3 compatible before deployment.",
  },
  {
    icon: FileCode,
    title: "YAML Editor",
    description:
      "Full-featured Monaco editor with YAML syntax highlighting for manual fine-tuning and customization.",
  },
];

export default function Home() {
  return (
    <div className="max-w-4xl mx-auto px-8 py-16">
      {/* Hero */}
      <div className="text-center space-y-6 mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-500/10 text-blue-400 text-xs font-medium">
          <Shield className="w-3.5 h-3.5" />
          Red Team Lab - Purple Team Tooling
        </div>

        <h1 className="text-4xl font-bold text-zinc-100 leading-tight">
          RTLPhishletGenerator
        </h1>

        <p className="text-lg text-zinc-400 max-w-2xl mx-auto leading-relaxed">
          Automated Evilginx phishlet generation for authorized red team
          engagements. Analyze target login flows and generate production-ready
          phishlet YAML configurations in seconds.
        </p>

        <div className="flex items-center justify-center gap-4 pt-4">
          <Link
            to="/generator"
            className="flex items-center gap-2 px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-colors"
          >
            <Zap className="w-4 h-4" />
            Get Started
          </Link>
          <a
            href="#features"
            className="px-6 py-3 rounded-lg border border-zinc-700 text-zinc-300 hover:bg-zinc-800 text-sm transition-colors"
          >
            Learn More
          </a>
        </div>
      </div>

      {/* Features */}
      <div id="features" className="grid grid-cols-2 gap-6 mb-16">
        {features.map((feature) => {
          const Icon = feature.icon;
          return (
            <div
              key={feature.title}
              className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 space-y-3 hover:border-zinc-700 transition-colors"
            >
              <div className="w-10 h-10 rounded-lg bg-zinc-800 flex items-center justify-center">
                <Icon className="w-5 h-5 text-blue-400" />
              </div>
              <h3 className="text-sm font-semibold text-zinc-200">
                {feature.title}
              </h3>
              <p className="text-sm text-zinc-400 leading-relaxed">
                {feature.description}
              </p>
            </div>
          );
        })}
      </div>

      {/* How it works */}
      <div className="space-y-6 mb-16">
        <h2 className="text-xl font-bold text-zinc-200 text-center">
          How It Works
        </h2>
        <div className="flex items-center justify-center gap-4">
          {[
            { step: "1", label: "Enter Target URL" },
            { step: "2", label: "Auto Analysis" },
            { step: "3", label: "Review Results" },
            { step: "4", label: "Export YAML" },
          ].map((item, i) => (
            <div key={item.step} className="flex items-center gap-4">
              <div className="text-center space-y-2">
                <div className="w-10 h-10 rounded-full bg-blue-600/20 text-blue-400 flex items-center justify-center text-sm font-bold mx-auto">
                  {item.step}
                </div>
                <p className="text-xs text-zinc-400">{item.label}</p>
              </div>
              {i < 3 && (
                <div className="w-12 h-px bg-zinc-700" />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Disclaimer */}
      <div className="p-4 rounded-lg bg-yellow-500/5 border border-yellow-500/20 text-center">
        <p className="text-xs text-yellow-400/80">
          This tool is designed exclusively for authorized red team and purple
          team security testing engagements. All users must have proper NDA and
          written authorization before use. Unauthorized use for malicious
          purposes is strictly prohibited.
        </p>
      </div>
    </div>
  );
}
