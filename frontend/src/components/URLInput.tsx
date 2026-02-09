import { useState } from "react";
import { Zap, Sparkles, AlertTriangle } from "lucide-react";
import { useAppStore } from "@/store/useAppStore";

interface URLInputProps {
  onSubmit: (params: {
    url: string;
    author: string;
    use_ai: boolean;
    custom_name: string;
  }) => void;
  isLoading: boolean;
}

export default function URLInput({ onSubmit, isLoading }: URLInputProps) {
  const { authorName, setAuthorName, useAI, setUseAI, aiStatus } =
    useAppStore();
  const [url, setUrl] = useState("");
  const [customName, setCustomName] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      new URL(url);
    } catch {
      setError("Please enter a valid URL (e.g., https://example.com/login)");
      return;
    }

    if (!url.startsWith("http")) {
      setError("URL must start with http:// or https://");
      return;
    }

    onSubmit({ url, author: authorName, use_ai: useAI, custom_name: customName });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* URL Input */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-zinc-300">
          Target URL
        </label>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://target.com/login"
          className="w-full px-4 py-3 rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
          disabled={isLoading}
        />
        {error && (
          <p className="text-sm text-red-400 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            {error}
          </p>
        )}
        <p className="text-xs text-zinc-500">
          Enter the login page URL of the target application
        </p>
      </div>

      {/* Author */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-zinc-300">
          Author
        </label>
        <input
          type="text"
          value={authorName}
          onChange={(e) => setAuthorName(e.target.value)}
          placeholder="@yourhandle"
          className="w-full px-4 py-3 rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
          disabled={isLoading}
        />
      </div>

      {/* Custom Name */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-zinc-300">
          Custom Phishlet Name{" "}
          <span className="text-zinc-500">(optional)</span>
        </label>
        <input
          type="text"
          value={customName}
          onChange={(e) => setCustomName(e.target.value)}
          placeholder="Auto-detected from target"
          className="w-full px-4 py-3 rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
          disabled={isLoading}
        />
      </div>

      {/* AI Toggle */}
      <div className="flex items-center justify-between p-4 rounded-lg bg-zinc-900 border border-zinc-700">
        <div className="flex items-center gap-3">
          <Sparkles className="w-5 h-5 text-purple-400" />
          <div>
            <p className="text-sm font-medium text-zinc-200">
              AI Enhancement
            </p>
            <p className="text-xs text-zinc-500">
              {aiStatus.enabled
                ? `Using ${aiStatus.model}`
                : "Configure an API key in .env to enable"}
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setUseAI(!useAI)}
          disabled={!aiStatus.enabled || isLoading}
          className={`relative w-11 h-6 rounded-full transition-colors ${
            useAI && aiStatus.enabled
              ? "bg-purple-600"
              : "bg-zinc-700"
          } ${!aiStatus.enabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
        >
          <span
            className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
              useAI && aiStatus.enabled ? "translate-x-5" : ""
            }`}
          />
        </button>
      </div>

      {/* Submit */}
      <button
        type="submit"
        disabled={isLoading || !url}
        className="w-full flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-zinc-700 disabled:cursor-not-allowed text-white font-medium text-sm transition-colors"
      >
        <Zap className="w-4 h-4" />
        {isLoading ? "Analyzing..." : "Analyze & Generate"}
      </button>

      {/* Disclaimer */}
      <p className="text-xs text-zinc-600 text-center">
        For authorized red team engagements only. Ensure proper NDA and
        authorization before use.
      </p>
    </form>
  );
}
