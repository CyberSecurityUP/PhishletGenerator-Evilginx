import { useEffect, useState } from "react";
import { Sparkles, CheckCircle2, XCircle, RefreshCw } from "lucide-react";
import { useAppStore } from "@/store/useAppStore";
import { checkAiStatus } from "@/services/api";

export default function Settings() {
  const { authorName, setAuthorName, aiStatus, setAiStatus } = useAppStore();
  const [checking, setChecking] = useState(false);

  const refreshAiStatus = async () => {
    setChecking(true);
    try {
      const status = await checkAiStatus();
      setAiStatus(status);
    } catch {
      setAiStatus({ enabled: false, model: null, connected: false });
    }
    setChecking(false);
  };

  useEffect(() => {
    refreshAiStatus();
  }, []);

  return (
    <div className="max-w-2xl mx-auto px-8 py-12 space-y-8">
      <div>
        <h2 className="text-lg font-bold text-zinc-100">Settings</h2>
        <p className="text-sm text-zinc-500 mt-1">
          Configure RTLPhishletGenerator preferences
        </p>
      </div>

      {/* Author */}
      <div className="space-y-3 p-6 bg-zinc-900 border border-zinc-800 rounded-lg">
        <h3 className="text-sm font-medium text-zinc-200">Default Author</h3>
        <input
          type="text"
          value={authorName}
          onChange={(e) => setAuthorName(e.target.value)}
          className="w-full px-4 py-2.5 rounded-lg bg-zinc-800 border border-zinc-700 text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
          placeholder="@yourhandle"
        />
        <p className="text-xs text-zinc-500">
          Used as the author field in generated phishlets. Saved to local
          storage.
        </p>
      </div>

      {/* AI Status */}
      <div className="space-y-3 p-6 bg-zinc-900 border border-zinc-800 rounded-lg">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-zinc-200 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-purple-400" />
            AI Integration
          </h3>
          <button
            onClick={refreshAiStatus}
            disabled={checking}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-400 text-xs transition-colors"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${checking ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between py-2">
            <span className="text-sm text-zinc-400">Status</span>
            {aiStatus.enabled ? (
              <span className="flex items-center gap-1.5 text-sm text-green-400">
                <CheckCircle2 className="w-4 h-4" />
                Enabled
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-sm text-zinc-500">
                <XCircle className="w-4 h-4" />
                Disabled
              </span>
            )}
          </div>

          {aiStatus.model && (
            <div className="flex items-center justify-between py-2">
              <span className="text-sm text-zinc-400">Model</span>
              <span className="text-sm text-zinc-300 font-mono">
                {aiStatus.model}
              </span>
            </div>
          )}

          <div className="flex items-center justify-between py-2">
            <span className="text-sm text-zinc-400">Connection</span>
            {aiStatus.connected ? (
              <span className="text-sm text-green-400">Connected</span>
            ) : (
              <span className="text-sm text-zinc-500">
                {aiStatus.enabled ? "Not connected" : "N/A"}
              </span>
            )}
          </div>
        </div>

        <div className="p-3 bg-zinc-800 rounded-lg">
          <p className="text-xs text-zinc-500">
            To enable AI enhancement, set <code className="text-zinc-400">AI_API_KEY</code> and{" "}
            <code className="text-zinc-400">AI_MODEL</code> in your{" "}
            <code className="text-zinc-400">.env</code> file. Supported
            providers: DeepSeek, Claude (Anthropic), OpenAI, and any
            litellm-compatible model.
          </p>
        </div>
      </div>

      {/* About */}
      <div className="space-y-3 p-6 bg-zinc-900 border border-zinc-800 rounded-lg">
        <h3 className="text-sm font-medium text-zinc-200">About</h3>
        <div className="space-y-2 text-sm text-zinc-400">
          <p>
            <span className="text-zinc-300">RTLPhishletGenerator</span> v1.0.0
          </p>
          <p>
            Automated Evilginx phishlet generator for authorized red team and
            purple team security testing engagements.
          </p>
          <p className="text-xs text-zinc-600 pt-2">
            Evilginx v3.2.0+ compatible
          </p>
        </div>
      </div>
    </div>
  );
}
