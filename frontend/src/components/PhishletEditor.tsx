import { useRef, useState } from "react";
import Editor from "@monaco-editor/react";
import {
  CheckCircle2,
  Copy,
  Download,
  RotateCcw,
  AlertTriangle,
  XCircle,
  Loader2,
  Save,
} from "lucide-react";
import { useAppStore } from "@/store/useAppStore";
import { useValidatePhishlet } from "@/hooks/useAnalysis";
import { savePhishlet } from "@/services/api";

export default function PhishletEditor() {
  const {
    yamlContent,
    setYamlContent,
    validationResult,
    generationResult,
    resetAll,
    targetUrl,
    authorName,
    addSavedPhishlet,
  } = useAppStore();

  const validateMutation = useValidatePhishlet();
  const editorRef = useRef<unknown>(null);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(yamlContent);
  };

  const handleDownload = () => {
    const name = generationResult?.phishlet.name || "phishlet";
    const blob = new Blob([yamlContent], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name}.yaml`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleValidate = () => {
    validateMutation.mutate(yamlContent);
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveSuccess(false);
    try {
      const name = generationResult?.phishlet.name || "untitled";
      const saved = await savePhishlet({
        name,
        author: authorName,
        target_url: targetUrl,
        yaml_content: yamlContent,
      });
      addSavedPhishlet(saved);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      console.error("Failed to save phishlet:", err);
    }
    setSaving(false);
  };

  return (
    <div className="flex gap-4 h-full">
      {/* Editor */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Toolbar */}
        <div className="flex items-center justify-between p-3 bg-zinc-900 border border-zinc-800 rounded-t-lg">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-medium text-zinc-300">
              Phishlet YAML Editor
            </h3>
            {generationResult?.phishlet.name && (
              <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 text-xs font-mono">
                {generationResult.phishlet.name}.yaml
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <button
              onClick={handleValidate}
              disabled={validateMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors"
            >
              {validateMutation.isPending ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <CheckCircle2 className="w-3.5 h-3.5" />
              )}
              Validate
            </button>
            <button
              onClick={handleSave}
              disabled={saving || !yamlContent}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs transition-colors ${
                saveSuccess
                  ? "bg-green-600 text-white"
                  : "bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
              }`}
            >
              {saving ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : saveSuccess ? (
                <CheckCircle2 className="w-3.5 h-3.5" />
              ) : (
                <Save className="w-3.5 h-3.5" />
              )}
              {saveSuccess ? "Saved!" : "Save"}
            </button>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors"
            >
              <Copy className="w-3.5 h-3.5" />
              Copy
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-500 text-white text-xs transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Download
            </button>
            <button
              onClick={resetAll}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-400 text-xs transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              New
            </button>
          </div>
        </div>

        {/* Monaco Editor */}
        <div className="flex-1 border border-t-0 border-zinc-800 rounded-b-lg overflow-hidden">
          <Editor
            height="100%"
            defaultLanguage="yaml"
            value={yamlContent}
            onChange={(value) => setYamlContent(value || "")}
            onMount={(editor) => {
              editorRef.current = editor;
            }}
            theme="vs-dark"
            options={{
              fontSize: 13,
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
              minimap: { enabled: false },
              lineNumbers: "on",
              wordWrap: "on",
              scrollBeyondLastLine: false,
              padding: { top: 16 },
              renderLineHighlight: "line",
              tabSize: 2,
            }}
          />
        </div>
      </div>

      {/* Sidebar: Validation + Warnings */}
      <div className="w-80 space-y-4 shrink-0">
        {/* Validation Result */}
        {validationResult && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-2">
              {validationResult.valid ? (
                <>
                  <CheckCircle2 className="w-5 h-5 text-green-400" />
                  <span className="text-sm font-medium text-green-400">
                    Valid Phishlet
                  </span>
                </>
              ) : (
                <>
                  <XCircle className="w-5 h-5 text-red-400" />
                  <span className="text-sm font-medium text-red-400">
                    Invalid Phishlet
                  </span>
                </>
              )}
            </div>

            {validationResult.errors.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium text-red-400 uppercase tracking-wide">
                  Errors
                </p>
                {validationResult.errors.map((err, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 text-xs text-red-300 bg-red-500/5 p-2 rounded"
                  >
                    <XCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    {err}
                  </div>
                ))}
              </div>
            )}

            {validationResult.warnings.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium text-yellow-400 uppercase tracking-wide">
                  Warnings
                </p>
                {validationResult.warnings.map((warn, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 text-xs text-yellow-300 bg-yellow-500/5 p-2 rounded"
                  >
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    {warn}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Generation Warnings */}
        {generationResult &&
          (generationResult.warnings.length > 0 ||
            generationResult.suggestions.length > 0) && (
            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 space-y-3">
              <p className="text-sm font-medium text-zinc-300">
                Generation Notes
              </p>

              {generationResult.warnings.map((w, i) => (
                <div
                  key={`w-${i}`}
                  className="flex items-start gap-2 text-xs text-yellow-300 bg-yellow-500/5 p-2 rounded"
                >
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                  {w}
                </div>
              ))}

              {generationResult.suggestions.map((s, i) => (
                <div
                  key={`s-${i}`}
                  className="flex items-start gap-2 text-xs text-blue-300 bg-blue-500/5 p-2 rounded"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                  {s}
                </div>
              ))}
            </div>
          )}

        {/* Quick Reference */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 space-y-2">
          <p className="text-sm font-medium text-zinc-300">Quick Reference</p>
          <div className="text-xs text-zinc-500 space-y-1">
            <p>
              <span className="text-zinc-400">proxy_hosts</span> - Domains to
              proxy
            </p>
            <p>
              <span className="text-zinc-400">auth_tokens</span> - Session
              cookies to capture
            </p>
            <p>
              <span className="text-zinc-400">credentials</span> - Form fields
              to extract
            </p>
            <p>
              <span className="text-zinc-400">auth_urls</span> - Post-login
              URL patterns
            </p>
            <p>
              <span className="text-zinc-400">login</span> - Login page
              domain/path
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
