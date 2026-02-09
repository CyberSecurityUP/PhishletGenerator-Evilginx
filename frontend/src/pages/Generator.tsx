import { useEffect } from "react";
import { useAppStore } from "@/store/useAppStore";
import {
  useAnalyzeUrl,
  useGenerateFromAnalysis,
} from "@/hooks/useAnalysis";
import { checkAiStatus, analyzeUrlWithProgress } from "@/services/api";
import URLInput from "@/components/URLInput";
import AnalysisProgress from "@/components/AnalysisProgress";
import AnalysisReview from "@/components/AnalysisReview";
import PhishletEditor from "@/components/PhishletEditor";

export default function Generator() {
  const store = useAppStore();
  const analyzeMutation = useAnalyzeUrl();
  const generateMutation = useGenerateFromAnalysis();

  // Check AI status on mount
  useEffect(() => {
    checkAiStatus()
      .then((status) => store.setAiStatus(status))
      .catch(() =>
        store.setAiStatus({ enabled: false, model: null, connected: false })
      );
  }, []);

  const handleSubmit = (params: {
    url: string;
    author: string;
    use_ai: boolean;
    custom_name: string;
  }) => {
    store.setTargetUrl(params.url);
    store.setIsAnalyzing(true);
    store.setCurrentStep("analyzing");

    // Try WebSocket first for real-time progress
    try {
      analyzeUrlWithProgress(
        params.url,
        (update) => {
          store.setAnalysisProgress({
            step: update.step,
            total: update.total_steps,
            message: update.message,
          });
        },
        (result) => {
          store.setAnalysisResult(result);
          store.setIsAnalyzing(false);
          store.setCurrentStep("review");
        },
        (error) => {
          console.warn("WebSocket failed, falling back to REST:", error);
          // Update progress to show we're using REST fallback
          store.setAnalysisProgress({
            step: 1,
            total: 7,
            message: "Analyzing (this may take a moment)...",
          });
          analyzeMutation.mutate(params.url);
        }
      );
    } catch {
      // Fallback to REST API
      store.setAnalysisProgress({
        step: 1,
        total: 7,
        message: "Analyzing (this may take a moment)...",
      });
      analyzeMutation.mutate(params.url);
    }
  };

  const handleGenerate = () => {
    if (!store.analysisResult) return;
    generateMutation.mutate({
      analysis: store.analysisResult,
      author: store.authorName,
      use_ai: store.useAI,
    });
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="px-8 py-6 border-b border-zinc-800">
        <h2 className="text-lg font-bold text-zinc-100">Phishlet Generator</h2>
        <p className="text-sm text-zinc-500 mt-1">
          {store.currentStep === "input" && "Enter a target URL to begin analysis"}
          {store.currentStep === "analyzing" && "Analyzing target authentication flow..."}
          {store.currentStep === "review" && "Review analysis results before generating"}
          {store.currentStep === "editor" && "Edit and export your phishlet YAML"}
        </p>
      </div>

      {/* Content */}
      <div className="flex-1 p-8 overflow-auto">
        {store.currentStep === "input" && (
          <div className="max-w-xl mx-auto">
            <URLInput
              onSubmit={handleSubmit}
              isLoading={store.isAnalyzing}
            />
          </div>
        )}

        {store.currentStep === "analyzing" && (
          <div className="max-w-md mx-auto">
            <AnalysisProgress progress={store.analysisProgress} />
          </div>
        )}

        {store.currentStep === "review" && store.analysisResult && (
          <div className="max-w-3xl mx-auto">
            <AnalysisReview
              analysis={store.analysisResult}
              onGenerate={handleGenerate}
              isGenerating={store.isGenerating}
              onBack={() => store.setCurrentStep("input")}
            />
          </div>
        )}

        {store.currentStep === "editor" && (
          <div className="h-[calc(100vh-200px)]">
            <PhishletEditor />
          </div>
        )}
      </div>
    </div>
  );
}
