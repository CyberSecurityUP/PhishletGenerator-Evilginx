import { Loader2, CheckCircle2 } from "lucide-react";

interface AnalysisProgressProps {
  progress: { step: number; total: number; message: string };
}

const STEPS = [
  "Navigating to target URL...",
  "Extracting page content...",
  "Detecting login forms...",
  "Capturing cookies...",
  "Identifying auth endpoints...",
  "Building domain map...",
  "Finalizing analysis...",
];

export default function AnalysisProgress({ progress }: AnalysisProgressProps) {
  const percentage = Math.round((progress.step / progress.total) * 100);

  return (
    <div className="space-y-8">
      <div className="text-center space-y-2">
        <Loader2 className="w-10 h-10 text-blue-500 animate-spin mx-auto" />
        <h3 className="text-lg font-medium text-zinc-200">
          Analyzing Target
        </h3>
        <p className="text-sm text-zinc-400">{progress.message || "Starting analysis..."}</p>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-zinc-800 rounded-full h-2">
        <div
          className="bg-blue-500 h-2 rounded-full transition-all duration-500"
          style={{ width: `${percentage}%` }}
        />
      </div>

      {/* Steps list */}
      <div className="space-y-3">
        {STEPS.map((step, index) => {
          const stepNum = index + 1;
          const isComplete = progress.step > stepNum;
          const isCurrent = progress.step === stepNum;

          return (
            <div
              key={step}
              className={`flex items-center gap-3 text-sm ${
                isComplete
                  ? "text-green-400"
                  : isCurrent
                    ? "text-blue-400"
                    : "text-zinc-600"
              }`}
            >
              {isComplete ? (
                <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
              ) : isCurrent ? (
                <Loader2 className="w-4 h-4 animate-spin shrink-0" />
              ) : (
                <div className="w-4 h-4 rounded-full border border-zinc-700 shrink-0" />
              )}
              {step}
            </div>
          );
        })}
      </div>
    </div>
  );
}
