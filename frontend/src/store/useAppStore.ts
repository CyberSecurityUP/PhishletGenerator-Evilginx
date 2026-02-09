import { create } from "zustand";
import type {
  AnalysisResult,
  PhishletGenerateResponse,
  WizardStep,
  ValidationResult,
  AIStatus,
  SavedPhishlet,
} from "@/types";

interface AppState {
  // Wizard
  currentStep: WizardStep;
  setCurrentStep: (step: WizardStep) => void;

  // Analysis
  targetUrl: string;
  setTargetUrl: (url: string) => void;
  analysisResult: AnalysisResult | null;
  setAnalysisResult: (result: AnalysisResult | null) => void;
  isAnalyzing: boolean;
  setIsAnalyzing: (v: boolean) => void;
  analysisProgress: { step: number; total: number; message: string };
  setAnalysisProgress: (p: { step: number; total: number; message: string }) => void;

  // Generation
  generationResult: PhishletGenerateResponse | null;
  setGenerationResult: (result: PhishletGenerateResponse | null) => void;
  isGenerating: boolean;
  setIsGenerating: (v: boolean) => void;

  // Editor
  yamlContent: string;
  setYamlContent: (content: string) => void;

  // Validation
  validationResult: ValidationResult | null;
  setValidationResult: (result: ValidationResult | null) => void;

  // Settings
  authorName: string;
  setAuthorName: (name: string) => void;
  useAI: boolean;
  setUseAI: (v: boolean) => void;
  aiStatus: AIStatus;
  setAiStatus: (status: AIStatus) => void;

  // Library
  savedPhishlets: SavedPhishlet[];
  setSavedPhishlets: (phishlets: SavedPhishlet[]) => void;
  addSavedPhishlet: (phishlet: SavedPhishlet) => void;
  removeSavedPhishlet: (id: string) => void;

  // Reset
  resetAll: () => void;
}

const initialState = {
  currentStep: "input" as WizardStep,
  targetUrl: "",
  analysisResult: null,
  isAnalyzing: false,
  analysisProgress: { step: 0, total: 7, message: "" },
  generationResult: null,
  isGenerating: false,
  yamlContent: "",
  validationResult: null,
  authorName: localStorage.getItem("rtl_author") || "@rtlphishletgen",
  useAI: false,
  aiStatus: { enabled: false, model: null, connected: false },
  savedPhishlets: [] as SavedPhishlet[],
};

export const useAppStore = create<AppState>((set) => ({
  ...initialState,

  setCurrentStep: (step) => set({ currentStep: step }),

  setTargetUrl: (url) => set({ targetUrl: url }),
  setAnalysisResult: (result) => set({ analysisResult: result }),
  setIsAnalyzing: (v) => set({ isAnalyzing: v }),
  setAnalysisProgress: (p) => set({ analysisProgress: p }),

  setGenerationResult: (result) => set({ generationResult: result }),
  setIsGenerating: (v) => set({ isGenerating: v }),

  setYamlContent: (content) => set({ yamlContent: content }),

  setValidationResult: (result) => set({ validationResult: result }),

  setAuthorName: (name) => {
    localStorage.setItem("rtl_author", name);
    set({ authorName: name });
  },
  setUseAI: (v) => set({ useAI: v }),
  setAiStatus: (status) => set({ aiStatus: status }),

  setSavedPhishlets: (phishlets) => set({ savedPhishlets: phishlets }),
  addSavedPhishlet: (phishlet) =>
    set((state) => ({ savedPhishlets: [phishlet, ...state.savedPhishlets] })),
  removeSavedPhishlet: (id) =>
    set((state) => ({
      savedPhishlets: state.savedPhishlets.filter((p) => p.id !== id),
    })),

  resetAll: () =>
    set({
      ...initialState,
      authorName: localStorage.getItem("rtl_author") || "@rtlphishletgen",
    }),
}));
