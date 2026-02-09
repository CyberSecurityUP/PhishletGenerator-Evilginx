import { useMutation } from "@tanstack/react-query";
import {
  analyzeUrl,
  generateFromUrl,
  generateFromAnalysis,
  validatePhishlet,
} from "@/services/api";
import { useAppStore } from "@/store/useAppStore";
import type { AnalysisResult } from "@/types";

export function useAnalyzeUrl() {
  const store = useAppStore();

  return useMutation({
    mutationFn: analyzeUrl,
    onMutate: () => {
      store.setIsAnalyzing(true);
      store.setCurrentStep("analyzing");
    },
    onSuccess: (data) => {
      store.setAnalysisResult(data);
      store.setIsAnalyzing(false);
      store.setCurrentStep("review");
    },
    onError: () => {
      store.setIsAnalyzing(false);
      store.setCurrentStep("input");
    },
  });
}

export function useGenerateFromUrl() {
  const store = useAppStore();

  return useMutation({
    mutationFn: generateFromUrl,
    onMutate: () => {
      store.setIsGenerating(true);
    },
    onSuccess: (data) => {
      store.setGenerationResult(data);
      store.setYamlContent(data.yaml_content);
      store.setIsGenerating(false);
      store.setCurrentStep("editor");
    },
    onError: () => {
      store.setIsGenerating(false);
    },
  });
}

export function useGenerateFromAnalysis() {
  const store = useAppStore();

  return useMutation({
    mutationFn: (params: {
      analysis: AnalysisResult;
      author?: string;
      use_ai?: boolean;
      custom_name?: string;
    }) => generateFromAnalysis(params),
    onMutate: () => {
      store.setIsGenerating(true);
    },
    onSuccess: (data) => {
      store.setGenerationResult(data);
      store.setYamlContent(data.yaml_content);
      store.setIsGenerating(false);
      store.setCurrentStep("editor");
    },
    onError: () => {
      store.setIsGenerating(false);
    },
  });
}

export function useValidatePhishlet() {
  const store = useAppStore();

  return useMutation({
    mutationFn: validatePhishlet,
    onSuccess: (data) => {
      store.setValidationResult(data);
    },
  });
}
