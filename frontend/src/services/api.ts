import axios from "axios";
import type {
  AnalysisResult,
  PhishletGenerateResponse,
  ValidationResult,
  AIStatus,
  ProgressUpdate,
  SavedPhishlet,
  SavedPhishletCreate,
  SavedPhishletList,
} from "@/types";

const api = axios.create({
  baseURL: "/api/v1",
  timeout: 120000,
});

export const analyzeUrl = async (url: string): Promise<AnalysisResult> => {
  const { data } = await api.post("/analyze/", { url });
  return data;
};

export const generateFromUrl = async (params: {
  url: string;
  author?: string;
  use_ai?: boolean;
  custom_name?: string;
}): Promise<PhishletGenerateResponse> => {
  const { data } = await api.post("/generate/from-url", params);
  return data;
};

export const generateFromAnalysis = async (params: {
  analysis: AnalysisResult;
  author?: string;
  use_ai?: boolean;
  custom_name?: string;
}): Promise<PhishletGenerateResponse> => {
  const { data } = await api.post("/generate/from-analysis", params);
  return data;
};

export const validatePhishlet = async (
  yamlContent: string
): Promise<ValidationResult> => {
  const { data } = await api.post("/validate/", { yaml_content: yamlContent });
  return data;
};

export const checkAiStatus = async (): Promise<AIStatus> => {
  const { data } = await api.get("/generate/ai-status");
  return data;
};

export const analyzeUrlWithProgress = (
  url: string,
  onProgress: (update: ProgressUpdate) => void,
  onComplete: (result: AnalysisResult) => void,
  onError: (error: string) => void
): WebSocket => {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/api/v1/analyze/ws`;
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    ws.send(JSON.stringify({ url }));
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.status === "complete") {
      onComplete(data.result);
    } else if (data.status === "error") {
      onError(data.message);
    } else {
      onProgress(data);
    }
  };

  ws.onerror = () => {
    onError("WebSocket connection failed. Falling back to REST API.");
  };

  return ws;
};

// --- Library CRUD ---
export const listPhishlets = async (): Promise<SavedPhishletList> => {
  const { data } = await api.get("/phishlets/");
  return data;
};

export const savePhishlet = async (
  params: SavedPhishletCreate
): Promise<SavedPhishlet> => {
  const { data } = await api.post("/phishlets/", params);
  return data;
};

export const getPhishlet = async (id: string): Promise<SavedPhishlet> => {
  const { data } = await api.get(`/phishlets/${id}`);
  return data;
};

export const deletePhishlet = async (id: string): Promise<void> => {
  await api.delete(`/phishlets/${id}`);
};
