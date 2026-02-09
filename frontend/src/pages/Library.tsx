import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  BookOpen,
  Search,
  Loader2,
  Plus,
} from "lucide-react";
import { useAppStore } from "@/store/useAppStore";
import { listPhishlets, deletePhishlet as apiDeletePhishlet } from "@/services/api";
import PhishletCard from "@/components/PhishletCard";
import type { SavedPhishlet } from "@/types";

export default function Library() {
  const {
    savedPhishlets,
    setSavedPhishlets,
    removeSavedPhishlet,
    setYamlContent,
    setCurrentStep,
    setGenerationResult,
  } = useAppStore();
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [deleting, setDeleting] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    loadPhishlets();
  }, []);

  const loadPhishlets = async () => {
    setLoading(true);
    try {
      const result = await listPhishlets();
      setSavedPhishlets(result.phishlets);
    } catch (err) {
      console.error("Failed to load phishlets:", err);
    }
    setLoading(false);
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this phishlet?")) return;
    setDeleting(id);
    try {
      await apiDeletePhishlet(id);
      removeSavedPhishlet(id);
    } catch (err) {
      console.error("Failed to delete:", err);
    }
    setDeleting(null);
  };

  const handleLoad = (phishlet: SavedPhishlet) => {
    setYamlContent(phishlet.yaml_content);
    setGenerationResult(null);
    setCurrentStep("editor");
    navigate("/generator");
  };

  const filtered = savedPhishlets.filter(
    (p) =>
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.target_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="px-8 py-6 border-b border-zinc-800">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-zinc-100 flex items-center gap-2">
              <BookOpen className="w-5 h-5" />
              Phishlet Library
            </h2>
            <p className="text-sm text-zinc-500 mt-1">
              {savedPhishlets.length} saved phishlet
              {savedPhishlets.length !== 1 ? "s" : ""}
            </p>
          </div>
          <button
            onClick={() => navigate("/generator")}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Phishlet
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="px-8 py-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
          <input
            type="text"
            placeholder="Search by name, URL, or tag..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
          />
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 px-8 pb-8 overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-16 space-y-3">
            <BookOpen className="w-12 h-12 text-zinc-700 mx-auto" />
            <p className="text-sm text-zinc-500">
              {searchQuery
                ? "No phishlets match your search."
                : "No saved phishlets yet."}
            </p>
            <p className="text-xs text-zinc-600">
              Generate a phishlet and save it to your library.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filtered.map((phishlet) => (
              <PhishletCard
                key={phishlet.id}
                phishlet={phishlet}
                onLoad={handleLoad}
                onDelete={handleDelete}
                isDeleting={deleting === phishlet.id}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
