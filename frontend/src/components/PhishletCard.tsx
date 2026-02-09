import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Trash2,
  ExternalLink,
  Loader2,
  Clock,
} from "lucide-react";
import type { SavedPhishlet } from "@/types";

interface PhishletCardProps {
  phishlet: SavedPhishlet;
  onLoad: (phishlet: SavedPhishlet) => void;
  onDelete: (id: string) => void;
  isDeleting: boolean;
}

export default function PhishletCard({
  phishlet,
  onLoad,
  onDelete,
  isDeleting,
}: PhishletCardProps) {
  const statusIcon = {
    valid: <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />,
    invalid: <XCircle className="w-3.5 h-3.5 text-red-400" />,
    unknown: <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />,
  }[phishlet.validation_status];

  const statusColor = {
    valid: "text-green-400 bg-green-500/10",
    invalid: "text-red-400 bg-red-500/10",
    unknown: "text-yellow-400 bg-yellow-500/10",
  }[phishlet.validation_status];

  const timeAgo = (date: string) => {
    const diff = Date.now() - new Date(date).getTime();
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return "just now";
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  };

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 hover:border-zinc-700 transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-zinc-200 truncate">
            {phishlet.name}
          </h3>
          {phishlet.target_url && (
            <p className="text-xs text-zinc-500 truncate mt-0.5 font-mono">
              {phishlet.target_url}
            </p>
          )}
        </div>
        <span
          className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs shrink-0 ml-2 ${statusColor}`}
        >
          {statusIcon}
          {phishlet.validation_status}
        </span>
      </div>

      {phishlet.description && (
        <p className="text-xs text-zinc-400 mb-3 line-clamp-2">
          {phishlet.description}
        </p>
      )}

      {phishlet.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {phishlet.tags.map((tag) => (
            <span
              key={tag}
              className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 text-xs"
            >
              {tag}
            </span>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between pt-3 border-t border-zinc-800">
        <div className="flex items-center gap-1.5 text-xs text-zinc-600">
          <Clock className="w-3 h-3" />
          {timeAgo(phishlet.updated_at)}
          <span className="mx-1">·</span>
          <span>{phishlet.author}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => onDelete(phishlet.id)}
            disabled={isDeleting}
            className="p-1.5 rounded hover:bg-zinc-800 text-zinc-500 hover:text-red-400 transition-colors"
            title="Delete"
          >
            {isDeleting ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Trash2 className="w-3.5 h-3.5" />
            )}
          </button>
          <button
            onClick={() => onLoad(phishlet)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors"
          >
            <ExternalLink className="w-3 h-3" />
            Open
          </button>
        </div>
      </div>
    </div>
  );
}
