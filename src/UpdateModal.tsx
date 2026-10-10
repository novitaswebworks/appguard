import { useState } from "react";
import {
  Sparkles,
  Download,
  ExternalLink,
  X,
  Terminal,
  Check,
  Copy,
} from "lucide-react";
import { UpdateInfo, detectUserPlatform } from "./useUpdater";
import { ThemeConfig } from "./theme";

interface UpdateModalProps {
  info: UpdateInfo;
  onDismiss: () => void;
  onDownloadUrl: (url: string) => void;
  theme: ThemeConfig;
}

export function UpdateModal({
  info,
  onDismiss,
  onDownloadUrl,
  theme,
}: UpdateModalProps) {
  const platform = detectUserPlatform();
  const [copiedCmd, setCopiedCmd] = useState(false);

  // Determine primary installer asset based on OS
  const macAsset = info.assets.find(
    (a) => a.name.endsWith(".dmg") || a.name.includes("universal.dmg")
  );
  const winAsset = info.assets.find(
    (a) => a.name.endsWith(".msi") || a.name.endsWith("-setup.exe")
  );
  const linuxAsset = info.assets.find(
    (a) => a.name.endsWith(".deb") || a.name.endsWith(".AppImage")
  );

  let primaryAsset = macAsset;
  let cliCommand = "brew upgrade --cask novitaswebworks/tap/appguard";
  let cliLabel = "Homebrew Terminal Upgrade";

  if (platform === "windows") {
    primaryAsset = winAsset;
    cliCommand = "winget upgrade NovitasWebWorks.AppGuard";
    cliLabel = "Windows Terminal Upgrade";
  } else if (platform === "linux") {
    primaryAsset = linuxAsset;
    cliCommand = "sudo apt update && sudo apt install --only-upgrade appguard";
    cliLabel = "Linux Package Upgrade";
  }

  const downloadTarget = primaryAsset?.browser_download_url || info.releaseUrl;

  const handleCopy = () => {
    navigator.clipboard.writeText(cliCommand);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-md flex items-center justify-center p-4 animate-in fade-in duration-200">
      <div
        className="w-full max-w-lg rounded-2xl border p-6 shadow-2xl space-y-5"
        style={{
          backgroundColor: theme.colors.bgModal,
          borderColor: theme.colors.borderCard,
          color: theme.colors.textPrimary,
        }}
      >
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center text-white shadow-lg"
              style={{
                backgroundColor: theme.colors.accent,
                boxShadow: `0 4px 14px ${theme.colors.accentGlow}`,
              }}
            >
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-base">New Version Available!</h3>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                  v{info.version}
                </span>
              </div>
              <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                You are currently running v{info.currentVersion}
              </p>
            </div>
          </div>
          <button
            onClick={onDismiss}
            className="p-1.5 rounded-lg opacity-60 hover:opacity-100 transition-opacity cursor-pointer"
            style={{ backgroundColor: theme.colors.bgInput }}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Release Notes */}
        <div
          className="p-3.5 rounded-xl border text-xs max-h-36 overflow-y-auto space-y-1.5"
          style={{
            backgroundColor: theme.colors.bgCard,
            borderColor: theme.colors.borderCard,
          }}
        >
          <div className="font-semibold flex items-center gap-1.5" style={{ color: theme.colors.accent }}>
            <span>What's new in v{info.version}:</span>
          </div>
          <p className="whitespace-pre-wrap leading-relaxed opacity-90" style={{ color: theme.colors.textSecondary }}>
            {info.releaseNotes}
          </p>
        </div>

        {/* Package Manager Fast Option */}
        <div
          className="p-3.5 rounded-xl border space-y-2"
          style={{
            backgroundColor: theme.colors.bgInput,
            borderColor: theme.colors.borderCard,
          }}
        >
          <div className="flex items-center justify-between text-xs font-semibold">
            <span className="flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" style={{ color: theme.colors.accent }} />
              {cliLabel}
            </span>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded cursor-pointer transition-all border"
              style={{
                borderColor: theme.colors.borderCard,
                backgroundColor: copiedCmd ? "rgba(16, 185, 129, 0.15)" : "transparent",
                color: copiedCmd ? "#10b981" : theme.colors.textPrimary,
              }}
            >
              {copiedCmd ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              <span>{copiedCmd ? "Copied" : "Copy"}</span>
            </button>
          </div>
          <code
            className="block text-[11px] font-mono p-2 rounded-lg select-all overflow-x-auto"
            style={{
              backgroundColor: "rgba(0, 0, 0, 0.25)",
              color: theme.colors.accent,
            }}
          >
            {cliCommand}
          </code>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3 pt-2">
          <button
            onClick={() => onDownloadUrl(info.releaseUrl)}
            className="px-4 py-2.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 cursor-pointer opacity-80 hover:opacity-100 transition-opacity"
            style={{
              borderColor: theme.colors.borderCard,
              backgroundColor: theme.colors.bgInput,
            }}
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>View Release</span>
          </button>

          <button
            onClick={() => onDownloadUrl(downloadTarget)}
            className="flex-1 py-2.5 rounded-xl text-xs font-semibold text-white shadow-lg flex items-center justify-center gap-2 cursor-pointer transition-transform active:scale-[0.98]"
            style={{
              backgroundColor: theme.colors.accent,
              boxShadow: `0 4px 14px ${theme.colors.accentGlow}`,
            }}
          >
            <Download className="w-4 h-4" />
            <span>Download {primaryAsset ? primaryAsset.name : "Installer"}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
