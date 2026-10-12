import { useEffect, useState, useCallback } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { getVersion } from "@tauri-apps/api/app";

const GITHUB_REPO = "novitaswebworks/appguard";
const LATEST_RELEASE_API = `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`;
const FALLBACK_VERSION = "0.8.0-beta.1";
const LAST_CHECK_KEY = "appguard:updater:last_check";
const CHECK_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

export interface ReleaseAsset {
  name: string;
  browser_download_url: string;
  size: number;
}

export interface UpdateInfo {
  version: string;
  currentVersion: string;
  releaseNotes: string;
  releaseUrl: string;
  publishedAt: string;
  assets: ReleaseAsset[];
}

export type UpdaterState =
  | { status: "idle" }
  | { status: "checking" }
  | { status: "up-to-date" }
  | { status: "available"; info: UpdateInfo }
  | { status: "error"; message: string };

function parseVersion(v: string): number[] {
  return v
    .replace(/^v/, "")
    .split("-")[0]
    .split(".")
    .map((p) => Number.parseInt(p, 10) || 0);
}

export function isNewer(remote: string, current: string): boolean {
  const a = parseVersion(remote);
  const b = parseVersion(current);
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return current.includes("-") && !remote.includes("-");
}

export function isReleaseUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "github.com" && !url.username && !url.password && !url.port && url.pathname.startsWith(`/${GITHUB_REPO}/releases/`);
  } catch { return false; }
}

export function useUpdater() {
  const [state, setState] = useState<UpdaterState>({ status: "idle" });
  const [currentVersion, setCurrentVersion] = useState<string>(FALLBACK_VERSION);

  useEffect(() => {
    getVersion()
      .then((ver) => setCurrentVersion(ver))
      .catch(() => setCurrentVersion(FALLBACK_VERSION));
  }, []);

  const checkForUpdates = useCallback(async (manual = false) => {
    if (!manual) {
      const lastCheck = localStorage.getItem(LAST_CHECK_KEY);
      if (lastCheck && Date.now() - Number.parseInt(lastCheck, 10) < CHECK_INTERVAL_MS) {
        return;
      }
    }

    setState({ status: "checking" });

    try {
      const [appVer, res] = await Promise.all([
        getVersion().catch(() => currentVersion),
        fetch(LATEST_RELEASE_API, {
          headers: { Accept: "application/vnd.github+json" },
        }),
      ]);

      if (!res.ok) {
        throw new Error(`GitHub API HTTP ${res.status}`);
      }

      localStorage.setItem(LAST_CHECK_KEY, Date.now().toString());

      const data = await res.json();
      if (typeof data.tag_name !== "string" || !/^v?\d+\.\d+\.\d+$/.test(data.tag_name) || data.draft || data.prerelease) {
        throw new Error("Unexpected release metadata from GitHub");
      }
      const remoteVersion = (data.tag_name || "").replace(/^v/, "");

      if (isNewer(remoteVersion, appVer)) {
        const assets: ReleaseAsset[] = Array.isArray(data.assets)
          ? data.assets.filter((a: any) => typeof a?.name === "string" && isReleaseUrl(a.browser_download_url) && Number.isFinite(a.size)).map((a: any) => ({
              name: a.name,
              browser_download_url: a.browser_download_url,
              size: a.size,
            }))
          : [];

        setState({
          status: "available",
          info: {
            version: remoteVersion,
            currentVersion: appVer,
            releaseNotes: typeof data.body === "string" ? data.body : "A new version of AppGuard is available.",
            releaseUrl: isReleaseUrl(data.html_url) ? data.html_url : `https://github.com/${GITHUB_REPO}/releases/latest`,
            publishedAt: data.published_at || new Date().toISOString(),
            assets,
          },
        });
      } else {
        setState({ status: "up-to-date" });
      }
    } catch (err: any) {
      console.warn("Update check failed:", err);
      setState({
        status: "error",
        message: err?.message || "Failed to check for updates.",
      });
    }
  }, [currentVersion]);

  const dismiss = useCallback(() => {
    setState({ status: "idle" });
  }, []);

  const openDownload = useCallback(async (url: string) => {
    if (!isReleaseUrl(url)) {
      setState({ status: "error", message: "Download URL is not an AppGuard GitHub release" });
      return;
    }
    try {
      await openUrl(url);
    } catch (error) {
      setState({ status: "error", message: `Could not open release: ${String(error)}` });
    }
  }, []);

  useEffect(() => {
    // Check in background on app launch
    const timer = setTimeout(() => {
      checkForUpdates(false);
    }, 2500);

    return () => clearTimeout(timer);
  }, [checkForUpdates]);

  return {
    state,
    checkForUpdates,
    dismiss,
    openDownload,
    currentVersion,
  };
}
