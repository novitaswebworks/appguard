import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Shield,
  ShieldAlert,
  Lock,
  Unlock,
  Fingerprint,
  KeyRound,
  Search,
  RefreshCw,
  FolderLock,
  Smartphone,
  CheckCircle2,
} from "lucide-react";

interface BiometricStatus {
  is_available: boolean;
  biometric_type: string;
  error_message?: string;
}

interface ScannedApp {
  name: string;
  bundle_id: string;
  path: string;
}

interface AppRule {
  bundle_id: string;
  name: string;
  path: string;
  is_locked: boolean;
  icon_base64?: string;
}

interface AppGuardConfig {
  master_pin_hash?: string;
  locked_apps: Record<string, AppRule>;
  locked_folders: string[];
  grace_period_seconds: number;
  stealth_mode: boolean;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"apps" | "vault" | "settings">("apps");
  const [biometrics, setBiometrics] = useState<BiometricStatus | null>(null);
  const [hasPin, setHasPin] = useState(false);
  const [config, setConfig] = useState<AppGuardConfig | null>(null);
  const [apps, setApps] = useState<ScannedApp[]>([]);
  const [search, setSearch] = useState("");
  const [loadingApps, setLoadingApps] = useState(false);

  // Lock Trigger Overlay State
  const [lockedTrigger, setLockedTrigger] = useState<{ bundle_id: string; name: string } | null>(null);
  const [pinInput, setPinInput] = useState("");
  const [pinError, setPinError] = useState(false);
  const [authSuccess, setAuthSuccess] = useState(false);

  // Master PIN setup state
  const [showPinSetup, setShowPinSetup] = useState(false);
  const [newPin, setNewPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [pinSetupError, setPinSetupError] = useState("");

  useEffect(() => {
    initApp();

    // Listen for background focus watchdog events
    const unlistenPromise = listen<{ bundle_id: string; name: string }>(
      "app-locked-triggered",
      (event) => {
        setLockedTrigger(event.payload);
        setPinInput("");
        setPinError(false);
        setAuthSuccess(false);
      }
    );

    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  async function initApp() {
    try {
      const bio = await invoke<BiometricStatus>("check_biometrics");
      setBiometrics(bio);

      const pinConfigured = await invoke<boolean>("is_pin_configured");
      setHasPin(pinConfigured);

      const cfg = await invoke<AppGuardConfig>("get_config");
      setConfig(cfg);

      loadInstalledApps();
    } catch (e) {
      console.error("Failed to initialize AppGuard:", e);
    }
  }

  async function loadInstalledApps() {
    setLoadingApps(true);
    try {
      const list = await invoke<ScannedApp[]>("get_installed_apps");
      setApps(list);
    } catch (e) {
      console.error("Error loading apps:", e);
    } finally {
      setLoadingApps(false);
    }
  }

  async function handleToggleApp(app: ScannedApp) {
    try {
      const isCurrentlyLocked = !!config?.locked_apps[app.bundle_id]?.is_locked;
      const rule: AppRule = {
        bundle_id: app.bundle_id,
        name: app.name,
        path: app.path,
        is_locked: !isCurrentlyLocked,
      };

      await invoke("toggle_lock_app", { app: rule });
      const updatedConfig = await invoke<AppGuardConfig>("get_config");
      setConfig(updatedConfig);
    } catch (e) {
      console.error("Failed to toggle app lock:", e);
    }
  }

  async function handleBiometricUnlock() {
    try {
      const success = await invoke<boolean>("authenticate_biometrics", {
        reason: `Unlock ${lockedTrigger?.name || "Application"}`,
      });
      if (success && lockedTrigger) {
        completeUnlock(lockedTrigger.bundle_id);
      }
    } catch (e) {
      console.error("Biometrics failed:", e);
      setPinError(true);
    }
  }

  async function handlePinSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!pinInput) return;

    try {
      const valid = await invoke<boolean>("verify_pin", { pin: pinInput });
      if (valid && lockedTrigger) {
        completeUnlock(lockedTrigger.bundle_id);
      } else {
        setPinError(true);
        setPinInput("");
      }
    } catch (e) {
      setPinError(true);
    }
  }

  async function completeUnlock(bundle_id: string) {
    setAuthSuccess(true);
    await invoke("unlock_app_session", { bundleId: bundle_id });
    setTimeout(() => {
      setLockedTrigger(null);
      setAuthSuccess(false);
    }, 600);
  }

  async function handleSavePin(e: React.FormEvent) {
    e.preventDefault();
    setPinSetupError("");
    if (newPin.length < 4) {
      setPinSetupError("PIN must be at least 4 digits");
      return;
    }
    if (newPin !== confirmPin) {
      setPinSetupError("PINs do not match");
      return;
    }

    try {
      await invoke("set_master_pin", { pin: newPin });
      setHasPin(true);
      setShowPinSetup(false);
      setNewPin("");
      setConfirmPin("");
    } catch (e: any) {
      setPinSetupError(String(e));
    }
  }

  const filteredApps = apps.filter((a) =>
    a.name.toLowerCase().includes(search.toLowerCase()) ||
    a.bundle_id.toLowerCase().includes(search.toLowerCase())
  );

  const lockedCount = Object.values(config?.locked_apps || {}).filter((a) => a.is_locked).length;

  return (
    <div className="flex h-screen w-screen bg-[#090a0f] text-slate-100 select-none overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-800/80 bg-[#0d0f18]/80 backdrop-blur-xl flex flex-col justify-between">
        <div>
          {/* Logo */}
          <div className="p-5 flex items-center gap-3 border-b border-slate-800/50">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-1.5">
                AppGuard
                <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
                  v0.1
                </span>
              </h1>
              <p className="text-xs text-slate-400">Native Biometric Shield</p>
            </div>
          </div>

          {/* Navigation */}
          <nav className="p-3 space-y-1">
            <button
              onClick={() => setActiveTab("apps")}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === "apps"
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Smartphone className="w-4 h-4" />
                <span>Protected Apps</span>
              </div>
              {lockedCount > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-semibold">
                  {lockedCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab("vault")}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === "vault"
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <FolderLock className="w-4 h-4" />
                <span>Encrypted Vaults</span>
              </div>
            </button>
          </nav>
        </div>

        {/* System Biometrics & Master PIN status */}
        <div className="p-4 border-t border-slate-800/60 bg-slate-900/40 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-300">
              <Fingerprint className="w-4 h-4 text-cyan-400" />
              <span>Biometrics</span>
            </div>
            <span
              className={`font-medium ${
                biometrics?.is_available ? "text-emerald-400" : "text-amber-400"
              }`}
            >
              {biometrics?.is_available ? biometrics.biometric_type : "Unavailable"}
            </span>
          </div>

          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-300">
              <KeyRound className="w-4 h-4 text-indigo-400" />
              <span>Master PIN</span>
            </div>
            {hasPin ? (
              <span className="text-emerald-400 font-medium">Configured</span>
            ) : (
              <button
                onClick={() => setShowPinSetup(true)}
                className="text-xs text-indigo-400 hover:underline font-medium"
              >
                Set PIN
              </button>
            )}
          </div>

          <button
            onClick={() => invoke("lock_all_sessions")}
            className="w-full mt-2 py-2 px-3 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Lock All Now</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-hidden bg-gradient-to-b from-[#090a0f] to-[#0c0d14]">
        {/* Top Header */}
        <header className="h-16 border-b border-slate-800/60 px-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold text-white">
              {activeTab === "apps" && "App Protection Engine"}
              {activeTab === "vault" && "Encrypted Folder Vaults"}
            </h2>
            <span className="text-xs text-slate-500">
              {apps.length} applications indexed
            </span>
          </div>

          {activeTab === "apps" && (
            <div className="flex items-center gap-3">
              <div className="relative w-72">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search applications..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <button
                onClick={loadInstalledApps}
                disabled={loadingApps}
                className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-all"
                title="Rescan Applications"
              >
                <RefreshCw className={`w-4 h-4 ${loadingApps ? "animate-spin" : ""}`} />
              </button>
            </div>
          )}
        </header>

        {/* Tab Body */}
        <section className="flex-1 overflow-y-auto p-6">
          {activeTab === "apps" && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
              {filteredApps.map((app) => {
                const isLocked = !!config?.locked_apps[app.bundle_id]?.is_locked;
                return (
                  <div
                    key={app.bundle_id}
                    className={`p-4 rounded-xl border transition-all flex items-center justify-between ${
                      isLocked
                        ? "bg-cyan-950/20 border-cyan-800/50 shadow-lg shadow-cyan-950/20"
                        : "bg-slate-900/40 border-slate-800/60 hover:border-slate-700/80"
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0 pr-3">
                      <div
                        className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${
                          isLocked
                            ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {isLocked ? <Lock className="w-5 h-5" /> : <Unlock className="w-5 h-5" />}
                      </div>
                      <div className="min-w-0">
                        <h4 className="text-sm font-semibold text-white truncate">
                          {app.name}
                        </h4>
                        <p className="text-xs text-slate-500 truncate" title={app.bundle_id}>
                          {app.bundle_id}
                        </p>
                      </div>
                    </div>

                    <button
                      onClick={() => handleToggleApp(app)}
                      className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                        isLocked ? "bg-cyan-500" : "bg-slate-800"
                      }`}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                          isLocked ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>
                );
              })}
            </div>
          )}

          {activeTab === "vault" && (
            <div className="h-full flex flex-col items-center justify-center text-center max-w-md mx-auto">
              <div className="w-16 h-16 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mb-4 shadow-xl shadow-indigo-500/10">
                <FolderLock className="w-8 h-8" />
              </div>
              <h3 className="text-lg font-bold text-white mb-2">Encrypted Folder Vaults</h3>
              <p className="text-sm text-slate-400 mb-6">
                Protect sensitive personal directories (Taxes, Financials, Journals) with zero-knowledge AES-256-GCM encryption.
              </p>
              <button className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 text-white font-medium text-sm hover:opacity-95 shadow-lg shadow-indigo-500/20 transition-all">
                + Create New Vault
              </button>
            </div>
          )}
        </section>
      </main>

      {/* Lock Trigger Modal (Triggered by active window focus) */}
      {lockedTrigger && (
        <div className="fixed inset-0 z-50 bg-[#090a0f]/90 backdrop-blur-2xl flex items-center justify-center p-4">
          <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-[#0e111a] p-8 shadow-2xl flex flex-col items-center text-center space-y-6">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center shadow-2xl shadow-cyan-500/30">
              {authSuccess ? (
                <CheckCircle2 className="w-8 h-8 text-white animate-bounce" />
              ) : (
                <ShieldAlert className="w-8 h-8 text-white" />
              )}
            </div>

            <div>
              <h3 className="text-xl font-bold text-white">{lockedTrigger.name} is Locked</h3>
              <p className="text-xs text-slate-400 mt-1">
                Biometric verification or Master PIN required to access
              </p>
            </div>

            {biometrics?.is_available && (
              <button
                onClick={handleBiometricUnlock}
                className="w-full py-3 px-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-lg shadow-cyan-500/20 cursor-pointer"
              >
                <Fingerprint className="w-5 h-5" />
                <span>Verify with {biometrics.biometric_type}</span>
              </button>
            )}

            <div className="w-full flex items-center gap-3">
              <div className="flex-1 h-px bg-slate-800" />
              <span className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">
                or enter PIN
              </span>
              <div className="flex-1 h-px bg-slate-800" />
            </div>

            <form onSubmit={handlePinSubmit} className="w-full space-y-3">
              <input
                type="password"
                maxLength={8}
                placeholder="••••"
                value={pinInput}
                onChange={(e) => {
                  setPinInput(e.target.value);
                  setPinError(false);
                }}
                className={`w-full text-center text-2xl tracking-[0.5em] py-2.5 rounded-xl bg-slate-900 border ${
                  pinError ? "border-red-500" : "border-slate-800 focus:border-cyan-500"
                } text-white focus:outline-none`}
                autoFocus
              />
              {pinError && (
                <p className="text-xs text-red-400 font-medium">Incorrect master PIN</p>
              )}
              <button
                type="submit"
                className="w-full py-2.5 rounded-xl bg-slate-800 hover:bg-slate-750 text-slate-200 text-xs font-semibold transition-all cursor-pointer"
              >
                Unlock with PIN
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Master PIN Setup Modal */}
      {showPinSetup && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4">
          <div className="w-full max-w-sm rounded-2xl border border-slate-800 bg-[#0e111a] p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-2.5 text-white">
              <KeyRound className="w-5 h-5 text-indigo-400" />
              <h3 className="font-bold">Set Master Recovery PIN</h3>
            </div>
            <p className="text-xs text-slate-400">
              Used when biometric sensor is unavailable or failed.
            </p>

            <form onSubmit={handleSavePin} className="space-y-3">
              <div>
                <label className="text-[11px] uppercase font-semibold text-slate-400">New PIN</label>
                <input
                  type="password"
                  maxLength={6}
                  value={newPin}
                  onChange={(e) => setNewPin(e.target.value)}
                  placeholder="At least 4 digits"
                  className="w-full mt-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white text-sm focus:outline-none focus:border-indigo-500"
                  autoFocus
                />
              </div>

              <div>
                <label className="text-[11px] uppercase font-semibold text-slate-400">Confirm PIN</label>
                <input
                  type="password"
                  maxLength={6}
                  value={confirmPin}
                  onChange={(e) => setConfirmPin(e.target.value)}
                  placeholder="Repeat PIN"
                  className="w-full mt-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white text-sm focus:outline-none focus:border-indigo-500"
                />
              </div>

              {pinSetupError && (
                <p className="text-xs text-red-400 font-medium">{pinSetupError}</p>
              )}

              <div className="flex gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowPinSetup(false)}
                  className="flex-1 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white shadow-md shadow-indigo-600/30"
                >
                  Save PIN
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
