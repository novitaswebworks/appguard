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
  Palette,
  Sun,
  Moon,
  Check,
} from "lucide-react";
import { THEMES, ThemeMode } from "./theme";

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
  const [activeTab, setActiveTab] = useState<"apps" | "vault" | "appearance">("apps");
  const [currentTheme, setCurrentTheme] = useState<ThemeMode>(() => {
    return (localStorage.getItem("appguard_theme") as ThemeMode) || "nordic";
  });

  const theme = THEMES[currentTheme] || THEMES.nordic;
  const isLight = theme.category === "light";

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
    localStorage.setItem("appguard_theme", currentTheme);
    document.body.style.backgroundColor = theme.colors.bgApp;
    document.body.style.color = theme.colors.textPrimary;
  }, [currentTheme, theme]);

  useEffect(() => {
    initApp();

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
    <div
      className="flex h-screen w-screen select-none overflow-hidden font-sans transition-colors duration-200"
      style={{
        backgroundColor: theme.colors.bgApp,
        color: theme.colors.textPrimary,
      }}
    >
      {/* Sidebar */}
      <aside
        className="w-64 border-r flex flex-col justify-between transition-colors duration-200"
        style={{
          backgroundColor: theme.colors.bgSidebar,
          borderColor: theme.colors.border,
        }}
      >
        <div>
          {/* Logo */}
          <div
            className="p-5 flex items-center gap-3 border-b"
            style={{ borderColor: theme.colors.border }}
          >
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center shadow-md text-white transition-transform duration-200 hover:scale-105"
              style={{
                backgroundColor: theme.colors.accent,
                boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
              }}
            >
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight flex items-center gap-1.5" style={{ color: theme.colors.textPrimary }}>
                AppGuard
                <span
                  className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded"
                  style={{
                    backgroundColor: theme.colors.badgeBg,
                    color: theme.colors.badgeText,
                  }}
                >
                  v0.1
                </span>
              </h1>
              <p className="text-xs" style={{ color: theme.colors.textSecondary }}>Biometric Lockbox</p>
            </div>
          </div>

          {/* Navigation */}
          <nav className="p-3 space-y-1">
            <button
              onClick={() => setActiveTab("apps")}
              className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all cursor-pointer"
              style={{
                backgroundColor: activeTab === "apps" ? (isLight ? "#e2e8f0" : "rgba(255,255,255,0.06)") : "transparent",
                color: activeTab === "apps" ? theme.colors.accent : theme.colors.textSecondary,
                fontWeight: activeTab === "apps" ? 600 : 500,
              }}
            >
              <div className="flex items-center gap-2.5">
                <Smartphone className="w-4 h-4" />
                <span>Protected Apps</span>
              </div>
              {lockedCount > 0 && (
                <span
                  className="text-xs px-2 py-0.5 rounded-full font-semibold"
                  style={{
                    backgroundColor: theme.colors.badgeBg,
                    color: theme.colors.badgeText,
                  }}
                >
                  {lockedCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab("vault")}
              className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all cursor-pointer"
              style={{
                backgroundColor: activeTab === "vault" ? (isLight ? "#e2e8f0" : "rgba(255,255,255,0.06)") : "transparent",
                color: activeTab === "vault" ? theme.colors.accent : theme.colors.textSecondary,
                fontWeight: activeTab === "vault" ? 600 : 500,
              }}
            >
              <div className="flex items-center gap-2.5">
                <FolderLock className="w-4 h-4" />
                <span>Encrypted Vaults</span>
              </div>
            </button>

            <button
              onClick={() => setActiveTab("appearance")}
              className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all cursor-pointer"
              style={{
                backgroundColor: activeTab === "appearance" ? (isLight ? "#e2e8f0" : "rgba(255,255,255,0.06)") : "transparent",
                color: activeTab === "appearance" ? theme.colors.accent : theme.colors.textSecondary,
                fontWeight: activeTab === "appearance" ? 600 : 500,
              }}
            >
              <div className="flex items-center gap-2.5">
                <Palette className="w-4 h-4" />
                <span>Theme & Colors</span>
              </div>
              <span className="text-xs uppercase font-mono px-1.5 py-0.5 rounded" style={{ color: theme.colors.textMuted }}>
                {theme.name.split(" ")[0]}
              </span>
            </button>
          </nav>
        </div>

        {/* System Biometrics & Master PIN status */}
        <div
          className="p-4 border-t space-y-3"
          style={{
            borderColor: theme.colors.border,
            backgroundColor: isLight ? "rgba(0,0,0,0.02)" : "rgba(255,255,255,0.02)",
          }}
        >
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2" style={{ color: theme.colors.textSecondary }}>
              <Fingerprint className="w-4 h-4" style={{ color: theme.colors.accent }} />
              <span>Biometrics</span>
            </div>
            <span className="font-semibold text-emerald-600 dark:text-emerald-400">
              {biometrics?.is_available ? biometrics.biometric_type : "Unavailable"}
            </span>
          </div>

          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2" style={{ color: theme.colors.textSecondary }}>
              <KeyRound className="w-4 h-4" style={{ color: theme.colors.accent }} />
              <span>Master PIN</span>
            </div>
            {hasPin ? (
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">Configured</span>
            ) : (
              <button
                onClick={() => setShowPinSetup(true)}
                className="text-xs hover:underline font-semibold cursor-pointer"
                style={{ color: theme.colors.accent }}
              >
                Set PIN
              </button>
            )}
          </div>

          <button
            onClick={() => invoke("lock_all_sessions")}
            className="w-full mt-2 py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer border border-red-500/20 bg-red-500/10 hover:bg-red-500/20 text-red-600 dark:text-red-400"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Lock All Now</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header */}
        <header
          className="h-16 border-b px-6 flex items-center justify-between transition-colors duration-200"
          style={{
            backgroundColor: theme.colors.bgHeader,
            borderColor: theme.colors.border,
          }}
        >
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold" style={{ color: theme.colors.textPrimary }}>
              {activeTab === "apps" && "App Protection Engine"}
              {activeTab === "vault" && "Encrypted Folder Vaults"}
              {activeTab === "appearance" && "Appearance & Color Schemes"}
            </h2>
            <span className="text-xs" style={{ color: theme.colors.textMuted }}>
              {activeTab === "apps" && `${apps.length} applications indexed`}
              {activeTab === "appearance" && "Customize your visual workspace"}
            </span>
          </div>

          {activeTab === "apps" && (
            <div className="flex items-center gap-3">
              <div className="relative w-72">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2" style={{ color: theme.colors.textMuted }} />
                <input
                  type="text"
                  placeholder="Search applications..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg border text-sm focus:outline-none transition-colors"
                  style={{
                    backgroundColor: theme.colors.bgInput,
                    borderColor: theme.colors.border,
                    color: theme.colors.textPrimary,
                  }}
                />
              </div>

              <button
                onClick={loadInstalledApps}
                disabled={loadingApps}
                className="p-2 rounded-lg border transition-all cursor-pointer hover:opacity-80"
                style={{
                  backgroundColor: theme.colors.bgCard,
                  borderColor: theme.colors.border,
                  color: theme.colors.textSecondary,
                }}
                title="Rescan Applications"
              >
                <RefreshCw className={`w-4 h-4 ${loadingApps ? "animate-spin" : ""}`} />
              </button>
            </div>
          )}
        </header>

        {/* Tab Body */}
        <section className="flex-1 overflow-y-auto p-6">
          {/* TAB 1: APPS */}
          {activeTab === "apps" && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
              {filteredApps.map((app) => {
                const isLocked = !!config?.locked_apps[app.bundle_id]?.is_locked;
                return (
                  <div
                    key={app.bundle_id}
                    className="p-4 rounded-xl border transition-all flex items-center justify-between shadow-xs"
                    style={{
                      backgroundColor: isLocked ? theme.colors.bgCardLocked : theme.colors.bgCard,
                      borderColor: isLocked ? theme.colors.borderLocked : theme.colors.borderCard,
                    }}
                  >
                    <div className="flex items-center gap-3 min-w-0 pr-3">
                      <div
                        className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 transition-colors"
                        style={{
                          backgroundColor: isLocked ? theme.colors.badgeBg : (isLight ? "#f1f5f9" : "#1e293b"),
                          color: isLocked ? theme.colors.accent : theme.colors.textMuted,
                        }}
                      >
                        {isLocked ? <Lock className="w-5 h-5" /> : <Unlock className="w-5 h-5" />}
                      </div>
                      <div className="min-w-0">
                        <h4 className="text-sm font-semibold truncate" style={{ color: theme.colors.textPrimary }}>
                          {app.name}
                        </h4>
                        <p className="text-xs truncate" style={{ color: theme.colors.textMuted }} title={app.bundle_id}>
                          {app.bundle_id}
                        </p>
                      </div>
                    </div>

                    <button
                      onClick={() => handleToggleApp(app)}
                      className="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                      style={{
                        backgroundColor: isLocked ? theme.colors.toggleActive : theme.colors.toggleInactive,
                      }}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                          isLocked ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>
                );
              })}
            </div>
          )}

          {/* TAB 2: VAULT */}
          {activeTab === "vault" && (
            <div className="h-full flex flex-col items-center justify-center text-center max-w-md mx-auto">
              <div
                className="w-16 h-16 rounded-2xl border flex items-center justify-center mb-4 shadow-xl"
                style={{
                  backgroundColor: theme.colors.badgeBg,
                  borderColor: theme.colors.borderLocked,
                  color: theme.colors.accent,
                }}
              >
                <FolderLock className="w-8 h-8" />
              </div>
              <h3 className="text-lg font-bold mb-2" style={{ color: theme.colors.textPrimary }}>
                Encrypted Folder Vaults
              </h3>
              <p className="text-sm mb-6" style={{ color: theme.colors.textSecondary }}>
                Protect sensitive personal directories (Taxes, Financials, Journals) with zero-knowledge AES-256-GCM encryption.
              </p>
              <button
                className="px-5 py-2.5 rounded-xl font-semibold text-sm hover:opacity-90 shadow-lg transition-all cursor-pointer"
                style={{
                  backgroundColor: theme.colors.accent,
                  color: theme.colors.accentText,
                  boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                }}
              >
                + Create New Vault
              </button>
            </div>
          )}

          {/* TAB 3: THEMES & COLOR PICKER */}
          {activeTab === "appearance" && (
            <div className="max-w-3xl space-y-8">
              <div>
                <h3 className="text-base font-bold mb-1" style={{ color: theme.colors.textPrimary }}>
                  Choose Your Palette
                </h3>
                <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                  Select from clean light themes or high-contrast dark themes to match your personal preference.
                </p>
              </div>

              {/* Light Themes */}
              <div>
                <div className="flex items-center gap-2 mb-3 text-xs font-semibold uppercase tracking-wider" style={{ color: theme.colors.textMuted }}>
                  <Sun className="w-4 h-4 text-amber-500" />
                  <span>Light Themes (Clean & Ergonomic)</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {(["nordic", "editorial"] as ThemeMode[]).map((mode) => {
                    const item = THEMES[mode];
                    const selected = currentTheme === mode;
                    return (
                      <div
                        key={mode}
                        onClick={() => setCurrentTheme(mode)}
                        className="p-5 rounded-2xl border-2 cursor-pointer transition-all hover:scale-[1.01] flex flex-col justify-between"
                        style={{
                          backgroundColor: item.colors.bgCard,
                          borderColor: selected ? item.colors.accent : item.colors.border,
                          boxShadow: selected ? `0 8px 24px ${item.colors.accentGlow}` : "none",
                        }}
                      >
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h4 className="font-bold text-sm" style={{ color: item.colors.textPrimary }}>
                              {item.name}
                            </h4>
                            <p className="text-xs" style={{ color: item.colors.textSecondary }}>
                              {mode === "nordic" ? "Crisp white with electric sapphire" : "Warm parchment with organic teal"}
                            </p>
                          </div>
                          {selected && (
                            <div
                              className="w-6 h-6 rounded-full flex items-center justify-center text-white"
                              style={{ backgroundColor: item.colors.accent }}
                            >
                              <Check className="w-3.5 h-3.5" />
                            </div>
                          )}
                        </div>

                        {/* Theme preview swatch */}
                        <div className="flex items-center gap-2 pt-2 border-t" style={{ borderColor: item.colors.border }}>
                          <span className="w-5 h-5 rounded-full border shadow-xs" style={{ backgroundColor: item.previewBg }} />
                          <span className="w-5 h-5 rounded-full shadow-xs" style={{ backgroundColor: item.previewAccent }} />
                          <span className="text-[11px] font-mono ml-auto" style={{ color: item.colors.textMuted }}>
                            {mode === "nordic" ? "#f8fafc" : "#faf9f6"}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Dark Themes */}
              <div>
                <div className="flex items-center gap-2 mb-3 text-xs font-semibold uppercase tracking-wider" style={{ color: theme.colors.textMuted }}>
                  <Moon className="w-4 h-4 text-indigo-400" />
                  <span>Dark Themes (Low Glare & Deep Focus)</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {(["slate", "obsidian"] as ThemeMode[]).map((mode) => {
                    const item = THEMES[mode];
                    const selected = currentTheme === mode;
                    return (
                      <div
                        key={mode}
                        onClick={() => setCurrentTheme(mode)}
                        className="p-5 rounded-2xl border-2 cursor-pointer transition-all hover:scale-[1.01] flex flex-col justify-between"
                        style={{
                          backgroundColor: item.colors.bgCard,
                          borderColor: selected ? item.colors.accent : item.colors.border,
                          boxShadow: selected ? `0 8px 24px ${item.colors.accentGlow}` : "none",
                        }}
                      >
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h4 className="font-bold text-sm" style={{ color: item.colors.textPrimary }}>
                              {item.name}
                            </h4>
                            <p className="text-xs" style={{ color: item.colors.textSecondary }}>
                              {mode === "slate" ? "Deep midnight navy with sky cyan" : "Pure obsidian with cyber glow"}
                            </p>
                          </div>
                          {selected && (
                            <div
                              className="w-6 h-6 rounded-full flex items-center justify-center text-white"
                              style={{ backgroundColor: item.colors.accent }}
                            >
                              <Check className="w-3.5 h-3.5" />
                            </div>
                          )}
                        </div>

                        {/* Theme preview swatch */}
                        <div className="flex items-center gap-2 pt-2 border-t" style={{ borderColor: item.colors.border }}>
                          <span className="w-5 h-5 rounded-full border shadow-xs" style={{ backgroundColor: item.previewBg }} />
                          <span className="w-5 h-5 rounded-full shadow-xs" style={{ backgroundColor: item.previewAccent }} />
                          <span className="text-[11px] font-mono ml-auto" style={{ color: item.colors.textMuted }}>
                            {mode === "slate" ? "#0f172a" : "#090a0f"}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </section>
      </main>

      {/* Lock Trigger Modal */}
      {lockedTrigger && (
        <div
          className="fixed inset-0 z-50 backdrop-blur-2xl flex items-center justify-center p-4 transition-all"
          style={{ backgroundColor: theme.colors.bgOverlay }}
        >
          <div
            className="w-full max-w-md rounded-2xl border p-8 shadow-2xl flex flex-col items-center text-center space-y-6"
            style={{
              backgroundColor: theme.colors.bgModal,
              borderColor: theme.colors.border,
            }}
          >
            <div
              className="w-16 h-16 rounded-2xl flex items-center justify-center shadow-xl text-white"
              style={{
                backgroundColor: theme.colors.accent,
                boxShadow: `0 12px 24px ${theme.colors.accentGlow}`,
              }}
            >
              {authSuccess ? (
                <CheckCircle2 className="w-8 h-8 text-white animate-bounce" />
              ) : (
                <ShieldAlert className="w-8 h-8 text-white" />
              )}
            </div>

            <div>
              <h3 className="text-xl font-bold" style={{ color: theme.colors.textPrimary }}>
                {lockedTrigger.name} is Locked
              </h3>
              <p className="text-xs mt-1" style={{ color: theme.colors.textSecondary }}>
                Biometric verification or Master PIN required to access
              </p>
            </div>

            {biometrics?.is_available && (
              <button
                onClick={handleBiometricUnlock}
                className="w-full py-3 px-4 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-md cursor-pointer hover:opacity-95"
                style={{
                  backgroundColor: theme.colors.accent,
                  color: theme.colors.accentText,
                  boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                }}
              >
                <Fingerprint className="w-5 h-5" />
                <span>Verify with {biometrics.biometric_type}</span>
              </button>
            )}

            <div className="w-full flex items-center gap-3">
              <div className="flex-1 h-px" style={{ backgroundColor: theme.colors.border }} />
              <span className="text-[11px] uppercase tracking-wider font-semibold" style={{ color: theme.colors.textMuted }}>
                or enter PIN
              </span>
              <div className="flex-1 h-px" style={{ backgroundColor: theme.colors.border }} />
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
                className="w-full text-center text-2xl tracking-[0.5em] py-2.5 rounded-xl border focus:outline-none"
                style={{
                  backgroundColor: theme.colors.bgInput,
                  borderColor: pinError ? "#ef4444" : theme.colors.border,
                  color: theme.colors.textPrimary,
                }}
                autoFocus
              />
              {pinError && (
                <p className="text-xs text-red-500 font-medium">Incorrect master PIN</p>
              )}
              <button
                type="submit"
                className="w-full py-2.5 rounded-xl text-xs font-semibold transition-all cursor-pointer border"
                style={{
                  backgroundColor: isLight ? "#f1f5f9" : "#1e293b",
                  borderColor: theme.colors.border,
                  color: theme.colors.textPrimary,
                }}
              >
                Unlock with PIN
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Master PIN Setup Modal */}
      {showPinSetup && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-md flex items-center justify-center p-4">
          <div
            className="w-full max-w-sm rounded-2xl border p-6 shadow-2xl space-y-4"
            style={{
              backgroundColor: theme.colors.bgModal,
              borderColor: theme.colors.border,
            }}
          >
            <div className="flex items-center gap-2.5" style={{ color: theme.colors.textPrimary }}>
              <KeyRound className="w-5 h-5" style={{ color: theme.colors.accent }} />
              <h3 className="font-bold">Set Master Recovery PIN</h3>
            </div>
            <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
              Used when biometric sensor is unavailable or failed.
            </p>

            <form onSubmit={handleSavePin} className="space-y-3">
              <div>
                <label className="text-[11px] uppercase font-semibold" style={{ color: theme.colors.textMuted }}>
                  New PIN
                </label>
                <input
                  type="password"
                  maxLength={6}
                  value={newPin}
                  onChange={(e) => setNewPin(e.target.value)}
                  placeholder="At least 4 digits"
                  className="w-full mt-1 px-3 py-2 rounded-lg border text-sm focus:outline-none"
                  style={{
                    backgroundColor: theme.colors.bgInput,
                    borderColor: theme.colors.border,
                    color: theme.colors.textPrimary,
                  }}
                  autoFocus
                />
              </div>

              <div>
                <label className="text-[11px] uppercase font-semibold" style={{ color: theme.colors.textMuted }}>
                  Confirm PIN
                </label>
                <input
                  type="password"
                  maxLength={6}
                  value={confirmPin}
                  onChange={(e) => setConfirmPin(e.target.value)}
                  placeholder="Repeat PIN"
                  className="w-full mt-1 px-3 py-2 rounded-lg border text-sm focus:outline-none"
                  style={{
                    backgroundColor: theme.colors.bgInput,
                    borderColor: theme.colors.border,
                    color: theme.colors.textPrimary,
                  }}
                />
              </div>

              {pinSetupError && (
                <p className="text-xs text-red-500 font-medium">{pinSetupError}</p>
              )}

              <div className="flex gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowPinSetup(false)}
                  className="flex-1 py-2 rounded-lg border text-xs font-semibold cursor-pointer"
                  style={{
                    backgroundColor: theme.colors.bgInput,
                    borderColor: theme.colors.border,
                    color: theme.colors.textSecondary,
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2 rounded-lg text-xs font-semibold text-white shadow-md cursor-pointer"
                  style={{
                    backgroundColor: theme.colors.accent,
                    boxShadow: `0 4px 12px ${theme.colors.accentGlow}`,
                  }}
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
