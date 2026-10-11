import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import { isEnabled, enable, disable } from "@tauri-apps/plugin-autostart";
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
  FolderPlus,
  Trash2,
  HardDrive,
  Power,
  Settings,
  Clock,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { THEMES, ThemeMode } from "./theme";
import { useUpdater } from "./useUpdater";
import { UpdateModal } from "./UpdateModal";

interface BiometricStatus {
  is_available: boolean;
  biometric_type: string;
  has_system_passcode?: boolean;
  error_message?: string;
}

interface VaultItem {
  path: string;
  name: string;
  is_locked: boolean;
  file_count: number;
  total_size_bytes: number;
}

interface ScannedApp {
  name: string;
  bundle_id: string;
  path: string;
  icon_path?: string;
  icon_base64?: string;
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
  app_self_locked: boolean;
  lock_on_sleep: boolean;
  lock_on_screensaver: boolean;
  instant_lock_mode: boolean;
  tamper_protection_enabled?: boolean;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"apps" | "vault" | "appearance" | "settings">("apps");
  const [currentTheme, setCurrentTheme] = useState<ThemeMode>(() => {
    return (localStorage.getItem("appguard_theme") as ThemeMode) || "nordic";
  });

  const theme = THEMES[currentTheme] || THEMES.nordic;
  const isLight = theme.category === "light";

  // Auto-updater hook
  const {
    state: updaterState,
    checkForUpdates,
    dismiss: dismissUpdater,
    openDownload,
    currentVersion,
  } = useUpdater();

  const [biometrics, setBiometrics] = useState<BiometricStatus | null>(null);
  const [hasPin, setHasPin] = useState(false);
  const [config, setConfig] = useState<AppGuardConfig | null>(null);
  const [apps, setApps] = useState<ScannedApp[]>([]);
  const [search, setSearch] = useState("");
  const [appFilter, setAppFilter] = useState<"all" | "locked" | "unlocked">("all");
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

  // Folder Vaults state
  const [vaults, setVaults] = useState<VaultItem[]>([]);
  const [loadingVaults, setLoadingVaults] = useState(false);
  const [vaultActionLoading, setVaultActionLoading] = useState<string | null>(null);

  // Autostart toggle state
  const [autostartEnabled, setAutostartEnabled] = useState(false);

  // In-app PIN Dialog for Encrypted Vaults
  const [vaultPinModal, setVaultPinModal] = useState<{
    item: VaultItem;
    action: "encrypt" | "decrypt";
    pin: string;
    error: string;
  } | null>(null);

  // AppGuard Self-Lock Gate (Protects AppGuard itself from unauthorized access)
  const [isAppLocked, setIsAppLocked] = useState(false);
  const [selfLockPinInput, setSelfLockPinInput] = useState("");
  const [selfLockPinError, setSelfLockPinError] = useState(false);
  const [selfLockAuthSuccess, setSelfLockAuthSuccess] = useState(false);
  const [lockAllSuccess, setLockAllSuccess] = useState(false);

  // First time 3-step setup wizard
  const [showWelcomeSetup, setShowWelcomeSetup] = useState(false);
  const [wizardStep, setWizardStep] = useState<1 | 2 | 3>(1);
  const [wizardPin, setWizardPin] = useState("");
  const [wizardConfirmPin, setWizardConfirmPin] = useState("");
  const [wizardError, setWizardError] = useState("");
  const [wizardSelectedBundles, setWizardSelectedBundles] = useState<Set<string>>(
    new Set(["com.apple.Notes", "com.apple.MobileSMS", "com.apple.Photos", "com.apple.Terminal"])
  );

  // Settings tab state
  const [changePinModalOpen, setChangePinModalOpen] = useState(false);
  const [oldPinInput, setOldPinInput] = useState("");
  const [newChangePinInput, setNewChangePinInput] = useState("");
  const [confirmChangePinInput, setConfirmChangePinInput] = useState("");
  const [changePinError, setChangePinError] = useState("");
  const [changePinSuccess, setChangePinSuccess] = useState(false);
  const [settingsSaveFeedback, setSettingsSaveFeedback] = useState(false);

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

        // Auto-trigger biometric dialog without requiring manual click
        setTimeout(() => {
          invoke<boolean>("authenticate_biometrics", {
            reason: `Unlock ${event.payload.name}`,
          })
            .then((success) => {
              if (success) {
                completeUnlock(event.payload.bundle_id);
              }
            })
            .catch(() => {
              // User cancelled Touch ID or fell back to PIN
            });
        }, 150);
      }
    );

    const unlistenLocked = listen("sessions-locked", () => {
      setIsAppLocked(true);
      setLockAllSuccess(true);
      setTimeout(() => setLockAllSuccess(false), 2000);
    });

    return () => {
      unlistenPromise.then((unlisten) => unlisten());
      unlistenLocked.then((unlisten) => unlisten());
    };
  }, []);

  async function initApp() {
    try {
      const bio = await invoke<BiometricStatus>("check_biometrics");
      setBiometrics(bio);

      const pinConfigured = await invoke<boolean>("is_pin_configured");
      setHasPin(pinConfigured);
      if (!pinConfigured) {
        setShowWelcomeSetup(true);
      } else {
        const isAuth = await invoke<boolean>("is_app_authenticated");
        if (!isAuth) {
          setIsAppLocked(true);
          // Try auto biometric verification if available
          if (bio.is_available) {
            setTimeout(() => {
              handleSelfLockBiometric();
            }, 250);
          }
        }
      }

      const cfg = await invoke<AppGuardConfig>("get_config");
      setConfig(cfg);

      loadInstalledApps();
      loadVaults();

      try {
        const auto = await isEnabled();
        setAutostartEnabled(auto);
      } catch (err) {
        console.warn("Autostart check failed:", err);
      }
    } catch (e) {
      console.error("Failed to initialize AppGuard:", e);
    }
  }

  async function loadVaults() {
    setLoadingVaults(true);
    try {
      const items = await invoke<VaultItem[]>("inspect_folder_vaults");
      setVaults(items);
    } catch (e) {
      console.error("Failed to load vaults:", e);
    } finally {
      setLoadingVaults(false);
    }
  }

  async function handleToggleAutostart() {
    try {
      if (autostartEnabled) {
        await disable();
        setAutostartEnabled(false);
      } else {
        await enable();
        setAutostartEnabled(true);
      }
    } catch (e) {
      console.error("Error toggling autostart:", e);
    }
  }

  async function handleSelectFolder() {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Select Directory to Protect",
      });
      if (selected && typeof selected === "string") {
        await invoke("add_folder_to_vault", { folderPath: selected });
        loadVaults();
      }
    } catch (e) {
      console.error("Folder selection failed:", e);
    }
  }

  async function handleRemoveVault(folderPath: string) {
    try {
      await invoke("remove_folder_from_vault", { folderPath });
      loadVaults();
    } catch (e) {
      console.error("Failed to remove vault folder:", e);
    }
  }

  function handleToggleVaultLock(item: VaultItem) {
    if (!hasPin) {
      setShowPinSetup(true);
      return;
    }

    setVaultPinModal({
      item,
      action: item.is_locked ? "decrypt" : "encrypt",
      pin: "",
      error: "",
    });
  }

  async function handleVaultPinSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!vaultPinModal || !vaultPinModal.pin) return;

    const { item, action, pin } = vaultPinModal;
    setVaultActionLoading(item.path);
    try {
      if (action === "decrypt") {
        await invoke("decrypt_vault_folder", { folderPath: item.path, pin });
      } else {
        await invoke("encrypt_vault_folder", { folderPath: item.path, pin });
      }
      setVaultPinModal(null);
      loadVaults();
    } catch (err: any) {
      setVaultPinModal((prev) => prev ? { ...prev, error: String(err) } : null);
    } finally {
      setVaultActionLoading(null);
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

  async function handleSelfLockBiometric() {
    try {
      const authLabel = biometrics?.biometric_type === "SystemPassword"
        ? "Authenticate with macOS Password to open AppGuard"
        : `Authenticate with ${biometrics?.biometric_type || "Touch ID"} to open AppGuard`;

      const success = await invoke<boolean>("authenticate_biometrics", {
        reason: authLabel,
      });
      if (success) {
        await invoke("unlock_appguard");
        setSelfLockAuthSuccess(true);
        setTimeout(() => {
          setIsAppLocked(false);
          setSelfLockAuthSuccess(false);
        }, 500);
      }
    } catch (e) {
      console.error("Self-lock biometric failed:", e);
      setSelfLockPinError(true);
    }
  }

  async function handleSelfLockPinSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!selfLockPinInput) return;

    try {
      const valid = await invoke<boolean>("verify_pin", { pin: selfLockPinInput });
      if (valid) {
        setSelfLockAuthSuccess(true);
        setTimeout(() => {
          setIsAppLocked(false);
          setSelfLockAuthSuccess(false);
          setSelfLockPinInput("");
        }, 500);
      } else {
        setSelfLockPinError(true);
        setSelfLockPinInput("");
      }
    } catch (e) {
      setSelfLockPinError(true);
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

  async function handleCancelLockedTrigger() {
    if (lockedTrigger) {
      await invoke("close_locked_application", { bundleId: lockedTrigger.bundle_id });
      setLockedTrigger(null);
      setPinInput("");
      setPinError(false);
    }
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

  async function handleFinishWizard() {
    setWizardError("");
    if (wizardPin.length < 4) {
      setWizardError("PIN must be at least 4 digits");
      return;
    }
    if (wizardPin !== wizardConfirmPin) {
      setWizardError("PINs do not match");
      return;
    }

    try {
      await invoke("set_master_pin", { pin: wizardPin });
      setHasPin(true);
      await invoke("unlock_appguard");

      // Lock all selected apps from step 3
      for (const bundleId of wizardSelectedBundles) {
        const matching = apps.find((a) => a.bundle_id === bundleId);
        if (matching) {
          await invoke("toggle_lock_app", {
            app: {
              bundle_id: matching.bundle_id,
              name: matching.name,
              path: matching.path,
              is_locked: true,
            },
          });
        }
      }

      const updatedConfig = await invoke<AppGuardConfig>("get_config");
      setConfig(updatedConfig);
      setShowWelcomeSetup(false);
      setIsAppLocked(false);
    } catch (err: any) {
      setWizardError(String(err));
    }
  }

  async function handleUpdatePreference<K extends keyof AppGuardConfig>(
    key: K,
    value: AppGuardConfig[K]
  ) {
    if (!config) return;
    const nextConfig = { ...config, [key]: value };
    setConfig(nextConfig);

    try {
      await invoke("update_preferences", {
        gracePeriodSeconds: nextConfig.grace_period_seconds,
        appSelfLocked: nextConfig.app_self_locked,
        lockOnSleep: nextConfig.lock_on_sleep,
        lockOnScreensaver: nextConfig.lock_on_screensaver,
        instantLockMode: nextConfig.instant_lock_mode,
        stealthMode: nextConfig.stealth_mode,
        tamperProtectionEnabled: !!nextConfig.tamper_protection_enabled,
      });
      setSettingsSaveFeedback(true);
      setTimeout(() => setSettingsSaveFeedback(false), 1500);
    } catch (err) {
      console.error("Failed to update preferences:", err);
    }
  }

  async function handleToggleTamperProtection() {
    if (!config) return;
    const targetState = !config.tamper_protection_enabled;
    try {
      await invoke("set_tamper_protection", { enabled: targetState });
      setConfig({ ...config, tamper_protection_enabled: targetState });
      setSettingsSaveFeedback(true);
      setTimeout(() => setSettingsSaveFeedback(false), 1500);
    } catch (err) {
      console.error("Failed to toggle tamper protection:", err);
      alert(`Tamper protection error: ${err}`);
    }
  }

  async function handleChangeMasterPin(e: React.FormEvent) {
    e.preventDefault();
    setChangePinError("");
    if (newChangePinInput.length < 4) {
      setChangePinError("New PIN must be at least 4 digits");
      return;
    }
    if (newChangePinInput !== confirmChangePinInput) {
      setChangePinError("New PINs do not match");
      return;
    }

    try {
      await invoke("change_master_pin", {
        oldPin: oldPinInput,
        newPin: newChangePinInput,
      });
      setChangePinSuccess(true);
      setTimeout(() => {
        setChangePinModalOpen(false);
        setChangePinSuccess(false);
        setOldPinInput("");
        setNewChangePinInput("");
        setConfirmChangePinInput("");
      }, 1200);
    } catch (err: any) {
      setChangePinError(String(err));
    }
  }

  const filteredApps = apps.filter((a) => {
    const matchesSearch =
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.bundle_id.toLowerCase().includes(search.toLowerCase());
    if (!matchesSearch) return false;
    const isLocked = !!config?.locked_apps[a.bundle_id]?.is_locked;
    if (appFilter === "locked") return isLocked;
    if (appFilter === "unlocked") return !isLocked;
    return true;
  });

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
              className="w-10 h-10 rounded-2xl flex items-center justify-center shadow-lg text-white transition-all duration-300 hover:scale-105 relative overflow-hidden"
              style={{
                background: `linear-gradient(135deg, ${theme.colors.accent}, #06b6d4)`,
                boxShadow: `0 8px 20px ${theme.colors.accentGlow}`,
              }}
            >
              <Shield className="w-5 h-5 relative z-10" />
              <div className="absolute inset-0 bg-white/10 opacity-0 hover:opacity-100 transition-opacity" />
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-tight flex items-center gap-1.5" style={{ color: theme.colors.textPrimary }}>
                <span>AppGuard</span>
                <span
                  className="text-[9px] uppercase font-bold tracking-widest px-1.5 py-0.5 rounded-full border"
                  style={{
                    backgroundColor: theme.colors.badgeBg,
                    borderColor: theme.colors.border,
                    color: theme.colors.badgeText,
                  }}
                >
                  PRO
                </span>
              </h1>
              <p className="text-[11px] font-medium" style={{ color: theme.colors.textSecondary }}>
                Local Privacy & Biometric Shield
              </p>
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
              onClick={() => setActiveTab("settings")}
              className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all cursor-pointer"
              style={{
                backgroundColor: activeTab === "settings" ? (isLight ? "#e2e8f0" : "rgba(255,255,255,0.06)") : "transparent",
                color: activeTab === "settings" ? theme.colors.accent : theme.colors.textSecondary,
                fontWeight: activeTab === "settings" ? 600 : 500,
              }}
            >
              <div className="flex items-center gap-2.5">
                <Settings className="w-4 h-4" />
                <span>Security & Settings</span>
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
            onClick={async () => {
              await invoke("lock_all_sessions");
              setIsAppLocked(true);
            }}
            className={`w-full mt-2 py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer border ${
              lockAllSuccess
                ? "border-emerald-500/30 bg-emerald-500/20 text-emerald-600 dark:text-emerald-400"
                : "border-red-500/20 bg-red-500/10 hover:bg-red-500/20 text-red-600 dark:text-red-400"
            }`}
          >
            {lockAllSuccess ? (
              <>
                <Check className="w-3.5 h-3.5 animate-scale" />
                <span>All Locked & Hidden!</span>
              </>
            ) : (
              <>
                <Lock className="w-3.5 h-3.5" />
                <span>Lock All Now</span>
              </>
            )}
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
            <div className="space-y-5">
              {/* Security Health / Metrics Overview Banner */}
              <div
                className="p-4 rounded-2xl border flex flex-col sm:flex-row items-center justify-between gap-4 glass-surface transition-all"
                style={{
                  backgroundColor: isLight ? "rgba(255,255,255,0.7)" : "rgba(255,255,255,0.03)",
                  borderColor: theme.colors.border,
                }}
              >
                <div className="flex items-center gap-3.5 w-full sm:w-auto">
                  <div
                    className="w-11 h-11 rounded-xl flex items-center justify-center text-white shadow-md flex-shrink-0"
                    style={{
                      backgroundColor: theme.colors.accent,
                      boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                    }}
                  >
                    <Shield className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold flex items-center gap-2" style={{ color: theme.colors.textPrimary }}>
                      System Privacy Status
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wider bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                        Active Shield
                      </span>
                    </h3>
                    <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                      {lockedCount === 0
                        ? "No apps shielded yet. Select apps below to guard against unauthorized access."
                        : `${lockedCount} app${lockedCount > 1 ? "s" : ""} protected with hardware biometrics and instant window shield.`}
                    </p>
                  </div>
                </div>

                {/* Filter Pills */}
                <div
                  className="flex items-center p-1 rounded-xl border w-full sm:w-auto justify-between sm:justify-start"
                  style={{
                    backgroundColor: isLight ? "#f1f5f9" : "rgba(255,255,255,0.04)",
                    borderColor: theme.colors.border,
                  }}
                >
                  <button
                    onClick={() => setAppFilter("all")}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                      appFilter === "all"
                        ? "shadow-xs text-white"
                        : "opacity-70 hover:opacity-100"
                    }`}
                    style={{
                      backgroundColor: appFilter === "all" ? theme.colors.accent : "transparent",
                      color: appFilter === "all" ? "#fff" : theme.colors.textSecondary,
                    }}
                  >
                    All ({apps.length})
                  </button>
                  <button
                    onClick={() => setAppFilter("locked")}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                      appFilter === "locked"
                        ? "shadow-xs text-white"
                        : "opacity-70 hover:opacity-100"
                    }`}
                    style={{
                      backgroundColor: appFilter === "locked" ? theme.colors.accent : "transparent",
                      color: appFilter === "locked" ? "#fff" : theme.colors.textSecondary,
                    }}
                  >
                    Shielded ({lockedCount})
                  </button>
                  <button
                    onClick={() => setAppFilter("unlocked")}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                      appFilter === "unlocked"
                        ? "shadow-xs text-white"
                        : "opacity-70 hover:opacity-100"
                    }`}
                    style={{
                      backgroundColor: appFilter === "unlocked" ? theme.colors.accent : "transparent",
                      color: appFilter === "unlocked" ? "#fff" : theme.colors.textSecondary,
                    }}
                  >
                    Unprotected ({Math.max(0, apps.length - lockedCount)})
                  </button>
                </div>
              </div>

              {filteredApps.length === 0 ? (
                <div
                  className="p-12 rounded-2xl border-2 border-dashed flex flex-col items-center justify-center text-center space-y-3"
                  style={{ borderColor: theme.colors.border }}
                >
                  <div
                    className="w-12 h-12 rounded-2xl flex items-center justify-center shadow-md"
                    style={{ backgroundColor: theme.colors.badgeBg, color: theme.colors.accent }}
                  >
                    <Search className="w-6 h-6" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold" style={{ color: theme.colors.textPrimary }}>
                      No applications found
                    </h4>
                    <p className="text-xs max-w-sm mt-1" style={{ color: theme.colors.textMuted }}>
                      {search ? `No results matching "${search}"` : "Try changing the filter or rescan your applications."}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
                  {filteredApps.map((app) => {
                    const isLocked = !!config?.locked_apps[app.bundle_id]?.is_locked;
                    return (
                      <div
                        key={app.bundle_id}
                        className="p-4 rounded-xl border transition-all flex items-center justify-between shadow-xs app-card-interactive"
                        style={{
                          backgroundColor: isLocked ? theme.colors.bgCardLocked : theme.colors.bgCard,
                          borderColor: isLocked ? theme.colors.borderLocked : theme.colors.borderCard,
                        }}
                      >
                        <div className="flex items-center gap-3 min-w-0 pr-3">
                          {app.icon_base64 ? (
                            <div className="w-10 h-10 rounded-xl overflow-hidden flex-shrink-0 bg-transparent flex items-center justify-center shadow-xs">
                              <img
                                src={app.icon_base64}
                                alt={app.name}
                                className="w-full h-full object-contain pointer-events-none select-none"
                                loading="lazy"
                              />
                            </div>
                          ) : (
                            <div
                              className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 transition-colors"
                              style={{
                                backgroundColor: isLocked ? theme.colors.badgeBg : (isLight ? "#f1f5f9" : "#1e293b"),
                                color: isLocked ? theme.colors.accent : theme.colors.textMuted,
                              }}
                            >
                              {isLocked ? <Lock className="w-5 h-5" /> : <Unlock className="w-5 h-5" />}
                            </div>
                          )}
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <h4 className="text-sm font-semibold truncate" style={{ color: theme.colors.textPrimary }}>
                                {app.name}
                              </h4>
                              {isLocked && (
                                <span
                                  className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
                                  style={{
                                    backgroundColor: theme.colors.badgeBg,
                                    color: theme.colors.badgeText,
                                  }}
                                >
                                  Locked
                                </span>
                              )}
                            </div>
                            <p className="text-xs truncate font-mono" style={{ color: theme.colors.textMuted }} title={app.bundle_id}>
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
            </div>
          )}

          {/* TAB 2: VAULT */}
          {activeTab === "vault" && (
            <div className="space-y-6 max-w-4xl">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold flex items-center gap-2" style={{ color: theme.colors.textPrimary }}>
                    Encrypted Folder Vaults
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full font-semibold uppercase bg-indigo-500/10 text-indigo-500 border border-indigo-500/20">
                      AES-256-GCM
                    </span>
                  </h3>
                  <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                    Folders secured with local AES-256-GCM authenticated encryption. Shielded from Finder exploration when locked.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={loadVaults}
                    disabled={loadingVaults}
                    title="Refresh vaults"
                    className="p-2 rounded-xl border hover:opacity-80 transition-opacity cursor-pointer"
                    style={{ borderColor: theme.colors.border, color: theme.colors.textMuted }}
                  >
                    <RefreshCw className={`w-4 h-4 ${loadingVaults ? "animate-spin" : ""}`} />
                  </button>
                  <button
                    onClick={handleSelectFolder}
                    className="px-4 py-2 rounded-xl font-semibold text-xs flex items-center gap-2 shadow-md cursor-pointer hover:opacity-90 transition-all text-white"
                    style={{
                      backgroundColor: theme.colors.accent,
                      boxShadow: `0 4px 12px ${theme.colors.accentGlow}`,
                    }}
                  >
                    <FolderPlus className="w-4 h-4" />
                    <span>Protect New Folder</span>
                  </button>
                </div>
              </div>

              {vaults.length === 0 ? (
                <div
                  className="p-12 rounded-2xl border-2 border-dashed flex flex-col items-center justify-center text-center space-y-3"
                  style={{ borderColor: theme.colors.border }}
                >
                  <div
                    className="w-14 h-14 rounded-2xl flex items-center justify-center shadow-md"
                    style={{ backgroundColor: theme.colors.badgeBg, color: theme.colors.accent }}
                  >
                    <FolderLock className="w-7 h-7" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold" style={{ color: theme.colors.textPrimary }}>
                      No Protected Folders Yet
                    </h4>
                    <p className="text-xs max-w-sm mt-1" style={{ color: theme.colors.textMuted }}>
                      Click "Protect New Folder" to select any directory on your Mac (such as Documents, Financials, or Taxes) and encrypt it.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {vaults.map((vault) => {
                    const isProcessing = vaultActionLoading === vault.path;
                    const formatSize = (bytes: number) => {
                      if (bytes === 0) return "0 B";
                      const k = 1024;
                      const sizes = ["B", "KB", "MB", "GB"];
                      const i = Math.floor(Math.log(bytes) / Math.log(k));
                      return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
                    };

                    return (
                      <div
                        key={vault.path}
                        className="p-5 rounded-2xl border transition-all flex flex-col justify-between space-y-4 shadow-xs app-card-interactive"
                        style={{
                          backgroundColor: vault.is_locked ? theme.colors.bgCardLocked : theme.colors.bgCard,
                          borderColor: vault.is_locked ? theme.colors.borderLocked : theme.colors.borderCard,
                        }}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-center gap-3 min-w-0">
                            <div
                              className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0 transition-colors"
                              style={{
                                backgroundColor: vault.is_locked ? theme.colors.badgeBg : (isLight ? "#f1f5f9" : "#1e293b"),
                                color: vault.is_locked ? theme.colors.accent : theme.colors.textMuted,
                              }}
                            >
                              {vault.is_locked ? <FolderLock className="w-6 h-6" /> : <HardDrive className="w-6 h-6" />}
                            </div>
                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                <h4 className="font-semibold text-sm truncate" style={{ color: theme.colors.textPrimary }}>
                                  {vault.name}
                                </h4>
                                <span
                                  className={`text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wider ${
                                    vault.is_locked
                                      ? "bg-red-500/10 text-red-500 border border-red-500/20"
                                      : "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20"
                                  }`}
                                >
                                  {vault.is_locked ? "Encrypted & Hidden" : "Open"}
                                </span>
                              </div>
                              <p className="text-[11px] truncate font-mono mt-0.5" style={{ color: theme.colors.textMuted }} title={vault.path}>
                                {vault.path}
                              </p>
                            </div>
                          </div>

                          <button
                            onClick={() => handleRemoveVault(vault.path)}
                            title="Remove from vault list"
                            className="p-1.5 rounded-lg opacity-60 hover:opacity-100 hover:text-red-500 transition-colors cursor-pointer"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>

                        <div className="flex items-center justify-between text-xs pt-3 border-t" style={{ borderColor: theme.colors.border }}>
                          <div className="flex items-center gap-3 font-medium" style={{ color: theme.colors.textSecondary }}>
                            <span>{vault.file_count} files</span>
                            <span className="opacity-40">•</span>
                            <span>{formatSize(vault.total_size_bytes)}</span>
                          </div>

                          <button
                            onClick={() => handleToggleVaultLock(vault)}
                            disabled={isProcessing}
                            className="px-3.5 py-1.5 rounded-xl font-semibold text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-xs disabled:opacity-50"
                            style={{
                              backgroundColor: vault.is_locked ? theme.colors.accent : (isLight ? "#e2e8f0" : "#334155"),
                              color: vault.is_locked ? theme.colors.accentText : theme.colors.textPrimary,
                            }}
                          >
                            {isProcessing ? (
                              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            ) : vault.is_locked ? (
                              <>
                                <Unlock className="w-3.5 h-3.5" />
                                <span>Decrypt Vault</span>
                              </>
                            ) : (
                              <>
                                <Lock className="w-3.5 h-3.5" />
                                <span>Encrypt Now</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
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
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {(["nordic", "editorial", "rose", "emerald", "amber"] as ThemeMode[]).map((mode) => {
                    const item = THEMES[mode];
                    const selected = currentTheme === mode;
                    const subtitles: Record<string, string> = {
                      nordic: "Crisp white with electric sapphire",
                      editorial: "Warm parchment with organic teal",
                      rose: "Blush quartz with vivid rose",
                      emerald: "Clean jade with mint highlights",
                      amber: "Warm sunlight with golden amber",
                    };
                    return (
                      <div
                        key={mode}
                        onClick={() => setCurrentTheme(mode)}
                        className="p-4 rounded-2xl border-2 cursor-pointer transition-all hover:scale-[1.01] flex flex-col justify-between"
                        style={{
                          backgroundColor: item.colors.bgCard,
                          borderColor: selected ? item.colors.accent : item.colors.border,
                          boxShadow: selected ? `0 8px 24px ${item.colors.accentGlow}` : "none",
                        }}
                      >
                        <div className="flex items-center justify-between mb-3">
                          <div>
                            <h4 className="font-bold text-sm" style={{ color: item.colors.textPrimary }}>
                              {item.name}
                            </h4>
                            <p className="text-xs" style={{ color: item.colors.textSecondary }}>
                              {subtitles[mode]}
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
                            {item.previewBg}
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

              {/* Startup & Background Guardian Settings */}
              <div
                className="p-5 rounded-2xl border space-y-4"
                style={{
                  backgroundColor: theme.colors.bgCard,
                  borderColor: theme.colors.borderCard,
                }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center"
                      style={{ backgroundColor: theme.colors.badgeBg, color: theme.colors.accent }}
                    >
                      <Power className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="font-bold text-sm" style={{ color: theme.colors.textPrimary }}>
                        Launch at System Startup
                      </h4>
                      <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                        Automatically protect applications and stay active in your macOS Menu Bar when your Mac boots up.
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={handleToggleAutostart}
                    className="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                    style={{
                      backgroundColor: autostartEnabled ? theme.colors.toggleActive : theme.colors.toggleInactive,
                    }}
                  >
                    <span
                      className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                        autostartEnabled ? "translate-x-5" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Settings & Security Preferences Tab */}
          {activeTab === "settings" && (
            <div className="p-8 max-w-4xl mx-auto space-y-8 animate-in fade-in duration-200">
              {/* Header */}
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-bold tracking-tight" style={{ color: theme.colors.textPrimary }}>
                    Security & Preferences
                  </h3>
                  <p className="text-xs mt-1" style={{ color: theme.colors.textSecondary }}>
                    Configure hardware defense policies, auto-lock grace intervals, and master credentials.
                  </p>
                </div>
                {settingsSaveFeedback && (
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 flex items-center gap-1.5 animate-in fade-in">
                    <Check className="w-3.5 h-3.5" />
                    <span>Settings Saved</span>
                  </span>
                )}
              </div>

              {/* Section 1: Self-Defense & Dashboard Gate */}
              <div
                className="p-6 rounded-2xl border space-y-5"
                style={{
                  backgroundColor: theme.colors.bgCard,
                  borderColor: theme.colors.borderCard,
                }}
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center text-white"
                    style={{ backgroundColor: theme.colors.accent }}
                  >
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="font-bold text-sm" style={{ color: theme.colors.textPrimary }}>
                      AppGuard Self-Defense
                    </h4>
                    <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                      Prevent unauthorized modification of your protection rules and vault paths.
                    </p>
                  </div>
                </div>

                <div className="space-y-4 pt-2">
                  <div className="flex items-center justify-between py-2 border-t" style={{ borderColor: theme.colors.borderCard }}>
                    <div>
                      <span className="text-xs font-semibold" style={{ color: theme.colors.textPrimary }}>
                        Require Authentication to Open AppGuard
                      </span>
                      <p className="text-[11px]" style={{ color: theme.colors.textSecondary }}>
                        Prompts for Touch ID, macOS Password, or Master PIN when opening the app.
                      </p>
                    </div>
                    <button
                      onClick={() => handleUpdatePreference("app_self_locked", !config?.app_self_locked)}
                      className="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                      style={{
                        backgroundColor: config?.app_self_locked ? theme.colors.toggleActive : theme.colors.toggleInactive,
                      }}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                          config?.app_self_locked ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>

                  <div className="flex items-center justify-between py-2 border-t" style={{ borderColor: theme.colors.borderCard }}>
                    <div>
                      <span className="text-xs font-semibold" style={{ color: theme.colors.textPrimary }}>
                        Instant Process Re-lock (Zero Tolerance)
                      </span>
                      <p className="text-[11px]" style={{ color: theme.colors.textSecondary }}>
                        Re-locks protected apps the exact millisecond you switch windows (overrides grace period).
                      </p>
                    </div>
                    <button
                      onClick={() => handleUpdatePreference("instant_lock_mode", !config?.instant_lock_mode)}
                      className="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                      style={{
                        backgroundColor: config?.instant_lock_mode ? theme.colors.toggleActive : theme.colors.toggleInactive,
                      }}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                          config?.instant_lock_mode ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>

                  <div className="flex items-center justify-between py-2 border-t" style={{ borderColor: theme.colors.borderCard }}>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold" style={{ color: theme.colors.textPrimary }}>
                          Tamper-Proof OS Watchdog (Auto-Resurrect)
                        </span>
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-amber-500/10 text-amber-500 border border-amber-500/20">
                          Cross-Platform
                        </span>
                      </div>
                      <p className="text-[11px]" style={{ color: theme.colors.textSecondary }}>
                        Registers OS supervisor (launchd / Windows Task Scheduler / systemd) to immediately resurrect AppGuard if an intruder forces kill via killall, Task Manager, or SIGKILL.
                      </p>
                    </div>
                    <button
                      onClick={handleToggleTamperProtection}
                      className="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                      style={{
                        backgroundColor: config?.tamper_protection_enabled ? theme.colors.toggleActive : theme.colors.toggleInactive,
                      }}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                          config?.tamper_protection_enabled ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>
                </div>
              </div>

              {/* Section 2: Grace Period & Re-lock Timers */}
              <div
                className="p-6 rounded-2xl border space-y-5"
                style={{
                  backgroundColor: theme.colors.bgCard,
                  borderColor: theme.colors.borderCard,
                }}
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center text-white"
                    style={{ backgroundColor: theme.colors.accent }}
                  >
                    <Clock className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="font-bold text-sm" style={{ color: theme.colors.textPrimary }}>
                      Session Grace Period
                    </h4>
                    <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                      How long an app stays unlocked before asking for authentication again.
                    </p>
                  </div>
                </div>

                <div className="space-y-3 pt-2">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
                    {[
                      { label: "Immediate (0s)", val: 0 },
                      { label: "30 Seconds", val: 30 },
                      { label: "1 Minute", val: 60 },
                      { label: "5 Minutes", val: 300 },
                    ].map((item) => {
                      const isSelected = config?.grace_period_seconds === item.val;
                      return (
                        <button
                          key={item.val}
                          onClick={() => handleUpdatePreference("grace_period_seconds", item.val)}
                          className={`p-3 rounded-xl border text-xs font-semibold cursor-pointer transition-all text-center ${
                            isSelected
                              ? "shadow-sm border-2"
                              : "opacity-75 hover:opacity-100"
                          }`}
                          style={{
                            borderColor: isSelected ? theme.colors.accent : theme.colors.border,
                            backgroundColor: isSelected
                              ? isLight
                                ? "#f1f5f9"
                                : "rgba(255,255,255,0.06)"
                              : "transparent",
                            color: isSelected ? theme.colors.accent : theme.colors.textPrimary,
                          }}
                        >
                          {item.label}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="space-y-4 pt-4 border-t" style={{ borderColor: theme.colors.borderCard }}>
                  <div className="flex items-center justify-between py-1">
                    <div>
                      <span className="text-xs font-semibold" style={{ color: theme.colors.textPrimary }}>
                        Lock All Apps when Mac Goes to Sleep
                      </span>
                      <p className="text-[11px]" style={{ color: theme.colors.textSecondary }}>
                        Instantly clears all active unlock sessions upon system sleep.
                      </p>
                    </div>
                    <button
                      onClick={() => handleUpdatePreference("lock_on_sleep", !config?.lock_on_sleep)}
                      className="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                      style={{
                        backgroundColor: config?.lock_on_sleep ? theme.colors.toggleActive : theme.colors.toggleInactive,
                      }}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                          config?.lock_on_sleep ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>

                  <div className="flex items-center justify-between py-1 border-t" style={{ borderColor: theme.colors.borderCard }}>
                    <div>
                      <span className="text-xs font-semibold" style={{ color: theme.colors.textPrimary }}>
                        Lock All Apps on Screensaver / Display Lock
                      </span>
                      <p className="text-[11px]" style={{ color: theme.colors.textSecondary }}>
                        Requires re-authentication whenever your screen turns off.
                      </p>
                    </div>
                    <button
                      onClick={() => handleUpdatePreference("lock_on_screensaver", !config?.lock_on_screensaver)}
                      className="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                      style={{
                        backgroundColor: config?.lock_on_screensaver ? theme.colors.toggleActive : theme.colors.toggleInactive,
                      }}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                          config?.lock_on_screensaver ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>
                </div>
              </div>

              {/* Section 3: Master Recovery PIN Management */}
              <div
                className="p-6 rounded-2xl border space-y-4"
                style={{
                  backgroundColor: theme.colors.bgCard,
                  borderColor: theme.colors.borderCard,
                }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center text-white"
                      style={{ backgroundColor: theme.colors.accent }}
                    >
                      <KeyRound className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="font-bold text-sm" style={{ color: theme.colors.textPrimary }}>
                        Master Recovery PIN
                      </h4>
                      <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                        Your primary fallback secret for unlocking applications and encrypting vaults.
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={() => setChangePinModalOpen(true)}
                    className="py-2.5 px-4 rounded-xl text-xs font-semibold cursor-pointer border transition-all hover:opacity-90 shadow-xs"
                    style={{
                      borderColor: theme.colors.border,
                      backgroundColor: isLight ? "#f8fafc" : "rgba(255,255,255,0.04)",
                      color: theme.colors.accent,
                    }}
                  >
                    Change PIN
                  </button>
                </div>
              </div>

              {/* Section 4: Software Updates */}
              <div
                className="p-6 rounded-2xl border space-y-4"
                style={{
                  backgroundColor: theme.colors.bgCard,
                  borderColor: theme.colors.borderCard,
                }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center text-white"
                      style={{ backgroundColor: theme.colors.accent }}
                    >
                      <Sparkles className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="font-bold text-sm" style={{ color: theme.colors.textPrimary }}>
                          App Updates
                        </h4>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-500 border border-blue-500/20 font-semibold">
                          v{currentVersion}
                        </span>
                      </div>
                      <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                        {updaterState.status === "checking"
                          ? "Checking GitHub for new releases..."
                          : updaterState.status === "up-to-date"
                          ? "AppGuard is up to date."
                          : updaterState.status === "error"
                          ? updaterState.message
                          : "Automatically checks for releases on startup."}
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={() => checkForUpdates(true)}
                    disabled={updaterState.status === "checking"}
                    className="py-2.5 px-4 rounded-xl text-xs font-semibold cursor-pointer border transition-all hover:opacity-90 flex items-center gap-2 disabled:opacity-50"
                    style={{
                      borderColor: theme.colors.border,
                      backgroundColor: isLight ? "#f8fafc" : "rgba(255,255,255,0.04)",
                      color: theme.colors.accent,
                    }}
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${updaterState.status === "checking" ? "animate-spin" : ""}`} />
                    <span>{updaterState.status === "checking" ? "Checking..." : "Check for Updates"}</span>
                  </button>
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
                {biometrics.biometric_type === "SystemPassword" ? (
                  <KeyRound className="w-5 h-5" />
                ) : (
                  <Fingerprint className="w-5 h-5" />
                )}
                <span>
                  {biometrics.biometric_type === "SystemPassword"
                    ? "Verify with macOS Password"
                    : `Verify with ${biometrics.biometric_type}`}
                </span>
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
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleCancelLockedTrigger}
                  className="flex-1 py-2.5 rounded-xl text-xs font-semibold transition-all cursor-pointer border text-red-600 dark:text-red-400 border-red-500/20 bg-red-500/10 hover:bg-red-500/20"
                >
                  Cancel & Close App
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2.5 rounded-xl text-xs font-semibold transition-all cursor-pointer border"
                  style={{
                    backgroundColor: isLight ? "#f1f5f9" : "#1e293b",
                    borderColor: theme.colors.border,
                    color: theme.colors.textPrimary,
                  }}
                >
                  Unlock with PIN
                </button>
              </div>
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

      {/* In-app Vault PIN Modal (For Encrypting / Decrypting Folders) */}
      {vaultPinModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-md flex items-center justify-center p-4">
          <div
            className="w-full max-w-sm rounded-2xl border p-6 shadow-2xl space-y-4"
            style={{
              backgroundColor: theme.colors.bgModal,
              borderColor: theme.colors.border,
            }}
          >
            <div className="flex items-center gap-2.5" style={{ color: theme.colors.textPrimary }}>
              <Lock className="w-5 h-5" style={{ color: theme.colors.accent }} />
              <h3 className="font-bold">
                {vaultPinModal.action === "encrypt" ? "Encrypt Folder Vault" : "Decrypt Folder Vault"}
              </h3>
            </div>
            <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
              Enter Master Recovery PIN to {vaultPinModal.action} <strong>{vaultPinModal.item.name}</strong> with AES-256-GCM.
            </p>

            <form onSubmit={handleVaultPinSubmit} className="space-y-3">
              <div>
                <input
                  type="password"
                  maxLength={8}
                  placeholder="Enter Master PIN"
                  value={vaultPinModal.pin}
                  onChange={(e) =>
                    setVaultPinModal((prev) => prev ? { ...prev, pin: e.target.value, error: "" } : null)
                  }
                  className="w-full px-3 py-2 rounded-lg border text-sm focus:outline-none"
                  style={{
                    backgroundColor: theme.colors.bgInput,
                    borderColor: vaultPinModal.error ? "#ef4444" : theme.colors.border,
                    color: theme.colors.textPrimary,
                  }}
                  autoFocus
                />
              </div>

              {vaultPinModal.error && (
                <p className="text-xs text-red-500 font-medium">{vaultPinModal.error}</p>
              )}

              <div className="flex gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setVaultPinModal(null)}
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
                  disabled={!vaultPinModal.pin}
                  className="flex-1 py-2 rounded-lg text-xs font-semibold text-white shadow-md cursor-pointer disabled:opacity-50"
                  style={{
                    backgroundColor: theme.colors.accent,
                    boxShadow: `0 4px 12px ${theme.colors.accentGlow}`,
                  }}
                >
                  {vaultPinModal.action === "encrypt" ? "Encrypt Now" : "Decrypt Now"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* First-time Setup / 3-Step Onboarding Wizard */}
      {showWelcomeSetup && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xl flex items-center justify-center p-4">
          <div
            className="w-full max-w-lg rounded-2xl border p-8 shadow-2xl space-y-6 text-center"
            style={{
              backgroundColor: theme.colors.bgModal,
              borderColor: theme.colors.border,
            }}
          >
            {/* Step Indicators */}
            <div className="flex items-center justify-center gap-3">
              {[1, 2, 3].map((stepNum) => (
                <div key={stepNum} className="flex items-center gap-2">
                  <div
                    className={`w-7 h-7 rounded-full text-xs font-bold flex items-center justify-center transition-all ${
                      wizardStep === stepNum
                        ? "text-white shadow-md"
                        : wizardStep > stepNum
                        ? "bg-emerald-500 text-white"
                        : "bg-gray-200 dark:bg-gray-800 text-gray-400"
                    }`}
                    style={{
                      backgroundColor: wizardStep === stepNum ? theme.colors.accent : undefined,
                    }}
                  >
                    {wizardStep > stepNum ? <Check className="w-3.5 h-3.5" /> : stepNum}
                  </div>
                  {stepNum < 3 && (
                    <div
                      className={`w-8 h-0.5 ${
                        wizardStep > stepNum ? "bg-emerald-500" : "bg-gray-200 dark:bg-gray-800"
                      }`}
                    />
                  )}
                </div>
              ))}
            </div>

            {/* Step 1: Security & Hardware Detection */}
            {wizardStep === 1 && (
              <div className="space-y-5 animate-in fade-in duration-300">
                <div
                  className="w-18 h-18 rounded-3xl flex items-center justify-center mx-auto shadow-2xl text-white relative overflow-hidden"
                  style={{
                    background: `linear-gradient(135deg, ${theme.colors.accent}, #06b6d4)`,
                    boxShadow: `0 16px 32px ${theme.colors.accentGlow}`,
                  }}
                >
                  <Shield className="w-9 h-9 relative z-10" />
                </div>
                <div>
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider mb-2 border"
                    style={{
                      backgroundColor: theme.colors.badgeBg,
                      borderColor: theme.colors.border,
                      color: theme.colors.badgeText,
                    }}
                  >
                    <span>AppGuard Privacy Suite</span>
                  </div>
                  <h3 className="text-2xl font-bold tracking-tight" style={{ color: theme.colors.textPrimary }}>
                    Welcome to AppGuard
                  </h3>
                  <p className="text-xs mt-1.5 max-w-sm mx-auto" style={{ color: theme.colors.textSecondary }}>
                    Hardware biometrics & local authenticated AES-256-GCM encryption
                  </p>
                </div>

                <div
                  className="p-4 rounded-xl border text-left space-y-2 text-xs"
                  style={{
                    backgroundColor: theme.colors.bgCard,
                    borderColor: theme.colors.borderCard,
                  }}
                >
                  <div className="font-semibold text-xs flex items-center justify-between">
                    <span>Hardware Sensor Status:</span>
                    <span className="font-mono text-emerald-600 dark:text-emerald-400">
                      {biometrics?.is_available ? biometrics.biometric_type : "PIN Fallback Mode"}
                    </span>
                  </div>
                  <p className="text-[11px]" style={{ color: theme.colors.textSecondary }}>
                    {biometrics?.biometric_type === "TouchID" || biometrics?.biometric_type === "FaceID"
                      ? "Hardware sensor detected. You can instantly unlock protected apps with your fingerprint."
                      : biometrics?.biometric_type === "SystemPassword"
                      ? "No dedicated fingerprint scanner detected. AppGuard will seamlessly use your macOS system login password and Master PIN."
                      : "No biometrics available. AppGuard will secure all applications and vaults using your Master PIN."}
                  </p>
                </div>

                <button
                  onClick={() => setWizardStep(2)}
                  className="w-full py-3 px-4 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 shadow-lg cursor-pointer hover:opacity-90 text-white"
                  style={{
                    backgroundColor: theme.colors.accent,
                    boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                  }}
                >
                  <span>Continue to Step 2</span>
                </button>
              </div>
            )}

            {/* Step 2: Configure Master Recovery PIN */}
            {wizardStep === 2 && (
              <div className="space-y-5 animate-in fade-in duration-300">
                <div
                  className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto shadow-xl text-white"
                  style={{
                    backgroundColor: theme.colors.accent,
                    boxShadow: `0 12px 24px ${theme.colors.accentGlow}`,
                  }}
                >
                  <KeyRound className="w-8 h-8" />
                </div>
                <div>
                  <h3 className="text-xl font-bold" style={{ color: theme.colors.textPrimary }}>
                    Create Master Recovery PIN
                  </h3>
                  <p className="text-xs mt-1.5" style={{ color: theme.colors.textSecondary }}>
                    Used to decrypt vaults and unlock apps whenever biometric verification is unavailable
                  </p>
                </div>

                <div className="space-y-3">
                  <input
                    type="password"
                    maxLength={8}
                    placeholder="Enter 4-8 digit PIN"
                    value={wizardPin}
                    onChange={(e) => {
                      setWizardPin(e.target.value);
                      setWizardError("");
                    }}
                    className="w-full text-center text-xl tracking-[0.4em] py-2.5 rounded-xl border focus:outline-none"
                    style={{
                      backgroundColor: theme.colors.bgInput,
                      borderColor: theme.colors.border,
                      color: theme.colors.textPrimary,
                    }}
                    autoFocus
                  />
                  <input
                    type="password"
                    maxLength={8}
                    placeholder="Confirm Master PIN"
                    value={wizardConfirmPin}
                    onChange={(e) => {
                      setWizardConfirmPin(e.target.value);
                      setWizardError("");
                    }}
                    className="w-full text-center text-xl tracking-[0.4em] py-2.5 rounded-xl border focus:outline-none"
                    style={{
                      backgroundColor: theme.colors.bgInput,
                      borderColor: theme.colors.border,
                      color: theme.colors.textPrimary,
                    }}
                  />
                  {wizardError && (
                    <p className="text-xs text-red-500 font-medium">{wizardError}</p>
                  )}
                </div>

                <div className="flex gap-2">
                  <button
                    onClick={() => setWizardStep(1)}
                    className="flex-1 py-3 px-4 rounded-xl font-semibold text-xs cursor-pointer border"
                    style={{
                      borderColor: theme.colors.border,
                      color: theme.colors.textSecondary,
                    }}
                  >
                    Back
                  </button>
                  <button
                    onClick={() => {
                      if (wizardPin.length < 4) {
                        setWizardError("PIN must be at least 4 digits");
                        return;
                      }
                      if (wizardPin !== wizardConfirmPin) {
                        setWizardError("PINs do not match");
                        return;
                      }
                      setWizardStep(3);
                    }}
                    className="flex-1 py-3 px-4 rounded-xl font-semibold text-xs shadow-md cursor-pointer text-white"
                    style={{
                      backgroundColor: theme.colors.accent,
                      boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                    }}
                  >
                    Next: Shield Apps
                  </button>
                </div>
              </div>
            )}

            {/* Step 3: Select Initial Protected Apps */}
            {wizardStep === 3 && (
              <div className="space-y-5 animate-in fade-in duration-300 text-left">
                <div className="text-center space-y-1">
                  <h3 className="text-xl font-bold" style={{ color: theme.colors.textPrimary }}>
                    Select Apps to Shield
                  </h3>
                  <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                    Choose commonly protected applications to lock immediately
                  </p>
                </div>

                <div
                  className="max-h-48 overflow-y-auto space-y-1.5 p-2 rounded-xl border"
                  style={{
                    backgroundColor: theme.colors.bgCard,
                    borderColor: theme.colors.borderCard,
                  }}
                >
                  {apps
                    .filter((a) =>
                      [
                        "com.apple.Notes",
                        "com.apple.MobileSMS",
                        "com.apple.Photos",
                        "com.apple.Terminal",
                        "com.apple.Safari",
                        "com.apple.mail",
                        "com.google.Chrome",
                      ].includes(a.bundle_id)
                    )
                    .map((app) => {
                      const isSelected = wizardSelectedBundles.has(app.bundle_id);
                      return (
                        <div
                          key={app.bundle_id}
                          onClick={() => {
                            const next = new Set(wizardSelectedBundles);
                            if (isSelected) {
                              next.delete(app.bundle_id);
                            } else {
                              next.add(app.bundle_id);
                            }
                            setWizardSelectedBundles(next);
                          }}
                          className="flex items-center justify-between p-2.5 rounded-lg cursor-pointer transition-all border"
                          style={{
                            backgroundColor: isSelected
                              ? isLight
                                ? "#f1f5f9"
                                : "rgba(255,255,255,0.06)"
                              : "transparent",
                            borderColor: isSelected ? theme.colors.accent : "transparent",
                          }}
                        >
                          <div className="flex items-center gap-3">
                            <div className="w-6 h-6 rounded-md bg-gray-100 dark:bg-gray-800 flex items-center justify-center">
                              {app.icon_base64 ? (
                                <img
                                  src={app.icon_base64}
                                  alt={app.name}
                                  className="w-5 h-5 rounded object-contain pointer-events-none select-none"
                                />
                              ) : (
                                <Shield className="w-3.5 h-3.5 text-gray-500" />
                              )}
                            </div>
                            <span className="text-xs font-semibold" style={{ color: theme.colors.textPrimary }}>
                              {app.name}
                            </span>
                          </div>
                          <input
                            type="checkbox"
                            checked={isSelected}
                            readOnly
                            className="rounded accent-emerald-500 cursor-pointer"
                          />
                        </div>
                      );
                    })}
                </div>

                {wizardError && (
                  <p className="text-xs text-red-500 font-medium text-center">{wizardError}</p>
                )}

                <div className="flex gap-2">
                  <button
                    onClick={() => setWizardStep(2)}
                    className="flex-1 py-3 px-4 rounded-xl font-semibold text-xs cursor-pointer border"
                    style={{
                      borderColor: theme.colors.border,
                      color: theme.colors.textSecondary,
                    }}
                  >
                    Back
                  </button>
                  <button
                    onClick={handleFinishWizard}
                    className="flex-1 py-3 px-4 rounded-xl font-semibold text-xs shadow-md cursor-pointer text-white"
                    style={{
                      backgroundColor: theme.colors.accent,
                      boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                    }}
                  >
                    Finish Setup & Activate Shield
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* AppGuard Self-Lock Gate (Prevents unauthorized access to AppGuard itself) */}
      {isAppLocked && !showWelcomeSetup && (
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
              {selfLockAuthSuccess ? (
                <CheckCircle2 className="w-8 h-8 text-white animate-bounce" />
              ) : (
                <Shield className="w-8 h-8 text-white" />
              )}
            </div>

            <div>
              <h3 className="text-xl font-bold" style={{ color: theme.colors.textPrimary }}>
                AppGuard is Locked
              </h3>
              <p className="text-xs mt-1" style={{ color: theme.colors.textSecondary }}>
                Authentication required to view or configure application protection
              </p>
            </div>

            {biometrics?.is_available && (
              <button
                onClick={handleSelfLockBiometric}
                className="w-full py-3 px-4 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-md cursor-pointer hover:opacity-95"
                style={{
                  backgroundColor: theme.colors.accent,
                  color: theme.colors.accentText,
                  boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                }}
              >
                {biometrics.biometric_type === "SystemPassword" ? (
                  <KeyRound className="w-5 h-5" />
                ) : (
                  <Fingerprint className="w-5 h-5" />
                )}
                <span>
                  {biometrics.biometric_type === "SystemPassword"
                    ? "Unlock with macOS Password"
                    : `Unlock with ${biometrics.biometric_type}`}
                </span>
              </button>
            )}

            <div className="w-full flex items-center gap-3">
              <div className="flex-1 h-px" style={{ backgroundColor: theme.colors.border }} />
              <span className="text-[11px] uppercase tracking-wider font-semibold" style={{ color: theme.colors.textMuted }}>
                or enter Master PIN
              </span>
              <div className="flex-1 h-px" style={{ backgroundColor: theme.colors.border }} />
            </div>

            <form onSubmit={handleSelfLockPinSubmit} className="w-full space-y-3">
              <input
                type="password"
                maxLength={8}
                placeholder="••••"
                value={selfLockPinInput}
                onChange={(e) => {
                  setSelfLockPinInput(e.target.value);
                  setSelfLockPinError(false);
                }}
                className="w-full text-center text-2xl tracking-[0.5em] py-2.5 rounded-xl border focus:outline-none"
                style={{
                  backgroundColor: theme.colors.bgInput,
                  borderColor: selfLockPinError ? "#ef4444" : theme.colors.border,
                  color: theme.colors.textPrimary,
                }}
                autoFocus
              />
              {selfLockPinError && (
                <p className="text-xs text-red-500 font-medium">Incorrect master PIN</p>
              )}
              <button
                type="submit"
                className="w-full py-3 rounded-xl text-xs font-semibold transition-all cursor-pointer shadow-md text-white"
                style={{
                  backgroundColor: theme.colors.accent,
                  boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                }}
              >
                Unlock AppGuard
              </button>
            </form>
          </div>
        </div>
      )}
      {/* Change Master PIN Modal */}
      {changePinModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xl flex items-center justify-center p-4">
          <div
            className="w-full max-w-md rounded-2xl border p-8 shadow-2xl space-y-6"
            style={{
              backgroundColor: theme.colors.bgModal,
              borderColor: theme.colors.border,
            }}
          >
            <div className="text-center space-y-2">
              <div
                className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto shadow-lg text-white"
                style={{
                  backgroundColor: theme.colors.accent,
                  boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                }}
              >
                <KeyRound className="w-7 h-7" />
              </div>
              <h3 className="text-lg font-bold" style={{ color: theme.colors.textPrimary }}>
                Change Master Recovery PIN
              </h3>
              <p className="text-xs" style={{ color: theme.colors.textSecondary }}>
                Enter your current PIN followed by your new 4-8 digit PIN
              </p>
            </div>

            <form onSubmit={handleChangeMasterPin} className="space-y-3.5">
              <div>
                <label className="text-[11px] font-semibold block mb-1" style={{ color: theme.colors.textSecondary }}>
                  Current PIN
                </label>
                <input
                  type="password"
                  maxLength={8}
                  placeholder="••••"
                  value={oldPinInput}
                  onChange={(e) => {
                    setOldPinInput(e.target.value);
                    setChangePinError("");
                  }}
                  className="w-full text-center text-xl tracking-[0.4em] py-2.5 rounded-xl border focus:outline-none"
                  style={{
                    backgroundColor: theme.colors.bgInput,
                    borderColor: theme.colors.border,
                    color: theme.colors.textPrimary,
                  }}
                  autoFocus
                />
              </div>

              <div>
                <label className="text-[11px] font-semibold block mb-1" style={{ color: theme.colors.textSecondary }}>
                  New Master PIN
                </label>
                <input
                  type="password"
                  maxLength={8}
                  placeholder="••••"
                  value={newChangePinInput}
                  onChange={(e) => {
                    setNewChangePinInput(e.target.value);
                    setChangePinError("");
                  }}
                  className="w-full text-center text-xl tracking-[0.4em] py-2.5 rounded-xl border focus:outline-none"
                  style={{
                    backgroundColor: theme.colors.bgInput,
                    borderColor: theme.colors.border,
                    color: theme.colors.textPrimary,
                  }}
                />
              </div>

              <div>
                <label className="text-[11px] font-semibold block mb-1" style={{ color: theme.colors.textSecondary }}>
                  Confirm New PIN
                </label>
                <input
                  type="password"
                  maxLength={8}
                  placeholder="••••"
                  value={confirmChangePinInput}
                  onChange={(e) => {
                    setConfirmChangePinInput(e.target.value);
                    setChangePinError("");
                  }}
                  className="w-full text-center text-xl tracking-[0.4em] py-2.5 rounded-xl border focus:outline-none"
                  style={{
                    backgroundColor: theme.colors.bgInput,
                    borderColor: theme.colors.border,
                    color: theme.colors.textPrimary,
                  }}
                />
              </div>

              {changePinError && (
                <p className="text-xs text-red-500 font-medium text-center">{changePinError}</p>
              )}

              {changePinSuccess && (
                <p className="text-xs text-emerald-500 font-semibold text-center flex items-center justify-center gap-1">
                  <Check className="w-3.5 h-3.5" />
                  <span>PIN successfully updated!</span>
                </p>
              )}

              <div className="flex gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setChangePinModalOpen(false);
                    setChangePinError("");
                    setOldPinInput("");
                    setNewChangePinInput("");
                    setConfirmChangePinInput("");
                  }}
                  className="flex-1 py-2.5 rounded-xl text-xs font-semibold cursor-pointer border"
                  style={{
                    borderColor: theme.colors.border,
                    color: theme.colors.textSecondary,
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2.5 rounded-xl text-xs font-semibold shadow-md cursor-pointer text-white"
                  style={{
                    backgroundColor: theme.colors.accent,
                    boxShadow: `0 8px 16px ${theme.colors.accentGlow}`,
                  }}
                >
                  Save New PIN
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Auto-Updater Notification Modal */}
      {updaterState.status === "available" && (
        <UpdateModal
          info={updaterState.info}
          onDismiss={dismissUpdater}
          onDownloadUrl={openDownload}
          theme={theme}
        />
      )}
    </div>
  );
}
