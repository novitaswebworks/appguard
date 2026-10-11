import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ShieldAlert, CheckCircle2, Fingerprint, KeyRound, X, Clock } from "lucide-react";

interface LockedAppPayload {
  bundle_id: string;
  name: string;
}

export function CompactAuthPanel() {
  const [lockedApp, setLockedApp] = useState<LockedAppPayload | null>(null);
  const [pin, setPin] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [bioAvailable, setBioAvailable] = useState(false);
  const [bioType, setBioType] = useState("Touch ID");
  const [temporaryOption, setTemporaryOption] = useState<number | null>(null); // null = session grace period, 300 = 5m

  useEffect(() => {
    // Check available biometrics
    invoke<{ is_available: boolean; biometric_type: string }>("check_biometrics")
      .then((status) => {
        setBioAvailable(status.is_available);
        setBioType(status.biometric_type || "Touch ID");
      })
      .catch(() => {});

    // Listen for locked application event
    const unlistenPromise = listen<LockedAppPayload>("app-locked-triggered", (event) => {
      setLockedApp(event.payload);
      setPin("");
      setError(null);
      setSuccess(false);
      setTemporaryOption(null);

      // Auto-trigger biometric verification first
      setTimeout(() => {
        handleBiometricAuth(event.payload.bundle_id, event.payload.name);
      }, 150);
    });

    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  async function handleBiometricAuth(bundleId: string, appName: string) {
    try {
      const ok = await invoke<boolean>("authenticate_biometrics", {
        reason: `Unlock ${appName}`,
      });
      if (ok) {
        completeUnlock(bundleId);
      }
    } catch {
      // User cancelled Touch ID or fell back to PIN
    }
  }

  async function completeUnlock(bundleId: string) {
    setSuccess(true);
    await invoke("unlock_app_session", {
      bundleId,
      durationSecs: temporaryOption,
    });
    setTimeout(async () => {
      setSuccess(false);
      setLockedApp(null);
      await invoke("hide_auth_window");
    }, 400);
  }

  async function handlePinSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!pin || !lockedApp) return;

    try {
      const valid = await invoke<boolean>("verify_pin", { pin });
      if (valid) {
        completeUnlock(lockedApp.bundle_id);
      } else {
        setError("Incorrect Master PIN");
        setPin("");
      }
    } catch (err: any) {
      setError(String(err) || "Incorrect Master PIN");
      setPin("");
    }
  }

  async function handleCancel() {
    if (lockedApp) {
      await invoke("close_locked_application", { bundleId: lockedApp.bundle_id });
    }
    setLockedApp(null);
    setPin("");
    await invoke("hide_auth_window");
  }

  return (
    <div className="w-full h-full select-none flex items-center justify-center p-2 bg-transparent font-sans">
      <div className="w-[340px] rounded-2xl border border-white/10 bg-slate-900/95 backdrop-blur-2xl shadow-2xl p-4 text-white flex flex-col items-center relative overflow-hidden">
        {/* Close Button */}
        <button
          onClick={handleCancel}
          className="absolute top-2.5 right-2.5 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-white/10 transition-colors cursor-pointer"
        >
          <X className="w-3.5 h-3.5" />
        </button>

        {/* Status Shield Icon */}
        <div className="w-10 h-10 rounded-xl flex items-center justify-center shadow-lg mb-2 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
          {success ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 animate-bounce" />
          ) : (
            <ShieldAlert className="w-5 h-5 text-indigo-400" />
          )}
        </div>

        {/* Target App Title */}
        <h2 className="text-sm font-bold text-center tracking-tight text-white mb-0.5 truncate max-w-[280px]">
          {lockedApp ? lockedApp.name : "Protected Application"}
        </h2>
        <p className="text-[10px] text-slate-400 text-center mb-3">
          Verification required to access
        </p>

        {/* Biometric Button */}
        {bioAvailable && (
          <button
            onClick={() => lockedApp && handleBiometricAuth(lockedApp.bundle_id, lockedApp.name)}
            className="w-full py-2 px-3 mb-2 rounded-xl font-semibold text-xs flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white shadow-md transition-all cursor-pointer"
          >
            {bioType === "SystemPassword" ? (
              <KeyRound className="w-3.5 h-3.5" />
            ) : (
              <Fingerprint className="w-3.5 h-3.5" />
            )}
            <span>
              {bioType === "SystemPassword"
                ? "Verify with System Password"
                : `Unlock with ${bioType}`}
            </span>
          </button>
        )}

        {/* Divider */}
        {bioAvailable && (
          <div className="w-full flex items-center gap-2 mb-2">
            <div className="flex-1 h-px bg-white/10" />
            <span className="text-[9px] uppercase font-bold tracking-wider text-slate-500">
              or enter PIN
            </span>
            <div className="flex-1 h-px bg-white/10" />
          </div>
        )}

        {/* Temporary Unlock Selector */}
        <div className="w-full flex items-center justify-between mb-2 px-1">
          <span className="text-[10px] text-slate-400 flex items-center gap-1">
            <Clock className="w-3 h-3 text-slate-500" />
            Unlock Duration:
          </span>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setTemporaryOption(null)}
              className={`text-[9px] px-2 py-0.5 rounded-md border transition-all cursor-pointer ${
                temporaryOption === null
                  ? "bg-indigo-500/20 text-indigo-400 border-indigo-500/40"
                  : "bg-slate-800 text-slate-400 border-white/5"
              }`}
            >
              Default
            </button>
            <button
              type="button"
              onClick={() => setTemporaryOption(300)}
              className={`text-[9px] px-2 py-0.5 rounded-md border transition-all cursor-pointer ${
                temporaryOption === 300
                  ? "bg-indigo-500/20 text-indigo-400 border-indigo-500/40"
                  : "bg-slate-800 text-slate-400 border-white/5"
              }`}
            >
              5 Min
            </button>
          </div>
        </div>

        {/* PIN Input Form */}
        <form onSubmit={handlePinSubmit} className="w-full space-y-2">
          <input
            type="password"
            maxLength={8}
            placeholder="••••"
            value={pin}
            onChange={(e) => {
              setPin(e.target.value);
              setError(null);
            }}
            className={`w-full text-center text-lg tracking-[0.4em] py-1.5 rounded-xl border bg-slate-800/80 text-white focus:outline-none transition-colors ${
              error ? "border-red-500" : "border-white/10 focus:border-indigo-500"
            }`}
            autoFocus
          />

          {error && (
            <p className="text-[10px] text-red-400 font-medium text-center">
              {error}
            </p>
          )}

          <div className="flex gap-2 pt-0.5">
            <button
              type="button"
              onClick={handleCancel}
              className="flex-1 py-1.5 rounded-xl text-xs font-semibold border border-white/10 text-slate-300 hover:bg-white/5 transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white border border-white/10 transition-colors cursor-pointer"
            >
              Unlock
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
