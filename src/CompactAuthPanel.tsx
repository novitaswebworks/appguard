import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { ShieldAlert, CheckCircle2, Fingerprint, KeyRound, X } from "lucide-react";

interface LockedAppPayload {
  bundle_id: string;
  name: string;
}

export function CompactAuthPanel() {
  const [lockedApp, setLockedApp] = useState<LockedAppPayload | null>(null);
  const [pin, setPin] = useState("");
  const [error, setError] = useState(false);
  const [success, setSuccess] = useState(false);
  const [bioAvailable, setBioAvailable] = useState(false);
  const [bioType, setBioType] = useState("Touch ID");

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
      setError(false);
      setSuccess(false);

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
    await invoke("unlock_app_session", { bundleId });
    setTimeout(async () => {
      setSuccess(false);
      setLockedApp(null);
      const win = getCurrentWindow();
      await win.hide();
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
        setError(true);
        setPin("");
      }
    } catch {
      setError(true);
      setPin("");
    }
  }

  async function handleCancel() {
    if (lockedApp) {
      await invoke("close_locked_application", { bundleId: lockedApp.bundle_id });
    }
    setLockedApp(null);
    setPin("");
    const win = getCurrentWindow();
    await win.hide();
  }

  return (
    <div className="w-full h-full select-none flex items-center justify-center p-2 bg-transparent font-sans">
      <div className="w-[360px] rounded-2xl border border-white/10 bg-slate-900/95 backdrop-blur-2xl shadow-2xl p-5 text-white flex flex-col items-center relative overflow-hidden">
        {/* Close Button */}
        <button
          onClick={handleCancel}
          className="absolute top-3 right-3 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-white/10 transition-colors cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Status Shield Icon */}
        <div className="w-12 h-12 rounded-xl flex items-center justify-center shadow-lg mb-3 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
          {success ? (
            <CheckCircle2 className="w-6 h-6 text-emerald-400 animate-bounce" />
          ) : (
            <ShieldAlert className="w-6 h-6 text-indigo-400" />
          )}
        </div>

        {/* Target App Title */}
        <h2 className="text-base font-bold text-center tracking-tight text-white mb-0.5">
          {lockedApp ? lockedApp.name : "Protected Application"}
        </h2>
        <p className="text-[11px] text-slate-400 text-center mb-4">
          Verification required to access
        </p>

        {/* Biometric Button */}
        {bioAvailable && (
          <button
            onClick={() => lockedApp && handleBiometricAuth(lockedApp.bundle_id, lockedApp.name)}
            className="w-full py-2.5 px-3 mb-3 rounded-xl font-semibold text-xs flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white shadow-md transition-all cursor-pointer"
          >
            {bioType === "SystemPassword" ? (
              <KeyRound className="w-4 h-4" />
            ) : (
              <Fingerprint className="w-4 h-4" />
            )}
            <span>
              {bioType === "SystemPassword"
                ? "Verify with macOS Password"
                : `Unlock with ${bioType}`}
            </span>
          </button>
        )}

        {/* Divider */}
        {bioAvailable && (
          <div className="w-full flex items-center gap-2 mb-3">
            <div className="flex-1 h-px bg-white/10" />
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500">
              or enter PIN
            </span>
            <div className="flex-1 h-px bg-white/10" />
          </div>
        )}

        {/* PIN Input Form */}
        <form onSubmit={handlePinSubmit} className="w-full space-y-3">
          <input
            type="password"
            maxLength={8}
            placeholder="••••"
            value={pin}
            onChange={(e) => {
              setPin(e.target.value);
              setError(false);
            }}
            className={`w-full text-center text-xl tracking-[0.4em] py-2 rounded-xl border bg-slate-800/80 text-white focus:outline-none transition-colors ${
              error ? "border-red-500" : "border-white/10 focus:border-indigo-500"
            }`}
            autoFocus
          />

          {error && (
            <p className="text-[11px] text-red-400 font-medium text-center">
              Incorrect master PIN
            </p>
          )}

          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleCancel}
              className="flex-1 py-2 rounded-xl text-xs font-semibold border border-white/10 text-slate-300 hover:bg-white/5 transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white border border-white/10 transition-colors cursor-pointer"
            >
              Unlock
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
