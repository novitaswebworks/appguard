import { useEffect, useRef, useState, type FormEvent } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ShieldAlert, Fingerprint, X } from "lucide-react";

interface Target { bundle_id: string; name: string; request_id: number }

export function CompactAuthPanel() {
  const [target, setTarget] = useState<Target | null>(null);
  const [pin, setPin] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const [bioAvailable, setBioAvailable] = useState(false);
  const [duration, setDuration] = useState<number | null>(null);

  useEffect(() => {
    let disposed = false;
    let revision = 0;
    const update = (next: Target | null) => {
      if (!disposed) setTarget((current) => current?.request_id === next?.request_id ? current : next);
    };
    const refresh = () => {
      const current = ++revision;
      invoke<Target | null>("get_locked_app_target").then((next) => {
        if (current === revision) update(next);
      }).catch((err) => { if (!disposed) setError(String(err)); });
    };
    const unlisten = listen<Target>("app-locked-triggered", (event) => { revision += 1; update(event.payload); });
    invoke<{ is_available: boolean }>("check_biometrics").then((value) => { if (!disposed) setBioAvailable(value.is_available); }).catch(() => setBioAvailable(false));
    refresh(); window.addEventListener("focus", refresh);
    return () => { disposed = true; window.removeEventListener("focus", refresh); void unlisten.then((stop) => stop()); };
  }, []);

  useEffect(() => { setPin(""); setError(null); setDuration(null); }, [target?.request_id]);

  async function authenticate(useBiometrics: boolean) {
    if (!target || inFlight.current) return;
    inFlight.current = true; setBusy(true); setError(null);
    const current = target;
    try {
      const ok = await invoke<boolean>("authenticate_target", {
        bundleId: current.bundle_id, requestId: current.request_id, pin: useBiometrics ? null : pin,
      });
      if (!ok) { setError("Incorrect Master PIN"); return; }
      await invoke("unlock_app_session", {
        bundleId: current.bundle_id, requestId: current.request_id, durationSecs: duration,
      });
      setTarget((next) => next?.request_id === current.request_id ? null : next);
    } catch (err) { setError(String(err)); }
    finally { setPin(""); setBusy(false); inFlight.current = false; }
  }

  async function cancel() {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(true);
    try {
      if (target) await invoke("close_locked_application", { bundleId: target.bundle_id, requestId: target.request_id });
      else await invoke("hide_auth_window");
      setTarget(null); setPin("");
    } catch (err) { setError(String(err)); }
    finally { setBusy(false); inFlight.current = false; }
  }

  function submit(event: FormEvent) { event.preventDefault(); if (pin) void authenticate(false); }

  return (
    <div className="h-screen w-screen overflow-y-auto p-2 bg-transparent text-white">
      <section aria-label="Application authentication" className="relative mx-auto max-w-[340px] rounded-2xl border border-white/10 bg-slate-900 p-4 shadow-xl">
        <button onClick={cancel} disabled={busy} aria-label="Cancel authentication" className="absolute right-1 top-1 p-3 disabled:opacity-50"><X className="h-4 w-4" /></button>
        <ShieldAlert aria-hidden="true" className="mx-auto mb-2 h-8 w-8 text-indigo-400" />
        <h1 className="text-center text-sm font-bold truncate">{target?.name || "Protected application"}</h1>
        <p className="text-center text-xs text-slate-300 mb-3">Authenticate to restore this window</p>
        {bioAvailable && <button disabled={busy || !target} onClick={() => authenticate(true)} className="w-full mb-3 p-2 rounded-lg bg-indigo-600 flex items-center justify-center gap-2 disabled:opacity-50"><Fingerprint className="h-4 w-4" />Use system authentication</button>}
        <form onSubmit={submit} className="space-y-2">
          <label className="block text-xs" htmlFor="app-pin">Master PIN</label>
          <input id="app-pin" type="password" autoComplete="current-password" autoFocus disabled={busy} value={pin} onChange={(event) => setPin(event.target.value)} className="w-full p-2 rounded-lg bg-slate-800 border border-slate-600 text-center" />
          <label className="flex justify-between items-center text-xs">Unlock duration
            <select aria-label="Unlock duration" disabled={busy} value={duration ?? "default"} onChange={(event) => setDuration(event.target.value === "default" ? null : 300)} className="bg-slate-800 p-1 rounded">
              <option value="default">Default</option><option value="300">5 minutes</option>
            </select>
          </label>
          {error && <p role="alert" className="text-xs text-red-300 break-words">{error}</p>}
          <div className="flex gap-2 pt-1">
            <button type="button" disabled={busy} onClick={cancel} className="flex-1 rounded-lg border border-slate-600 p-2 disabled:opacity-50">Cancel</button>
            <button disabled={busy || !pin || !target} type="submit" className="flex-1 rounded-lg bg-indigo-600 p-2 disabled:opacity-50">{busy ? "Verifying…" : "Unlock"}</button>
          </div>
        </form>
      </section>
    </div>
  );
}
