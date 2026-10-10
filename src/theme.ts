export type ThemeMode = "nordic" | "editorial" | "slate" | "obsidian";

export interface ThemeConfig {
  id: ThemeMode;
  name: string;
  category: "light" | "dark";
  previewBg: string;
  previewAccent: string;
  colors: {
    bgApp: string;
    bgSidebar: string;
    bgHeader: string;
    bgCard: string;
    bgCardLocked: string;
    bgOverlay: string;
    bgModal: string;
    bgInput: string;
    border: string;
    borderCard: string;
    borderLocked: string;
    textPrimary: string;
    textSecondary: string;
    textMuted: string;
    accent: string;
    accentGlow: string;
    accentText: string;
    toggleActive: string;
    toggleInactive: string;
    badgeBg: string;
    badgeText: string;
  };
}

export const THEMES: Record<ThemeMode, ThemeConfig> = {
  nordic: {
    id: "nordic",
    name: "Nordic Minimal",
    category: "light",
    previewBg: "#f8fafc",
    previewAccent: "#2563eb",
    colors: {
      bgApp: "#f8fafc",
      bgSidebar: "#ffffff",
      bgHeader: "#ffffff",
      bgCard: "#ffffff",
      bgCardLocked: "#eff6ff",
      bgOverlay: "rgba(255, 255, 255, 0.88)",
      bgModal: "#ffffff",
      bgInput: "#f1f5f9",
      border: "#e2e8f0",
      borderCard: "#e2e8f0",
      borderLocked: "#bfdbfe",
      textPrimary: "#0f172a",
      textSecondary: "#475569",
      textMuted: "#94a3b8",
      accent: "#2563eb",
      accentGlow: "rgba(37, 99, 235, 0.15)",
      accentText: "#ffffff",
      toggleActive: "#2563eb",
      toggleInactive: "#cbd5e1",
      badgeBg: "#dbeafe",
      badgeText: "#1e40af",
    },
  },
  editorial: {
    id: "editorial",
    name: "Editorial Warm",
    category: "light",
    previewBg: "#faf9f6",
    previewAccent: "#0f766e",
    colors: {
      bgApp: "#faf9f6",
      bgSidebar: "#f4f1eb",
      bgHeader: "#f4f1eb",
      bgCard: "#ffffff",
      bgCardLocked: "#f0fdf4",
      bgOverlay: "rgba(250, 249, 246, 0.92)",
      bgModal: "#ffffff",
      bgInput: "#ebe7df",
      border: "#e5e0d8",
      borderCard: "#e5e0d8",
      borderLocked: "#bbf7d0",
      textPrimary: "#1c1917",
      textSecondary: "#57534e",
      textMuted: "#a8a29e",
      accent: "#0f766e",
      accentGlow: "rgba(15, 118, 110, 0.15)",
      accentText: "#ffffff",
      toggleActive: "#0f766e",
      toggleInactive: "#d6d3d1",
      badgeBg: "#ccfbf1",
      badgeText: "#115e59",
    },
  },
  slate: {
    id: "slate",
    name: "Modern Slate",
    category: "dark",
    previewBg: "#0f172a",
    previewAccent: "#38bdf8",
    colors: {
      bgApp: "#0f172a",
      bgSidebar: "#1e293b",
      bgHeader: "#1e293b",
      bgCard: "#1e293b",
      bgCardLocked: "#0c4a6e22",
      bgOverlay: "rgba(15, 23, 42, 0.92)",
      bgModal: "#1e293b",
      bgInput: "#0f172a",
      border: "#334155",
      borderCard: "#334155",
      borderLocked: "#0284c7",
      textPrimary: "#f8fafc",
      textSecondary: "#cbd5e1",
      textMuted: "#64748b",
      accent: "#38bdf8",
      accentGlow: "rgba(56, 189, 248, 0.2)",
      accentText: "#0f172a",
      toggleActive: "#38bdf8",
      toggleInactive: "#475569",
      badgeBg: "#075985",
      badgeText: "#e0f2fe",
    },
  },
  obsidian: {
    id: "obsidian",
    name: "Obsidian Cyber",
    category: "dark",
    previewBg: "#090a0f",
    previewAccent: "#06b6d4",
    colors: {
      bgApp: "#090a0f",
      bgSidebar: "#0d0f18",
      bgHeader: "#0d0f18",
      bgCard: "#131622",
      bgCardLocked: "#08334433",
      bgOverlay: "rgba(9, 10, 15, 0.92)",
      bgModal: "#0e111a",
      bgInput: "#131622",
      border: "#1e2333",
      borderCard: "#1e2333",
      borderLocked: "#0891b2",
      textPrimary: "#f1f5f9",
      textSecondary: "#94a3b8",
      textMuted: "#475569",
      accent: "#06b6d4",
      accentGlow: "rgba(6, 182, 212, 0.2)",
      accentText: "#090a0f",
      toggleActive: "#06b6d4",
      toggleInactive: "#334155",
      badgeBg: "#164e63",
      badgeText: "#cffafe",
    },
  },
};
