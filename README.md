# AppGuard

> **Cross-Platform Biometric App Lock & Hardware-Accelerated Privacy Vault for macOS, Windows & Linux.**

[![Version](https://img.shields.io/badge/version-0.6.0-emerald.svg)](https://github.com/novitaswebworks/appguard/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey.svg)](#platform-support)
[![Architecture](https://img.shields.io/badge/arch-Rust%202024%20%2B%20Tauri%202-orange.svg)](#architecture)
[![Telemetry](https://img.shields.io/badge/telemetry-0%25%20Airgapped-brightgreen.svg)](#privacy--security-guarantees)

AppGuard intercepts desktop application launches, window switches, and unauthorized access attempts in **< 5ms**, prompting for biometric authentication (Apple Touch ID, Windows Hello, Linux PAM) before sensitive application windows can ever draw to the screen. It also features a hardware-accelerated **AES-256-GCM** privacy vault to cloak confidential files and folders at rest with zero cloud dependency.

Official Website & Downloads: [appguard.novitasweb.works](https://appguard.novitasweb.works)

---

## 📸 Visual Overview

### 1. Instant App Shielding & Biometric Interception
When you launch or switch to a protected app, AppGuard instantly cloaks the target window and displays a minimal, floating authentication prompt right above it. Authenticate via **Touch ID / Windows Hello** or enter your Master PIN to unlock:

<p align="center">
  <img src="docs/images/compact-auth-panel.png" alt="Compact Floating Auth Panel" width="460" />
</p>
<p align="center"><em>Sub-5ms floating biometric prompt — zero disruption, zero dashboard popup</em></p>

---

### 2. Full Security Dashboard & Management

<table>
  <tr>
    <td width="50%" align="center">
      <strong>🛡️ Application Protection Manager</strong><br /><br />
      <img src="docs/images/dashboard-apps.png" alt="App Protection Engine" width="100%" />
      <p align="left"><em>Scan and toggle hardware biometric protection for any installed app in one click.</em></p>
    </td>
    <td width="50%" align="center">
      <strong>🔐 Encrypted Folder Vaults (AES-256-GCM)</strong><br /><br />
      <img src="docs/images/dashboard-vault.png" alt="Encrypted Folder Vaults" width="100%" />
      <p align="left"><em>Cloak and encrypt confidential folders with local hardware-accelerated AES-256-GCM.</em></p>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <strong>🎨 7 Handcrafted Color Palettes</strong><br /><br />
      <img src="docs/images/dashboard-themes.png" alt="Appearance & Themes" width="100%" />
      <p align="left"><em>Ergonomic light & high-contrast cyber dark themes with automatic OS appearance synchronization.</em></p>
    </td>
    <td width="50%" align="center">
      <strong>⚙️ Security Policy & Preferences</strong><br /><br />
      <img src="docs/images/dashboard-settings.png" alt="Security Policies & Preferences" width="100%" />
      <p align="left"><em>Self-defense locks, idle grace periods, tamper-proof OS watchdog, and audit trail history.</em></p>
    </td>
  </tr>
</table>

---

## ✨ Features

- **⚡ Sub-5ms Window Intercept:** Native background watchdog daemon intercepts protected process activations (macOS `NSWorkspace`, Windows Foreground hooks, Linux D-Bus/X11) before window rendering occurs.
- **👆 Multi-Biometric Hardware Integration:**
  - **macOS:** Apple Secure Enclave Touch ID & Apple Watch verification via `LocalAuthentication`.
  - **Windows:** Windows Hello Facial Recognition & Fingerprint sensors via `UserConsentVerifier`.
  - **Linux:** System credentials & fingerprint readers via `PAM` and `fprintd`.
- **🔐 Memory-Hard Argon2id KDF & Brute-Force Defense:**
  - Master PIN storage upgraded to cryptographic **Argon2id** with dedicated per-instance salts.
  - Exponential rate limiting and temporary lockout cooldown timers mitigate brute-force attempts.
- **🎟️ Single-Use Replay-Proof Auth Tickets:**
  - Authentications yield single-use authorization tokens with a strict **15-second consumption window** (`consume_recent_auth()`), preventing replay or background bypass attacks.
- **🪟 Compact Floating Auth Panel:**
  - Discreet, floating, borderless modal window (`auth`) launches directly over intercepted apps so your workflow isn't disrupted by pulling open the main dashboard.
- **🔑 Emergency Recovery Key Safeguard:**
  - Single-use 16-character base32 recovery key (`AG-XXXX-XXXX-XXXX`) hashed with Argon2id allows safe Master PIN reset without data loss or config corruption.
- **🛡️ AES-256-GCM Encrypted Folder Vault:**
  - Hardware-accelerated symmetric vault utilizing 96-bit OsRng nonces. Files and folders are cloaked and encrypted at rest across all disks.
- **📜 Local-First Tamper-Evident Audit Trail:**
  - Persistent FIFO activity log recording up to 150 lock/unlock events, PIN alterations, and watchdog triggers directly on-device.
- **💤 Session & Sleep Auto-Arming:**
  - Locks protected applications the moment your laptop lid closes, display goes to sleep, screensaver triggers, or customizable idle grace timers expire.
- **🎨 7 Handcrafted Appearance Themes:**
  - Auto-system theme synchronization plus handcrafted presets: *Nordic Minimal*, *Editorial Warm*, *Obsidian Cyber*, *Modern Slate*, *Emerald Zen*, *Rose Quartz*, and *Sunset Amber*.
- **🌐 100% Airgapped & Zero Telemetry:**
  - No cloud servers, no tracking analytics, no telemetry, and no account requirements.

---

## 💻 Platform Support

| Operating System | Architecture | Supported Biometrics / Auth | Package Format |
| :--- | :--- | :--- | :--- |
| **macOS 12+** | Apple Silicon (`arm64`) & Intel (`x86_64`) | Touch ID, Apple Watch, Argon2id PIN | `.dmg` (Universal), Homebrew |
| **Windows 10 / 11** | 64-bit (`x64`) | Windows Hello (Face / Fingerprint / PIN) | `.exe` (NSIS Installer) |
| **Linux (X11 & Wayland)** | `x86_64` | Linux PAM, `fprintd`, Argon2id PIN | `.AppImage`, `.deb` |

---

## 🚀 Installation

### macOS

#### Homebrew (Recommended)
```bash
brew install --cask novitaswebworks/tap/appguard
```

#### Universal DMG
Download the latest `AppGuard_0.6.0_universal.dmg` from the [GitHub Releases](https://github.com/novitaswebworks/appguard/releases) page or the [Landing Page](https://appguard.novitasweb.works). Mount the disk image and drag **AppGuard** into your `/Applications` directory.

> **macOS Permissions:** AppGuard requires *Accessibility* permissions to monitor application window switching and provide sub-5ms window protection. Grant this in `System Settings → Privacy & Security → Accessibility`.

---

### Windows (10 & 11)

Download `AppGuard_0.6.0_x64-setup.exe` from [Releases](https://github.com/novitaswebworks/appguard/releases). Run the installer and launch AppGuard. Windows Hello will be automatically detected if configured in Windows Settings.

---

### Linux

#### AppImage
```bash
chmod +x AppGuard_0.6.0_amd64.AppImage
./AppGuard_0.6.0_amd64.AppImage
```

#### Debian / Ubuntu (.deb)
```bash
sudo dpkg -i AppGuard_0.6.0_amd64.deb
sudo apt-get install -f
```

---

## 🔒 Security Architecture

```
                                  +---------------------------------------+
                                  |     Target Application Launch /       |
                                  |       Window Focus Intercept          |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |   High-Performance Rust Watchdog      |
                                  |    (< 5ms Platform Native Hook)       |
                                  +---------------------------------------+
                                                      |
                                       [ Is Target App Protected? ]
                                                      |
                                          Yes --------+-------- No -> (Pass Through)
                                          |
                                          v
                         +-----------------------------------+
                         |  Compact Floating Auth Window     |
                         |  (Directly Over Intercepted App)  |
                         +-----------------------------------+
                                          |
                          [ Biometric Sensor / Argon2id PIN ]
                                          |
                        Success ----------+---------- Failure
                          |                             |
                          v                             v
+------------------------------------+   +-----------------------------------+
|  Single-Use Auth Ticket Generated  |   |  Exponential Rate Limit Count     |
|      (15-Second Expiry Window)     |   |  & Lockout Cooldown Enforced      |
+------------------------------------+   +-----------------------------------+
                  |
                  v
+------------------------------------+
|  consume_recent_auth() Validates   |
|  & Target Application Uncloaked    |
+------------------------------------+
                  |
                  v
+------------------------------------+
|  Event Recorded in Audit Log FIFO  |
+------------------------------------+
```

### Cryptographic Details
- **Master PIN Hash:** Argon2id (`m_cost = 19456`, `t_cost = 2`, `p_cost = 1`) with 16-byte cryptographically secure random salt generated via `rand::rngs::OsRng`.
- **Vault Encryption:** AES-256-GCM cipher with unique 96-bit initialization vectors (nonces) per file.
- **Recovery Key:** 16-character Base32 emergency key with Argon2id verification for resilient, airgapped disaster recovery.
- **Config Integrity:** Atomic file writes with `.tmp` staging and `.bak` snapshots prevent corruption during system interruptions.

---

## 🛠️ Development & Building from Source

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+) & [pnpm](https://pnpm.io/)
- [Rust](https://rustup.rs/) (v1.85+ recommended, 2024 edition)
- Platform-specific dependencies:
  - **macOS:** Xcode Command Line Tools (`xcode-select --install`)
  - **Linux:** `libwebkit2gtk-4.1-dev`, `build-essential`, `curl`, `wget`, `file`, `libxdo-dev`, `libssl-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`
  - **Windows:** Microsoft Visual Studio C++ Build Tools & WebView2

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/novitaswebworks/appguard.git
   cd appguard
   ```

2. **Install frontend dependencies:**
   ```bash
   pnpm install
   ```

3. **Run in development mode:**
   ```bash
   pnpm run tauri dev
   ```

4. **Run verification checks:**
   ```bash
   # Frontend TypeScript & Vite build
   pnpm run build

   # Rust backend check
   cd src-tauri && cargo check
   ```

5. **Build release packages:**
   ```bash
   pnpm run tauri build
   ```

---

## 📁 Repository Layout

```
appguard/
├── .github/              # GitHub Actions release & CI workflows
├── src/                  # React 19 + TypeScript frontend
│   ├── App.tsx           # Main dashboard window UI
│   ├── CompactAuthPanel.tsx # Floating minimal auth prompt window
│   ├── theme.ts          # 7 handcrafted color themes & CSS variable engine
│   ├── useUpdater.ts     # Release update checker & notification hook
│   └── main.tsx          # Multi-window router entry point
├── src-tauri/            # Tauri 2 Rust backend
│   ├── src/
│   │   ├── auth.rs       # Platform biometric bindings (Touch ID, Hello, PAM)
│   │   ├── lib.rs        # IPC command handlers & lifecycle events
│   │   ├── platform.rs   # OS window activation & process management
│   │   ├── scanner.rs    # Installed application scanning logic
│   │   ├── state.rs      # Argon2id KDF, recovery key, audit log & config
│   │   ├── vault.rs      # AES-256-GCM file & folder encryption engine
│   │   └── watchdog.rs   # Sub-5ms application intercept daemon
│   ├── Cargo.toml        # Rust dependencies & build profile
│   └── tauri.conf.json   # Multi-window definitions, capabilities & bundle config
└── package.json          # Frontend packages & scripts
```

---

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome! Please check open issues or open a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

Developed with care by **[Novitas Web Works](https://novitasweb.works)**.
