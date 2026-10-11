import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import { CompactAuthPanel } from "./CompactAuthPanel";
import "./App.css";

function getInitialWindowLabel(): string {
  try {
    return getCurrentWindow().label;
  } catch {
    return "main";
  }
}

const windowLabel = getInitialWindowLabel();

function Root() {
  if (windowLabel === "auth") {
    return <CompactAuthPanel />;
  }

  return <App />;
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
