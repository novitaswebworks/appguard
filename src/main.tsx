import React, { useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import { CompactAuthPanel } from "./CompactAuthPanel";
import "./App.css";

function Root() {
  const [windowLabel, setWindowLabel] = useState<string>("main");

  useEffect(() => {
    try {
      const win = getCurrentWindow();
      setWindowLabel(win.label);
    } catch {
      setWindowLabel("main");
    }
  }, []);

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
