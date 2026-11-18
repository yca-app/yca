import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { TooltipProvider } from "@/components/ui/tooltip";

// Light or dark follows the system, and keeps following it.
const dark = window.matchMedia("(prefers-color-scheme: dark)");
const applyTheme = () => document.documentElement.classList.toggle("dark", dark.matches);
applyTheme();
dark.addEventListener("change", applyTheme);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <TooltipProvider delayDuration={400}>
      <App />
    </TooltipProvider>
  </React.StrictMode>,
);
