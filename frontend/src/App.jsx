import { useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import AppShell from "./components/layout/AppShell.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Events from "./pages/Events.jsx";
import Governance from "./pages/Governance.jsx";
import Ingestion from "./pages/Ingestion.jsx";
import Parsers from "./pages/Parsers.jsx";
import Pipeline from "./pages/Pipeline.jsx";
import Provenance from "./pages/Provenance.jsx";
import Replay from "./pages/Replay.jsx";
import Settings from "./pages/Settings.jsx";

export default function App() {
  const [darkMode, setDarkMode] = useState(() => localStorage.getItem("drishti-theme") === "dark");
  const toggleTheme = () => setDarkMode((current) => {
    const next = !current;
    localStorage.setItem("drishti-theme", next ? "dark" : "light");
    return next;
  });

  return (
    <AppShell darkMode={darkMode} onToggleTheme={toggleTheme}>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/ingestion" element={<Ingestion />} />
        <Route path="/pipeline" element={<Pipeline />} />
        <Route path="/events" element={<Events />} />
        <Route path="/parsers" element={<Parsers />} />
        <Route path="/provenance" element={<Provenance />} />
        <Route path="/replay" element={<Replay />} />
        <Route path="/governance" element={<Governance />} />
        <Route path="/settings" element={<Settings darkMode={darkMode} onToggleTheme={toggleTheme} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}