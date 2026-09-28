import { useState } from "react";
import { Check, Database, Globe, Moon, ShieldCheck, Sun } from "lucide-react";
import { PageHeader, PlaceholderLabel, StatusTag, Surface } from "../components/common/UI.jsx";

export default function Settings({ darkMode, onToggleTheme }) {
  const [mockEnabled, setMockEnabled] = useState(() => localStorage.getItem("drishti-data-source") !== "live");
  const [saved, setSaved] = useState(false);
  const toggleMocks = () => { setMockEnabled((value) => !value); setSaved(false); };

  return (
    <>
      <PageHeader eyebrow="CONSOLE PREFERENCES" title="Settings" description="Configure the local Drishti control-plane experience." action={<PlaceholderLabel />} />
      <div className="settings-layout">
        <div className="settings-nav"><span className="settings-nav-active"><Globe size={15} /> General</span><span><Database size={15} /> Data connections</span><span><ShieldCheck size={15} /> Security</span></div>
        <div className="settings-content">
          <Surface className="settings-section"><div className="settings-section-head"><div><h2>Appearance</h2><p>Choose how the console looks on this device.</p></div></div><div className="theme-options"><button className={!darkMode ? "theme-option theme-selected" : "theme-option"} onClick={() => darkMode && onToggleTheme()}><Sun size={17} /><strong>Light</strong>{!darkMode && <Check size={14} />}</button><button className={darkMode ? "theme-option theme-selected" : "theme-option"} onClick={() => !darkMode && onToggleTheme()}><Moon size={17} /><strong>Dark</strong>{darkMode && <Check size={14} />}</button></div></Surface>
          <Surface className="settings-section"><div className="settings-section-head"><div><h2>Data source</h2><p>Mock values are used for endpoints not available in the backend.</p></div><PlaceholderLabel /></div><div className="settings-row"><div><strong>Mock API responses</strong><span>Stable sample events, parser records, and component health.</span></div><button className={`toggle-switch${mockEnabled ? " toggle-on" : ""}`} role="switch" aria-checked={mockEnabled} aria-label="Toggle mock API responses" onClick={toggleMocks}><i /></button></div><div className="settings-row"><div><strong>Backend base URL</strong><span className="mono-cell">http://localhost:8080</span></div><StatusTag status="healthy">Configured</StatusTag></div><div className="settings-row"><div><strong>Existing API endpoints</strong><span>Health checks, raw event ingestion, OCSF validation</span></div><a className="inline-link" href="http://localhost:8080/docs" target="_blank" rel="noreferrer">Open API docs <Globe size={13} /></a></div></Surface>
          <Surface className="settings-section"><div className="settings-section-head"><div><h2>System status</h2><p>Resource status is illustrative until the relevant API endpoints are connected.</p></div></div><div className="settings-status"><span><i />API</span><span><i />Kafka / Redpanda</span><span><i />MinIO</span><span><i />Parser engine</span><span><i />OCSF validator</span></div></Surface>
          <div className="settings-save"><span>{saved ? <><Check size={14} /> Preferences saved locally</> : mockEnabled ? "Mock API is enabled" : "Live API mode selected; unavailable routes fall back to mock data"}</span><button className="button button-primary" onClick={() => { localStorage.setItem("drishti-data-source", mockEnabled ? "mock" : "live"); setSaved(true); }}>Save preferences</button></div>
        </div>
      </div>
    </>
  );
}