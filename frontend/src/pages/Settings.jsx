import { PageHeader, Surface, JsonViewer, ResourceState } from "../components/common/UI.jsx";
import { api } from "../services/api.js";
import { useResource } from "../hooks/useResource.js";
export default function Settings({darkMode, onToggleTheme}) {
  const health = useResource(api.getSystemHealth);
  return <><PageHeader title="Settings" description="Local demo configuration" /><Surface className="surface-space"><button className="button button-secondary" onClick={onToggleTheme}>{darkMode ? "Light" : "Dark"} theme</button><p>The console uses the live API. Failed requests display errors; no mock fallback is enabled.</p><p>Local reviewer roles share server-held demo keys. This is not a production authentication system.</p><a href="/docs" target="_blank" rel="noreferrer">Open API documentation</a></Surface><ResourceState loading={health.loading} error={health.error}><JsonViewer value={health.data} /></ResourceState></>;
}
