import { useState } from "react";
import { Activity, ArrowDown, ArrowRight, Braces, Boxes, Cpu, Database, GitBranch, Radio, ScanSearch, Settings2, Workflow } from "lucide-react";
import { useResource } from "../hooks/useResource.js";
import { api } from "../services/api.js";
import { Drawer, PageHeader, PlaceholderLabel, ResourceState, SectionTitle, StatusTag, Surface } from "../components/common/UI.jsx";

const iconMap = { sources: Radio, kafka: Boxes, worker: Cpu, minio: Database, parser: Braces, ocsf: ScanSearch, provenance: GitBranch };

export default function Pipeline() {
  const { data, loading, error } = useResource(api.getPipelineStatus);
  const [selected, setSelected] = useState(null);

  return (
    <>
      <PageHeader eyebrow="SYSTEM TOPOLOGY" title="Pipeline" description="Follow raw evidence from intake to traceable OCSF events." action={<PlaceholderLabel />} />
      <ResourceState loading={loading} error={error}>
        <Surface className="pipeline-overview surface-space">
          <div className="pipeline-overview-head"><div><span className="eyebrow">PIPELINE SNAPSHOT</span><h2>Evidence processing</h2><p>Illustrative component state across the evidence lifecycle.</p></div><StatusTag status="healthy">Mock status</StatusTag></div>
          <div className="topology-flow">
            {data?.map((stage, index) => {
              const Icon = iconMap[stage.id] ?? Workflow;
              return <div className="topology-step-wrap" key={stage.id}>
                <button className={`topology-node node-${stage.status}`} onClick={() => setSelected(stage)}>
                  <span className="topology-node-icon"><Icon size={18} /></span>
                  <span className="topology-node-title">{stage.name}</span>
                  <span className="topology-node-status"><i className={`stage-dot stage-${stage.status}`} />{stage.description}</span>
                  <span className="topology-node-metric">{stage.metric}</span>
                  <span className="topology-node-open"><Settings2 size={13} /> Details</span>
                </button>
                {index < (data?.length ?? 0) - 1 && <div className="topology-connector"><span /><ArrowRight size={15} /></div>}
              </div>;
            })}
          </div>
          <div className="topology-legend"><span><i className="stage-dot stage-healthy" /> Healthy</span><span><i className="stage-dot stage-processing" /> Active processing</span><span className="topology-update"><Activity size={13} /> Static mock snapshot <PlaceholderLabel /></span></div>
        </Surface>

        <div className="pipeline-lower-grid">
          <Surface className="pipeline-note-card"><span className="pipeline-note-icon"><ArrowDown size={16} /></span><div><h3>Evidence-first ordering</h3><p>Raw evidence is archived before it is made visible downstream. Parser output remains linked to the immutable source record.</p></div></Surface>
          <Surface className="pipeline-note-card"><span className="pipeline-note-icon"><GitBranch size={16} /></span><div><h3>Traceable normalization</h3><p>Field lineage and byte-disposition claims follow each normalized event through OCSF validation.</p></div></Surface>
        </div>
      </ResourceState>
      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.name ?? "Pipeline component"} subtitle="Component detail · API placeholder">
        {selected && <PipelineDetails stage={selected} />}
      </Drawer>
    </>
  );
}

function PipelineDetails({ stage }) {
  return (
    <div className="drawer-stack">
      <div className="detail-status-row"><StatusTag status={stage.status}>{stage.description}</StatusTag><PlaceholderLabel /></div>
      <div className="detail-grid"><div><span>Throughput</span><strong>{stage.metric}</strong></div><div><span>Component key</span><strong className="mono-cell">{stage.id}</strong></div><div><span>Configuration</span><strong>Managed by deployment</strong></div><div><span>Last update</span><strong>4 sec ago</strong></div></div>
      <div className="drawer-subsection"><h3>Endpoint</h3><code>API placeholder</code></div>
      <div className="drawer-subsection"><h3>Recent activity</h3><div className="drawer-log-line"><i className="stage-dot stage-healthy" /><span>{stage.name} health check passed</span><time>18:42:16 UTC</time></div><div className="drawer-log-line"><i className="stage-dot stage-processing" /><span>{stage.metric} observed</span><time>18:42:12 UTC</time></div></div>
      <div className="drawer-subsection"><h3>Logs</h3><div className="log-placeholder">Logs endpoint not connected yet.</div></div>
    </div>
  );
}