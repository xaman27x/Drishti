import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, ArrowUpRight, Blocks, Braces, Cpu, Database, Gauge, GitBranch, Inbox, Radio, ScanSearch, Shield, Workflow, ChevronRight } from "lucide-react";
import { api } from "../services/api.js";
import { useResource } from "../hooks/useResource.js";
import { DataTable, Drawer, MetricCard, PageHeader, PlaceholderLabel, ResourceState, SectionTitle, StatusTag, Surface } from "../components/common/UI.jsx";

const pipelineIcons = { sources: Radio, kafka: Blocks, worker: Cpu, minio: Database, parser: Braces, ocsf: ScanSearch, provenance: GitBranch };
const metricIcons = { inbox: Inbox, activity: Activity, gauge: Gauge, braces: Braces, shield: Shield, blocks: Blocks };
const eventColumns = [
  { key: "timestamp", label: "TIME", render: (event) => <span className="mono-cell">{new Date(event.timestamp).toISOString().slice(11, 19)}</span> },
  { key: "id", label: "EVENT ID", render: (event) => <span className="mono-cell event-id">{event.id}</span> },
  { key: "source", label: "SOURCE" },
  { key: "format", label: "FORMAT", render: (event) => <span className="format-mark">{event.format}</span> },
  { key: "parser", label: "PARSER", render: (event) => <span className="mono-cell">{event.parser}</span> },
  { key: "status", label: "STATUS", render: (event) => <StatusTag status={event.status} /> },
  { key: "duration", label: "TIME", className: "align-right mono-cell" },
];

export default function Dashboard() {
  const { data, loading, error } = useResource(api.getDashboard);
  const dashboard = data ?? { stats: [], pipeline: [], events: [] };
  const [selectedStage, setSelectedStage] = useState(null);
  const navigate = useNavigate();

  return (
    <>
      <PageHeader
        eyebrow={new Date().toLocaleDateString()}
        title="Processing overview"
        description="Drishti processing overview"
        action={<PlaceholderLabel />}
      />
      <ResourceState loading={loading} error={error}>
        <div className="metric-grid">
          {dashboard.stats.map((item) => <MetricCard key={item.label} item={item} icon={metricIcons[item.icon]} />)}
        </div>

        <Surface className="dashboard-pipeline surface-space">
          <SectionTitle title="Pipeline health" detail="Current status across the evidence lifecycle" action={<button className="text-action" onClick={() => navigate("/pipeline")}>Full pipeline <ArrowUpRight size={14} /></button>} />
          <div className="pipeline-strip">
            {dashboard.pipeline.map((stage, index) => {
              const Icon = pipelineIcons[stage.id] ?? Workflow;
              return (
                <div className="pipeline-strip-item" key={stage.id}>
                  <button className="pipeline-tile" onClick={() => setSelectedStage(stage)} aria-label={`View ${stage.name} details`}>
                    <div className="pipeline-tile-top"><span className="pipeline-tile-icon"><Icon size={16} /></span><i className={`stage-dot stage-${stage.status}`} /></div>
                    <strong>{stage.name}</strong>
                    <span className="pipeline-description">{stage.description}</span>
                    <span className="pipeline-metric">{stage.metric}</span>
                  </button>
                  {index < dashboard.pipeline.length - 1 && <span className="pipeline-connector"><i /></span>}
                </div>
              );
            })}
          </div>
          <div className="pipeline-footnote"><span><i className="stage-dot stage-healthy" /> Healthy</span><span><i className="stage-dot stage-processing" /> Processing</span><PlaceholderLabel /></div>
        </Surface>

        <Surface className="surface-space activity-surface">
          <SectionTitle title="Recent processing activity" detail="Latest evidence moving through Drishti" action={<button className="text-action" onClick={() => navigate("/events")}>Explore events <ChevronRight size={14} /></button>} />
          <DataTable columns={eventColumns} rows={dashboard.events.slice(0, 5)} onRowClick={(event) => navigate(`/events?q=${encodeURIComponent(event.id)}`)} />
          <div className="table-note"><span>Showing {dashboard.events.length} of {dashboard.total ?? 0} events</span><PlaceholderLabel /></div>
        </Surface>
      </ResourceState>

      <Drawer open={Boolean(selectedStage)} onClose={() => setSelectedStage(null)} title={selectedStage?.name ?? "Pipeline stage"} subtitle="Component overview">
        {selectedStage && <StageDetails stage={selectedStage} />}
      </Drawer>
    </>
  );
}

function StageDetails({ stage }) {
  return <div className="drawer-stack"><StatusTag status={stage.status}>{stage.description}</StatusTag><div className="detail-grid"><div><span>Current metric</span><strong>{stage.metric}</strong></div><div><span>Component ID</span><strong className="mono-cell">{stage.id}</strong></div></div><PlaceholderLabel /><p className="drawer-note">Status refreshed from the backend every three seconds.</p></div>;
}
