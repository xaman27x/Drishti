import { useResource } from "../hooks/useResource.js";
import { api } from "../services/api.js";
import { DataTable, PageHeader, PlaceholderLabel, ResourceState, SectionTitle, StatusTag, Surface } from "../components/common/UI.jsx";
import WorkerStatusCard from "../components/ingestion/WorkerStatusCard.jsx";
import { Activity, Database, Globe, Layers } from "lucide-react";

const serviceIcons = { "Kafka / Redpanda": Layers, "MinIO evidence store": Database, "API ingestion": Globe };
const recentColumns = [
  { key: "id", label: "EVENT ID", render: (row) => <span className="mono-cell event-id">{row.id}</span> },
  { key: "source", label: "SOURCE" },
  { key: "format", label: "FORMAT", render: (row) => <span className="format-mark">{row.format}</span> },
  { key: "size", label: "SIZE", className: "mono-cell" },
  { key: "timestamp", label: "RECEIVED", render: (row) => <span className="mono-cell">{new Date(row.timestamp).toISOString().slice(11, 19)} UTC</span> },
  { key: "storage", label: "STORAGE", render: (row) => <StatusTag status="healthy">Archived</StatusTag> },
  { key: "status", label: "STATUS", render: (row) => <StatusTag status={row.status} /> },
];

export default function Ingestion() {
  const { data, loading, error } = useResource(api.getIngestionStatus);

  return (
    <>
      <PageHeader eyebrow="EVIDENCE INTAKE" title="Ingestion" description="Monitor incoming evidence and ingestion sources." action={<PlaceholderLabel />} />
      <ResourceState loading={loading} error={error}>
        <div className="integration-grid">
          {data?.services?.map((service) => {
            const Icon = serviceIcons[service.name] ?? Activity;
            return <ServiceCard key={service.name} service={service} icon={Icon} />;
          })}
        </div>

        <div className="section-spacer" />
        <SectionTitle title="Ingestion worker" detail="Kafka → immutable evidence archive → parser" />
        {data?.worker && <WorkerStatusCard worker={data.worker} />}

        <Surface className="surface-space ingestion-recent">
          <SectionTitle title="Recent ingestion" detail="Latest records accepted for archival" action={<PlaceholderLabel />} />
          <DataTable columns={recentColumns} rows={data?.recent} />
        </Surface>
      </ResourceState>
    </>
  );
}

function ServiceCard({ service, icon: Icon }) {
  return (
    <Surface className="service-card">
      <div className="service-card-head"><span className="service-icon"><Icon size={17} /></span><StatusTag status={service.status}>{service.detail}</StatusTag></div>
      <h3>{service.name}</h3>
      <div className="service-facts">{service.facts.map(([label, value]) => <div key={label}><span>{label}</span><strong className={value.includes(".") || value.includes("/") ? "mono-cell" : ""}>{value}</strong></div>)}</div>
      <div className="service-card-foot"><PlaceholderLabel /><span className="service-healthy-note"><i /> Healthy</span></div>
    </Surface>
  );
}