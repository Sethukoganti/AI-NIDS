/**
 * About page — project overview with PUC (block diagram) for presentation.
 * Limited but effective: one screen, no scroll-heavy walls of text.
 */
import {
  ArrowRight, Brain, Database, FileSearch, Network,
  ShieldAlert, ShieldCheck, Wifi, Cpu, GitBranch,
} from 'lucide-react'

const PIPELINE_STAGES = [
  { icon: Wifi,        label: 'Packet Capture',   detail: 'Npcap sniffs live Wi-Fi/LAN traffic' },
  { icon: Network,     label: 'Flow Assembly',    detail: 'Packets grouped into bidirectional flows' },
  { icon: Database,    label: 'Feature Extraction', detail: '70 CICIDS2017 statistical features computed' },
  { icon: Brain,       label: 'Random Forest',    detail: '100-tree classifier, 99.6% test accuracy' },
  { icon: ShieldAlert, label: 'Risk Scoring',      detail: 'Confidence × severity weight = risk level' },
  { icon: ShieldCheck, label: 'Threat Report',     detail: 'Plain-language verdict + precautions' },
]

const ATTACK_CLASSES = [
  'DoS Hulk', 'DDoS', 'Port Scanning', 'SSH/FTP Brute Force',
  'Web Attack (SQLi/XSS)', 'Botnet', 'Infiltration', 'Heartbleed',
]

const STATS = [
  { value: '99.6%', label: 'Test Accuracy' },
  { value: '70', label: 'Flow Features' },
  { value: '100', label: 'Decision Trees' },
  { value: '8', label: 'Attack Classes' },
]

export function About() {
  return (
    <div className="space-y-5">

      {/* ══ Hero ════════════════════════════════════════════════════════════ */}
      <div className="relative overflow-hidden rounded-2xl border border-border/60 bg-panel/60 p-8">
        <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-primary/10 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-16 -left-10 h-56 w-56 rounded-full bg-blue-500/5 blur-3xl" />
        <div className="pointer-events-none absolute inset-0 grid-line opacity-10" />

        <div className="relative text-center space-y-3">
          <div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-primary/40 bg-primary/10 shadow-[0_0_40px_rgba(34,211,238,0.2)]">
            <ShieldCheck className="h-8 w-8 text-primary" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight">AI-Powered Network Intrusion Detection System</h1>
          <p className="mx-auto max-w-2xl text-sm text-muted-foreground">
            A real-time network monitor that captures live traffic, classifies every connection using a
            machine-learning model trained on the CICIDS2017 benchmark dataset, and explains detected
            threats in plain language with concrete precautions.
          </p>

          {/* Stats row */}
          <div className="flex justify-center gap-6 pt-3">
            {STATS.map(({ value, label }) => (
              <div key={label}>
                <div className="text-2xl font-bold text-primary tabular-nums">{value}</div>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ══ PUC / Block Diagram ═══════════════════════════════════════════════ */}
      <div className="rounded-2xl border border-border/60 bg-panel/50 p-6">
        <div className="mb-5 flex items-center gap-2">
          <GitBranch className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-foreground">
            System Architecture — Processing Pipeline
          </h2>
        </div>

        <div className="flex flex-wrap items-stretch justify-center gap-2">
          {PIPELINE_STAGES.map(({ icon: Icon, label, detail }, i) => (
            <div key={label} className="flex items-stretch gap-2">
              <div className="flex w-[150px] flex-col items-center gap-2 rounded-xl border border-border/60 bg-background/40 p-3 text-center">
                <div className="grid h-10 w-10 place-items-center rounded-lg border border-primary/30 bg-primary/10">
                  <Icon className="h-5 w-5 text-primary" />
                </div>
                <div className="text-xs font-semibold text-foreground">{label}</div>
                <div className="text-[10px] leading-tight text-muted-foreground">{detail}</div>
              </div>
              {i < PIPELINE_STAGES.length - 1 && (
                <div className="flex items-center">
                  <ArrowRight className="h-4 w-4 text-primary/50" />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ══ Two columns: Model + Attack types ═══════════════════════════════ */}
      <div className="grid gap-4 md:grid-cols-2">

        {/* Model details */}
        <div className="rounded-2xl border border-border/60 bg-panel/50 p-6 space-y-3">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-bold uppercase tracking-wider">Machine Learning Model</h3>
          </div>
          <div className="space-y-2 text-xs text-muted-foreground">
            <div className="flex justify-between border-b border-border/40 pb-2">
              <span>Algorithm</span>
              <span className="font-mono text-foreground">Random Forest Classifier</span>
            </div>
            <div className="flex justify-between border-b border-border/40 pb-2">
              <span>Trees</span>
              <span className="font-mono text-foreground">100 estimators</span>
            </div>
            <div className="flex justify-between border-b border-border/40 pb-2">
              <span>Training Dataset</span>
              <span className="font-mono text-foreground">CICIDS2017</span>
            </div>
            <div className="flex justify-between border-b border-border/40 pb-2">
              <span>Features per Flow</span>
              <span className="font-mono text-foreground">70 statistical metrics</span>
            </div>
            <div className="flex justify-between border-b border-border/40 pb-2">
              <span>Test Accuracy</span>
              <span className="font-mono text-emerald-400">99.6%</span>
            </div>
            <div className="flex justify-between">
              <span>Explainability</span>
              <span className="font-mono text-foreground">SHAP + feature importance</span>
            </div>
          </div>
        </div>

        {/* Attack classes */}
        <div className="rounded-2xl border border-border/60 bg-panel/50 p-6 space-y-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-orange-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider">Detected Attack Classes</h3>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {ATTACK_CLASSES.map((a) => (
              <div key={a} className="rounded-lg border border-orange-500/20 bg-orange-500/5 px-3 py-2 text-xs text-orange-200">
                {a}
              </div>
            ))}
          </div>
          <p className="pt-1 text-[11px] text-muted-foreground">
            Each detection includes a plain-language explanation and specific precaution steps —
            not just a label.
          </p>
        </div>
      </div>

      {/* ══ Key features strip ══════════════════════════════════════════════ */}
      <div className="rounded-2xl border border-border/60 bg-panel/50 p-6">
        <div className="mb-4 flex items-center gap-2">
          <FileSearch className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-bold uppercase tracking-wider">Key Capabilities</h3>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          {[
            { title: 'Real-Time Capture', body: 'Monitors live Wi-Fi/LAN traffic via Npcap — no sample data required to start.' },
            { title: 'Explainable Verdicts', body: 'Every threat includes what it is and exactly what action to take.' },
            { title: 'Attack Simulation', body: 'Replays real CICIDS2017 attack flows to demonstrate detection on demand.' },
          ].map(({ title, body }) => (
            <div key={title} className="rounded-xl border border-border/50 bg-background/30 p-4">
              <div className="text-xs font-semibold text-foreground">{title}</div>
              <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{body}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
