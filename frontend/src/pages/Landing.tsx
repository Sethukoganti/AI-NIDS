import { Link } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  BrainCircuit,
  Eye,
  FileSearch,
  GitBranch,
  Layers,
  Network,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  Zap,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { NetworkBackground } from '@/components/NetworkBackground'
import { useAuth } from '@/context/AuthContext'

const PIPELINE = [
  { icon: Network, title: 'Network Traffic', text: 'Upload CICIDS2017-compatible network-flow records' },
  { icon: Layers, title: 'Preprocessing', text: 'Feature alignment to the trained schema, inf/NaN cleaning' },
  { icon: BrainCircuit, title: 'Random Forest', text: '100 decision trees vote across 9 traffic classes' },
  { icon: ScanSearch, title: 'Prediction', text: 'Per-flow class + model confidence from predict_proba' },
  { icon: TriangleAlert, title: 'Risk & Alerts', text: 'Documented severity rules, aggregated alerting' },
  { icon: Sparkles, title: 'Explanation', text: 'TreeSHAP drivers + evidence-grounded AI assistant' },
]

const CAPABILITIES = [
  {
    icon: Activity,
    title: 'Real inference, not a mock-up',
    text: 'Every number in the dashboard comes from the trained Random Forest running over data you supply through the API.',
  },
  {
    icon: Eye,
    title: 'Explainable detections',
    text: 'Per-record TreeSHAP contributions show which flow features pushed a record towards an attack class and by how much.',
  },
  {
    icon: FileSearch,
    title: 'Inspectable records',
    text: 'Filter, sort and open any analysed flow to see its ports, rate, packet statistics, risk score and explanation.',
  },
  {
    icon: GitBranch,
    title: 'Honest by design',
    text: 'The reported accuracy is measured on a held-out CICIDS2017 split - it is labelled everywhere as a test-split result, never a live guarantee.',
  },
]

export function Landing() {
  const { user } = useAuth()

  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="pointer-events-none absolute inset-0 grid-line opacity-40" />
      <div className="pointer-events-none absolute -top-40 right-0 h-[420px] w-[420px] rounded-full bg-primary/10 blur-[120px]" />

      <header className="relative z-10 mx-auto flex max-w-6xl items-center justify-between px-5 py-5">
        <div className="flex items-center gap-2.5">
          <div className="grid h-9 w-9 place-items-center rounded-lg border border-primary/30 bg-primary/10">
            <ShieldCheck className="h-5 w-5 text-primary" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold tracking-wide">AI-NIDS</div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Intrusion Detection System
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" asChild>
            <Link to="/login">Sign in</Link>
          </Button>
          <Button size="sm" asChild>
            <Link to={user ? '/dashboard' : '/login'}>
              {user ? 'Open console' : 'Launch Dashboard'}
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </Button>
        </div>
      </header>

      <section className="relative z-10 mx-auto grid max-w-6xl items-center gap-8 px-5 pb-10 pt-6 lg:grid-cols-[1.05fr_1fr]">
        <div className="animate-fade-up">
          <Badge variant="secondary" className="mb-4 gap-1.5">
            <Zap className="h-3 w-3 text-primary" />
            Random Forest · CICIDS2017 · FastAPI · React
          </Badge>
          <h1 className="text-4xl font-semibold leading-[1.05] tracking-tight sm:text-5xl">
            AI-Powered
            <span className="bg-gradient-to-r from-primary to-blue-400 bg-clip-text text-transparent"> Network Intrusion </span>
            Detection System
          </h1>
          <p className="mt-4 text-base text-muted-foreground">Detect. Analyze. Explain. Respond.</p>
          <p className="mt-4 max-w-xl text-sm leading-relaxed text-muted-foreground">
            AI-NIDS analyses network-flow records with a supervised Random Forest classifier trained on the
            CICIDS2017 benchmark, scores each detection with a documented risk engine, raises trackable alerts,
            and explains every decision with SHAP-based feature attribution plus an evidence-grounded AI
            assistant. Built as a defensive monitoring system - it watches traffic, it never attacks anything.
          </p>
          <div className="mt-6 flex flex-wrap items-center gap-3">
            <Button size="lg" asChild>
              <Link to={user ? '/dashboard' : '/login'}>
                <ShieldCheck className="h-4 w-4" />
                Launch Dashboard
              </Link>
            </Button>
            <Button size="lg" variant="outline" asChild>
              <a href="#detection">
                <ScanSearch className="h-4 w-4" />
                Explore Detection
              </a>
            </Button>
          </div>
          <p className="mt-4 text-[11px] text-muted-foreground">
            Demo accounts are pre-provisioned for the college demonstration - see the login page.
          </p>
        </div>

        <div className="relative animate-fade-up">
          <div className="pointer-events-none absolute inset-0 grid-line opacity-30" />
          <NetworkBackground className="relative w-full" />
        </div>
      </section>

      <section id="detection" className="relative z-10 mx-auto max-w-6xl px-5 py-10">
        <h2 className="text-lg font-semibold tracking-tight">The detection pipeline</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Every stage below is implemented in the running application - not a slide.
        </p>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {PIPELINE.map((stage, index) => (
            <Card key={stage.title} className="card-hover p-4">
              <div className="flex items-center gap-3">
                <div className="grid h-9 w-9 place-items-center rounded-lg border border-border bg-background/60">
                  <stage.icon className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    Stage {index + 1}
                  </div>
                  <div className="text-sm font-medium">{stage.title}</div>
                </div>
              </div>
              <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{stage.text}</p>
            </Card>
          ))}
        </div>
      </section>

      <section className="relative z-10 mx-auto max-w-6xl px-5 pb-14">
        <div className="grid gap-3 lg:grid-cols-2">
          {CAPABILITIES.map((item) => (
            <Card key={item.title} className="flex gap-3 p-4">
              <item.icon className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              <div>
                <div className="text-sm font-medium">{item.title}</div>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{item.text}</p>
              </div>
            </Card>
          ))}
        </div>
      </section>

      <footer className="relative z-10 border-t border-border/60 py-6">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-2 px-5 text-[11px] text-muted-foreground">
          <span>AI-NIDS · college project · defensive network monitoring only</span>
          <span>Random Forest on CICIDS2017 · tree-based explainability · FastAPI + React</span>
        </div>
      </footer>
    </div>
  )
}
