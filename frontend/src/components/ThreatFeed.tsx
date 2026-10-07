/**
 * Shared threat feed components used by both LiveCapture and Simulation pages.
 * Provides: ATTACK_INFO knowledge base, ThreatCard, SafeFlowRow, ThreatFeed
 */
import { Ban, ClipboardList, Info, ShieldAlert, ShieldCheck, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { cn, formatNumber, formatPercent } from '@/lib/format'

// --------------------------------------------------------------------------- //
// Types
// --------------------------------------------------------------------------- //
export interface ScoredFlow {
  index: number
  prediction: string
  confidence: number
  is_attack: boolean
  risk_level: string
  risk_score: number
  source_ip?: string | null
  destination_ip?: string | null
  source_port?: number | null
  destination_port?: number | null
  protocol?: string | null
  flow_duration?: number | null
  packet_rate?: number | null
  ground_truth?: string | null
}

// --------------------------------------------------------------------------- //
// Attack knowledge base
// --------------------------------------------------------------------------- //
const ATTACK_INFO: Record<string, { what: string; precautions: string[] }> = {
  'DoS Hulk': {
    what: 'A Denial of Service attack using HTTP flooding (Hulk tool). It tries to overwhelm a web server with massive traffic so it stops responding to legitimate users.',
    precautions: [
      'Block the source IP in your firewall immediately.',
      'Enable rate limiting on your web server (nginx/Apache).',
      'Consider a CDN or DDoS protection service like Cloudflare.',
      'Monitor CPU and memory — the server may be under heavy load.',
    ],
  },
  'DoS GoldenEye': {
    what: 'A targeted HTTP-layer DoS attack that keeps many connections open simultaneously to exhaust server threads and memory.',
    precautions: [
      'Block the source IP in your firewall.',
      'Reduce the maximum number of concurrent connections per IP.',
      'Enable connection timeouts on your web server.',
      'Check if the web service is still responding normally.',
    ],
  },
  'DoS slowloris': {
    what: 'An attack that opens many slow, partial HTTP connections to exhaust your server\'s connection pool — without using much bandwidth, making it hard to detect.',
    precautions: [
      'Enable mod_reqtimeout (Apache) or equivalent timeout on nginx.',
      'Set short connection timeouts for incomplete requests.',
      'Block the source IP if it keeps reconnecting.',
      'Consider IP-based rate limiting.',
    ],
  },
  'DoS Slowhttptest': {
    what: 'Similar to Slowloris — sends partial HTTP requests very slowly to tie up server resources and deny service to legitimate users.',
    precautions: [
      'Configure your server to reject slow or incomplete HTTP headers.',
      'Set request timeout values (recommended: 10–30 seconds).',
      'Block the source IP in your firewall.',
    ],
  },
  'DDoS': {
    what: 'Distributed Denial of Service — a coordinated flood of traffic from many different sources targeting a machine or network to make it unavailable.',
    precautions: [
      'Contact your ISP — DDoS mitigation requires upstream filtering.',
      'Enable any built-in DDoS protection on your router or firewall.',
      'Consider Cloudflare or another DDoS protection service.',
      'Document source IPs and report to your ISP.',
      'Do not try to block individual IPs — there are too many sources.',
    ],
  },
  'Port Scan': {
    what: 'Someone is systematically probing your machine\'s ports to discover which services are running — this is reconnaissance that often precedes an actual attack.',
    precautions: [
      'Check which ports are open: run netstat -an in a terminal.',
      'Close any unnecessary services and ports on your firewall.',
      'Block the scanning IP if repeated scans occur.',
      'This is reconnaissance — a targeted attack may follow.',
    ],
  },
  'PortScan': {
    what: 'Someone is probing your machine\'s ports to discover running services. This is the first step in most network attacks.',
    precautions: [
      'Check which ports are open: netstat -an',
      'Close services you don\'t need.',
      'Enable your firewall and block the source IP.',
    ],
  },
  'FTP-Patator': {
    what: 'A brute-force attack on an FTP server — automatically trying many username and password combinations to gain unauthorized access.',
    precautions: [
      'Disable FTP if you don\'t use it — use SFTP instead (it\'s encrypted).',
      'Block the attacking IP in your firewall.',
      'Enable account lockout after repeated failed login attempts.',
      'Check FTP logs for any successful logins — the account may be compromised.',
    ],
  },
  'SSH-Patator': {
    what: 'A brute-force attack on SSH — automatically trying to guess your SSH login password to gain remote access to your machine.',
    precautions: [
      'Block the source IP in your firewall immediately.',
      'Disable password-based SSH — use SSH key authentication only.',
      'Change your SSH port from the default 22 to a non-standard port.',
      'Install fail2ban to automatically block repeated failures.',
      'Check auth logs for successful logins: /var/log/auth.log',
    ],
  },
  'Web Attack \u2013 Brute Force': {
    what: 'Automated guessing of web application login credentials — a bot is trying thousands of username/password combinations against your login page.',
    precautions: [
      'Enable CAPTCHA on login forms.',
      'Lock accounts after 3–5 failed login attempts.',
      'Block the attacking IP in your firewall.',
      'Check application logs for any successful logins.',
      'Enable two-factor authentication (2FA).',
    ],
  },
  'Web Attack \u2013 Sql Injection': {
    what: 'SQL injection — attempting to manipulate your database by injecting malicious code through web form inputs or URL parameters.',
    precautions: [
      'Use parameterized queries / prepared statements — never build SQL from user input.',
      'Enable a Web Application Firewall (WAF).',
      'Check your database for unauthorized changes.',
      'Block the source IP and review your application code immediately.',
    ],
  },
  'Web Attack \u2013 XSS': {
    what: 'Cross-Site Scripting — injecting malicious JavaScript into your web application to steal session tokens, redirect users, or deface pages.',
    precautions: [
      'Sanitize and escape all user input in your web application.',
      'Set Content-Security-Policy headers on your web server.',
      'Block the source IP.',
      'Review your application for XSS vulnerabilities.',
    ],
  },
  'Infiltration': {
    what: 'An active breach attempt — someone may already be inside the network trying to move laterally, escalate privileges, or exfiltrate data.',
    precautions: [
      'This is serious — isolate the affected machine from the network immediately.',
      'Run a full antivirus/malware scan.',
      'Check for unauthorized user accounts or scheduled tasks.',
      'Review system and network logs for unusual activity.',
      'Consider engaging a security professional.',
    ],
  },
  'Bot': {
    what: 'Bot or malware traffic — a machine on the network may be part of a botnet, making automated connections to command-and-control servers.',
    precautions: [
      'Run a full antivirus scan on the source machine.',
      'Check for unusual processes in Task Manager.',
      'Block outbound connections to the destination IP.',
      'Change all passwords — the machine may be compromised.',
      'Consider reinstalling the OS if infection is confirmed.',
    ],
  },
  'Heartbleed': {
    what: 'Exploitation of the Heartbleed OpenSSL vulnerability (CVE-2014-0160) — attempts to read server memory including private keys and user passwords.',
    precautions: [
      'Update OpenSSL immediately — this is a critical vulnerability.',
      'Revoke and reissue all SSL/TLS certificates on affected servers.',
      'Block the source IP.',
      'Rotate all passwords and API keys that may have been exposed.',
    ],
  },
  'Normal Traffic': {
    what: 'This connection was classified as normal, legitimate network traffic — no threat detected.',
    precautions: [],
  },
}

const GENERIC_PRECAUTIONS = [
  'Block the source IP in your firewall as a precaution.',
  'Monitor your system for unusual activity.',
  'Check system logs for related events.',
  'Keep your software and OS updated.',
]

export function getAttackInfo(prediction: string) {
  if (ATTACK_INFO[prediction]) return ATTACK_INFO[prediction]
  const key = Object.keys(ATTACK_INFO).find(
    (k) =>
      prediction.toLowerCase().includes(k.toLowerCase()) ||
      k.toLowerCase().includes(prediction.toLowerCase().split(' ')[0]),
  )
  if (key) return ATTACK_INFO[key]
  return {
    what: `The model detected suspicious traffic patterns matching the "${prediction}" attack category.`,
    precautions: GENERIC_PRECAUTIONS,
  }
}

// --------------------------------------------------------------------------- //
// Risk config
// --------------------------------------------------------------------------- //
export const RISK_CONFIG = {
  critical: { bg: 'bg-red-500/15', border: 'border-red-500/40', text: 'text-red-400', dot: 'bg-red-500', label: '🔴 CRITICAL THREAT' },
  high:     { bg: 'bg-orange-500/15', border: 'border-orange-500/40', text: 'text-orange-400', dot: 'bg-orange-500', label: '🟠 HIGH RISK' },
  medium:   { bg: 'bg-yellow-500/15', border: 'border-yellow-500/40', text: 'text-yellow-400', dot: 'bg-yellow-500', label: '🟡 MEDIUM RISK' },
  low:      { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', dot: 'bg-emerald-500', label: '🟢 SAFE' },
}

// --------------------------------------------------------------------------- //
// ThreatCard — full explanation card for a suspicious flow
// --------------------------------------------------------------------------- //
export function ThreatCard({
  flow,
  onRemove,
  onBlockIntrusion,
  blocked,
  blocking,
}: {
  flow: ScoredFlow
  onRemove?: (flow: ScoredFlow) => void
  onBlockIntrusion?: (flow: ScoredFlow) => void
  blocked?: boolean
  blocking?: boolean
}) {
  const cfg = RISK_CONFIG[flow.risk_level as keyof typeof RISK_CONFIG] ?? RISK_CONFIG.medium
  const info = getAttackInfo(flow.prediction)

  return (
    <div className={cn('rounded-xl border p-4 space-y-3', cfg.bg, cfg.border)}>
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert className={cn('h-5 w-5 shrink-0', cfg.text)} />
          <div>
            <div className={cn('text-sm font-bold', cfg.text)}>{cfg.label}</div>
            <div className="text-xs text-muted-foreground">
              {flow.prediction} · {formatPercent(flow.confidence, 1)} confidence
              {flow.ground_truth && flow.ground_truth !== flow.prediction && (
                <span className="ml-2 text-yellow-400">(dataset label: {flow.ground_truth})</span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="font-mono text-[10px]">flow #{flow.index}</Badge>
          {onBlockIntrusion && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={blocked || blocking}
              aria-label={blocked ? 'Intrusion blocked' : 'Block intrusion'}
              title="Mark this intrusion as blocked in AI-NIDS. If an IP is available, add it to the analysis blocklist; this does not interrupt network traffic."
              onClick={() => onBlockIntrusion(flow)}
              className="h-7 gap-1 px-2 text-[10px]"
            >
              <Ban className="h-3 w-3" />
              {blocking ? 'Blocking…' : blocked ? 'Blocked' : 'Block intrusion'}
            </Button>
          )}
          {onRemove && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              aria-label="Remove connection from list"
              title="Remove from list"
              onClick={() => onRemove(flow)}
              className="h-7 gap-1 px-2 text-[10px]"
            >
              <X className="h-3 w-3" />
              Remove connection
            </Button>
          )}
        </div>
      </div>

      {/* Connection info */}
      <div className="rounded-lg bg-background/40 px-3 py-2 font-mono text-[11px] text-muted-foreground space-y-0.5">
        {flow.source_ip && (
          <div><span className="text-foreground/60">From: </span>{flow.source_ip}{flow.source_port ? `:${flow.source_port}` : ''}</div>
        )}
        {flow.destination_ip && (
          <div><span className="text-foreground/60">To: </span>{flow.destination_ip}{flow.destination_port ? `:${flow.destination_port}` : ''}</div>
        )}
        {!flow.source_ip && flow.destination_port && (
          <div><span className="text-foreground/60">Destination port: </span>{flow.destination_port}</div>
        )}
        {flow.protocol && <div><span className="text-foreground/60">Protocol: </span>{flow.protocol}</div>}
        {flow.packet_rate != null && <div><span className="text-foreground/60">Packet rate: </span>{formatNumber(flow.packet_rate, 0)} pkt/s</div>}
        {flow.flow_duration != null && flow.flow_duration > 0 && (
          <div><span className="text-foreground/60">Duration: </span>{(flow.flow_duration / 1000).toFixed(1)} ms</div>
        )}
      </div>

      {/* What is this */}
      <div>
        <div className="text-[11px] font-semibold text-foreground/80 mb-1 flex items-center gap-1">
          <Info className="h-3.5 w-3.5" /> What is this?
        </div>
        <p className="text-[11px] leading-relaxed text-muted-foreground">{info.what}</p>
      </div>

      {/* Precautions */}
      {info.precautions.length > 0 && (
        <div>
          <div className="text-[11px] font-semibold text-foreground/80 mb-1.5 flex items-center gap-1">
            <ClipboardList className="h-3.5 w-3.5" /> What you should do
          </div>
          <ul className="space-y-1">
            {info.precautions.map((p, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] leading-relaxed text-muted-foreground">
                <span className={cn('mt-1 h-1.5 w-1.5 shrink-0 rounded-full', cfg.dot)} />
                {p}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

// --------------------------------------------------------------------------- //
// SafeFlowRow — compact row for normal traffic
// --------------------------------------------------------------------------- //
export function SafeFlowRow({
  flow,
  onRemove,
}: {
  flow: ScoredFlow
  onRemove?: (flow: ScoredFlow) => void
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-[11px]">
      <div className="flex items-center gap-2 min-w-0">
        <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
        <span className="text-emerald-400 font-medium shrink-0">Safe</span>
        <span className="font-mono text-muted-foreground truncate">
          {flow.source_ip
            ? `${flow.source_ip} → ${flow.destination_ip ?? '?'}${flow.destination_port ? `:${flow.destination_port}` : ''}`
            : flow.destination_port
            ? `→ port ${flow.destination_port}`
            : 'Normal Traffic'}
        </span>
      </div>
      <div className="flex items-center gap-2 text-muted-foreground shrink-0">
        <span className="font-mono">{formatPercent(flow.confidence, 0)}</span>
        {flow.protocol && <span>{flow.protocol}</span>}
        {onRemove && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            aria-label="Remove connection from list"
            title="Remove from list"
            onClick={() => onRemove(flow)}
            className="h-7 w-7"
          >
            <X className="h-3 w-3" />
          </Button>
        )}
      </div>
    </div>
  )
}

// --------------------------------------------------------------------------- //
// ThreatFeed — the full two-column layout (threats left, safe right)
// --------------------------------------------------------------------------- //
export function ThreatFeed({
  flows,
  streaming,
  total,
  suspicious,
  removedThreats = 0,
  blockedThreats = 0,
  onRemoveFlow,
  onBlockIntrusion,
  blockedThreatIndexes = [],
  blockingFlowIndex,
  emptyMessage = 'Click Start to begin monitoring.',
  waitingMessage = 'Waiting for first flow…',
}: {
  flows: ScoredFlow[]
  streaming: boolean
  total: number
  suspicious: number
  removedThreats?: number
  blockedThreats?: number
  onRemoveFlow?: (flow: ScoredFlow) => void
  onBlockIntrusion?: (flow: ScoredFlow) => void
  blockedThreatIndexes?: number[]
  blockingFlowIndex?: number | null
  emptyMessage?: string
  waitingMessage?: string
}) {
  const threats = flows.filter((f) => f.is_attack)
  const safeFlows = flows.filter((f) => !f.is_attack)

  return (
    <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
      {/* ── Left: Threats ──────────────────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <span className="relative flex h-2 w-2">
            {streaming && threats.length > 0 && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-60" />
            )}
            <span className={cn(
              'relative inline-flex h-2 w-2 rounded-full',
              streaming && threats.length > 0 ? 'bg-red-500'
              : streaming ? 'bg-primary'
              : 'bg-muted-foreground/30'
            )} />
          </span>
          Threat alerts
          {threats.length > 0 && (
            <Badge variant="destructive" className="ml-1">{threats.length}</Badge>
          )}
        </div>

        {flows.length === 0 && removedThreats === 0 && blockedThreats === 0 ? (
          <Card className="border-border/50">
            <CardContent className="py-12 text-center space-y-2">
              <ShieldAlert className="mx-auto h-10 w-10 text-muted-foreground/20" />
              <p className="text-sm text-muted-foreground">
                {streaming ? waitingMessage : emptyMessage}
              </p>
              {streaming && (
                <p className="text-[11px] text-muted-foreground/60">
                  Flows appear when connections complete (FIN/RST) or go idle.
                </p>
              )}
            </CardContent>
          </Card>
        ) : threats.length === 0 ? (
          <Card className={suspicious > 0 || removedThreats > 0 || blockedThreats > 0 ? 'border-orange-500/30 bg-orange-500/5' : 'border-emerald-500/30 bg-emerald-500/5'}>
            <CardContent className="py-8 text-center space-y-1">
              {suspicious > 0 || removedThreats > 0 || blockedThreats > 0
                ? <ShieldAlert className="mx-auto h-8 w-8 text-orange-400" />
                : <ShieldCheck className="mx-auto h-8 w-8 text-emerald-400" />}
              <p className={cn('text-sm font-semibold', suspicious > 0 || removedThreats > 0 || blockedThreats > 0 ? 'text-orange-400' : 'text-emerald-400')}>
                {suspicious > 0 || removedThreats > 0 || blockedThreats > 0 ? 'No threats in this list' : 'All traffic looks clean'}
              </p>
              <p className="text-xs text-muted-foreground">
                {suspicious > 0 || removedThreats > 0 || blockedThreats > 0
                  ? `${suspicious} threat${suspicious !== 1 ? 's' : ''} remain${suspicious === 1 ? 's' : ''} in ${total} analysed flows; ${blockedThreats} blocked and ${removedThreats} removed from this list.`
                  : `${total} flow${total !== 1 ? 's' : ''} analysed — no threats detected so far.`}
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-3 max-h-[620px] overflow-y-auto pr-1">
            {threats.slice(0, 25).map((flow, i) => (
              <ThreatCard
                key={`${flow.index}-${i}`}
                flow={flow}
                onRemove={onRemoveFlow}
                onBlockIntrusion={onBlockIntrusion}
                blocked={blockedThreatIndexes.includes(flow.index)}
                blocking={blockingFlowIndex === flow.index}
              />
            ))}
            {threats.length > 25 && (
              <p className="text-center text-xs text-muted-foreground py-2">
                +{threats.length - 25} more threats above
              </p>
            )}
          </div>
        )}
      </div>

      {/* ── Right: Safe flows ──────────────────────────────────────────── */}
      <div className="space-y-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2 mb-3 text-sm font-semibold">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              Safe connections
              {safeFlows.length > 0 && (
                <Badge variant="secondary" className="ml-1 text-emerald-400 border-emerald-500/30">
                  {safeFlows.length}
                </Badge>
              )}
            </div>
            {safeFlows.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted-foreground">
                {streaming ? 'Waiting…' : 'No flows yet.'}
              </p>
            ) : (
              <div className="max-h-[300px] overflow-y-auto space-y-1">
                {safeFlows.slice(0, 40).map((flow, i) => (
                  <SafeFlowRow key={`safe-${flow.index}-${i}`} flow={flow} onRemove={onRemoveFlow} />
                ))}
                {safeFlows.length > 40 && (
                  <p className="text-center text-[10px] text-muted-foreground pt-1">
                    +{safeFlows.length - 40} more
                  </p>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* General safety tips */}
        <Card className="border-border/40">
          <CardContent className="pt-4 space-y-2 text-[11px] leading-relaxed text-muted-foreground">
            <p className="text-xs font-semibold text-foreground/70 mb-2">General network safety</p>
            {[
              { icon: '🔒', tip: 'Keep your OS and software updated — most attacks exploit known vulnerabilities.' },
              { icon: '🛡️', tip: 'Enable your firewall and block all inbound connections you don\'t explicitly need.' },
              { icon: '🔑', tip: 'Use strong, unique passwords and enable 2FA on all important accounts.' },
              { icon: '📡', tip: 'On public Wi-Fi, use a VPN. Never send sensitive data over unencrypted connections.' },
              { icon: '🚫', tip: 'If you see port scanning from an external IP, block it and report it to your ISP.' },
            ].map(({ icon, tip }, i) => (
              <div key={i} className="flex items-start gap-2">
                <span className="text-sm shrink-0">{icon}</span>
                <span>{tip}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
