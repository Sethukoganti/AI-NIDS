/**
 * Animated network/flow artwork for the landing page.
 * Pure inline SVG - no external assets, so it renders in sandboxed previews.
 */
export function NetworkBackground({ className = '' }: { className?: string }) {
  const nodes = [
    { x: 90, y: 120 },
    { x: 250, y: 60 },
    { x: 400, y: 150 },
    { x: 560, y: 80 },
    { x: 700, y: 170 },
    { x: 170, y: 260 },
    { x: 340, y: 300 },
    { x: 520, y: 250 },
    { x: 660, y: 320 },
    { x: 80, y: 340 },
    { x: 440, y: 60 },
    { x: 610, y: 380 },
  ]
  const edges: [number, number][] = [
    [0, 1], [1, 2], [2, 3], [3, 4], [0, 5], [5, 6], [6, 7], [7, 8], [5, 9], [1, 10],
    [10, 3], [6, 2], [7, 2], [8, 11], [6, 11], [9, 6], [4, 8], [10, 7],
  ]
  return (
    <svg
      viewBox="0 0 780 430"
      className={className}
      role="img"
      aria-label="Network traffic flowing through the AI-NIDS detection engine"
    >
      <defs>
        <linearGradient id="edgeGrad" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.15" />
          <stop offset="50%" stopColor="#22d3ee" stopOpacity="0.75" />
          <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.15" />
        </linearGradient>
        <radialGradient id="coreGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.45" />
          <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
        </radialGradient>
      </defs>

      {edges.map(([a, b], i) => (
        <line
          key={i}
          x1={nodes[a].x}
          y1={nodes[a].y}
          x2={nodes[b].x}
          y2={nodes[b].y}
          stroke="url(#edgeGrad)"
          strokeWidth="1.2"
          strokeDasharray="6 10"
          className="animate-dash-flow"
          style={{ animationDelay: `${i * 0.35}s` }}
        />
      ))}

      {nodes.map((node, i) => (
        <g key={i}>
          <circle cx={node.x} cy={node.y} r="14" fill="url(#coreGlow)" />
          <circle
            cx={node.x}
            cy={node.y}
            r="4.2"
            fill={i % 4 === 0 ? '#f97316' : '#22d3ee'}
            opacity={0.9}
          >
            <animate
              attributeName="r"
              values="3.2;5.4;3.2"
              dur={`${3 + (i % 5) * 0.6}s`}
              repeatCount="indefinite"
            />
          </circle>
        </g>
      ))}

      {/* detection engine core */}
      <g transform="translate(390, 215)">
        <circle r="58" fill="url(#coreGlow)" />
        <circle r="34" fill="#0b1220" stroke="#22d3ee" strokeOpacity="0.55" strokeWidth="1.4" />
        <circle r="34" fill="none" stroke="#22d3ee" strokeOpacity="0.35" strokeWidth="1">
          <animate attributeName="r" values="34;48;34" dur="4s" repeatCount="indefinite" />
          <animate attributeName="stroke-opacity" values="0.35;0;0.35" dur="4s" repeatCount="indefinite" />
        </circle>
        <path
          d="M0 -17 L14 -11 V1 C14 11 7 17 0 20 C-7 17 -14 11 -14 1 V-11 Z"
          fill="#22d3ee"
          fillOpacity="0.14"
          stroke="#22d3ee"
          strokeWidth="1.2"
        />
        <path d="M-6 1 L-1 6 L7 -6" fill="none" stroke="#22d3ee" strokeWidth="1.8" strokeLinecap="round" />
        <text y="46" textAnchor="middle" fill="#94a3b8" fontSize="10" fontFamily="monospace">
          RandomForest · 100 trees
        </text>
      </g>
    </svg>
  )
}
