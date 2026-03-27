/**
 * PolicyDependencyGraph Component
 *
 * Interactive SVG showing which address/service objects are used by which policies.
 * Nodes represent policies and objects, edges represent references.
 * Click a node to highlight its connections.
 */
import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';

const NODE_TYPES = {
  policy: { color: 'var(--accent)', label: 'Policy', radius: 10 },
  address: { color: 'var(--info)', label: 'Address', radius: 7 },
  address_group: { color: '#818cf8', label: 'Addr Group', radius: 8 },
  service: { color: 'var(--success)', label: 'Service', radius: 7 },
  application: { color: 'var(--warning)', label: 'Application', radius: 7 },
};

/**
 * Build graph data from intermediate config.
 * @param {Object} intermediateConfig
 * @returns {{ nodes: Array, edges: Array }}
 */
function buildGraph(intermediateConfig) {
  if (!intermediateConfig) return { nodes: [], edges: [] };

  const nodes = [];
  const edges = [];
  const nodeMap = new Map();

  const addNode = (id, type, name) => {
    if (nodeMap.has(id)) return;
    nodeMap.set(id, { id, type, name });
    nodes.push({ id, type, name });
  };

  // Add policies as nodes
  const policies = intermediateConfig.security_policies || [];
  for (const policy of policies) {
    const policyId = `policy:${policy.name}`;
    addNode(policyId, 'policy', policy.name);

    // Connect to source addresses
    for (const addr of (policy.src_addresses || [])) {
      if (addr === 'any') continue;
      const addrId = `address:${addr}`;
      addNode(addrId, 'address', addr);
      edges.push({ from: policyId, to: addrId, label: 'src' });
    }

    // Connect to destination addresses
    for (const addr of (policy.dst_addresses || [])) {
      if (addr === 'any') continue;
      const addrId = `address:${addr}`;
      addNode(addrId, 'address', addr);
      edges.push({ from: policyId, to: addrId, label: 'dst' });
    }

    // Connect to services
    for (const svc of (policy.services || [])) {
      if (svc === 'application-default' || svc === 'any') continue;
      const svcId = `service:${svc}`;
      addNode(svcId, 'service', svc);
      edges.push({ from: policyId, to: svcId, label: 'svc' });
    }

    // Connect to applications
    for (const app of (policy.applications || [])) {
      if (app === 'any') continue;
      const appId = `application:${app}`;
      addNode(appId, 'application', app);
      edges.push({ from: policyId, to: appId, label: 'app' });
    }
  }

  // Add address groups and their membership edges
  for (const group of (intermediateConfig.address_groups || [])) {
    const groupId = `address_group:${group.name}`;
    addNode(groupId, 'address_group', group.name);
    for (const member of (group.members || [])) {
      const memberId = `address:${member}`;
      addNode(memberId, 'address', member);
      edges.push({ from: groupId, to: memberId, label: 'member' });
    }
  }

  return { nodes, edges };
}

/**
 * Simple force-directed layout.
 * Runs a fixed number of iterations to position nodes.
 */
function layoutGraph(nodes, edges, width, height) {
  if (nodes.length === 0) return [];

  // Initialize positions in a circle
  const positions = nodes.map((node, i) => {
    const angle = (2 * Math.PI * i) / nodes.length;
    const radius = Math.min(width, height) * 0.35;
    return {
      id: node.id,
      x: width / 2 + radius * Math.cos(angle),
      y: height / 2 + radius * Math.sin(angle),
      vx: 0,
      vy: 0,
    };
  });

  const posMap = new Map(positions.map(p => [p.id, p]));

  // Run simulation
  const iterations = 80;
  const repulsion = 3000;
  const attraction = 0.005;
  const damping = 0.85;
  const centerForce = 0.01;

  for (let iter = 0; iter < iterations; iter++) {
    // Repulsion between all nodes
    for (let i = 0; i < positions.length; i++) {
      for (let j = i + 1; j < positions.length; j++) {
        const dx = positions[i].x - positions[j].x;
        const dy = positions[i].y - positions[j].y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = repulsion / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        positions[i].vx += fx;
        positions[i].vy += fy;
        positions[j].vx -= fx;
        positions[j].vy -= fy;
      }
    }

    // Attraction along edges
    for (const edge of edges) {
      const a = posMap.get(edge.from);
      const b = posMap.get(edge.to);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const force = dist * attraction;
      a.vx += dx * force;
      a.vy += dy * force;
      b.vx -= dx * force;
      b.vy -= dy * force;
    }

    // Center gravity
    for (const pos of positions) {
      pos.vx += (width / 2 - pos.x) * centerForce;
      pos.vy += (height / 2 - pos.y) * centerForce;
    }

    // Apply velocities
    for (const pos of positions) {
      pos.vx *= damping;
      pos.vy *= damping;
      pos.x += pos.vx;
      pos.y += pos.vy;
      // Clamp to bounds
      pos.x = Math.max(30, Math.min(width - 30, pos.x));
      pos.y = Math.max(30, Math.min(height - 30, pos.y));
    }
  }

  return positions;
}

export default function PolicyDependencyGraph({ intermediateConfig }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });
  const containerRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(entries => {
      const entry = entries[0];
      if (entry) {
        setDimensions({
          width: Math.max(400, entry.contentRect.width),
          height: Math.max(300, entry.contentRect.height),
        });
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const { nodes, edges } = useMemo(() => buildGraph(intermediateConfig), [intermediateConfig]);

  const positions = useMemo(
    () => layoutGraph(nodes, edges, dimensions.width, dimensions.height),
    [nodes, edges, dimensions.width, dimensions.height]
  );

  const posMap = useMemo(() => new Map(positions.map(p => [p.id, p])), [positions]);

  // Compute highlighted edges/nodes when a node is selected
  const { highlightedNodes, highlightedEdges } = useMemo(() => {
    if (!selectedNode) return { highlightedNodes: new Set(), highlightedEdges: new Set() };
    const hNodes = new Set([selectedNode]);
    const hEdges = new Set();
    edges.forEach((edge, i) => {
      if (edge.from === selectedNode || edge.to === selectedNode) {
        hEdges.add(i);
        hNodes.add(edge.from);
        hNodes.add(edge.to);
      }
    });
    return { highlightedNodes: hNodes, highlightedEdges: hEdges };
  }, [selectedNode, edges]);

  const handleNodeClick = useCallback((nodeId) => {
    setSelectedNode(prev => prev === nodeId ? null : nodeId);
  }, []);

  if (!intermediateConfig || nodes.length === 0) {
    return (
      <div className="panel-body">
        <div className="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
            <circle cx="12" cy="5" r="3" />
            <circle cx="5" cy="19" r="3" />
            <circle cx="19" cy="19" r="3" />
            <line x1="12" y1="8" x2="5" y2="16" />
            <line x1="12" y1="8" x2="19" y2="16" />
          </svg>
          <h3>No policies to graph</h3>
          <p>Parse a configuration with security policies to see the dependency graph.</p>
        </div>
      </div>
    );
  }

  // Limit display for performance
  const maxNodes = 200;
  const isLimited = nodes.length > maxNodes;

  return (
    <div ref={containerRef} style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
      {/* Legend */}
      <div style={{ display: 'flex', gap: 12, padding: '8px 12px', borderBottom: '1px solid var(--border-color)', flexShrink: 0, fontSize: 11 }}>
        {Object.entries(NODE_TYPES).map(([type, cfg]) => (
          <span key={type} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: cfg.color, display: 'inline-block' }} />
            {cfg.label}
          </span>
        ))}
        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>
          {nodes.length} nodes, {edges.length} edges
          {selectedNode && (
            <> | Selected: <strong style={{ color: 'var(--accent)' }}>{selectedNode.split(':')[1]}</strong>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 11, marginLeft: 4 }}
              >[clear]</button>
            </>
          )}
        </span>
      </div>

      {isLimited && (
        <div style={{ padding: '4px 12px', background: 'rgba(167, 139, 250, 0.1)', fontSize: 11, color: 'var(--caution)' }}>
          Graph limited to first {maxNodes} nodes for performance. Full config has {nodes.length} objects.
        </div>
      )}

      {/* SVG Graph */}
      <svg
        width={dimensions.width}
        height={dimensions.height - 40}
        style={{ flex: 1, minHeight: 0 }}
      >
        {/* Edges */}
        {edges.map((edge, i) => {
          const from = posMap.get(edge.from);
          const to = posMap.get(edge.to);
          if (!from || !to) return null;
          const isHighlighted = selectedNode ? highlightedEdges.has(i) : true;
          return (
            <line
              key={i}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              stroke={isHighlighted ? 'var(--border-color)' : 'rgba(58, 63, 72, 0.2)'}
              strokeWidth={isHighlighted ? 1.5 : 0.5}
              strokeOpacity={isHighlighted ? 0.8 : 0.15}
            />
          );
        })}

        {/* Nodes */}
        {nodes.slice(0, maxNodes).map(node => {
          const pos = posMap.get(node.id);
          if (!pos) return null;
          const cfg = NODE_TYPES[node.type] || NODE_TYPES.address;
          const isHighlighted = selectedNode ? highlightedNodes.has(node.id) : true;
          const isSelected = node.id === selectedNode;

          return (
            <g
              key={node.id}
              onClick={() => handleNodeClick(node.id)}
              style={{ cursor: 'pointer' }}
            >
              <circle
                cx={pos.x}
                cy={pos.y}
                r={isSelected ? cfg.radius + 3 : cfg.radius}
                fill={cfg.color}
                opacity={isHighlighted ? 1 : 0.15}
                stroke={isSelected ? '#fff' : 'none'}
                strokeWidth={isSelected ? 2 : 0}
              />
              {(isSelected || (isHighlighted && node.type === 'policy')) && (
                <text
                  x={pos.x}
                  y={pos.y - cfg.radius - 4}
                  textAnchor="middle"
                  fill="var(--text-primary)"
                  fontSize={10}
                  fontFamily="var(--font-sans)"
                >
                  {node.name.length > 20 ? node.name.slice(0, 18) + '...' : node.name}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
