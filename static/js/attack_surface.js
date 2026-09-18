/**
 * ThreatScope V2 - Interactive Attack Surface Graph Canvas
 * Self-contained, physics-based force-directed asset graph visualization.
 * Zero external CDN or script dependencies.
 */

class AttackSurfaceGraph {
  constructor(canvasId, graphData) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.rawNodes = (graphData && graphData.nodes) || [];
    this.rawEdges = (graphData && graphData.edges) || [];

    // Colors mapping
    this.typeColors = {
      target: '#8b5cf6',
      domain: '#3b82f6',
      subdomain: '#60a5fa',
      ip: '#06b6d4',
      port: '#f97316',
      service: '#facc15',
      technology: '#10b981',
      endpoint: '#94a3b8',
      certificate: '#6366f1',
      dns_record: '#ec4899'
    };

    // Active filters
    this.activeFilters = new Set(Object.keys(this.typeColors));

    // Transform state
    this.scale = 1;
    this.panX = 0;
    this.panY = 0;
    this.isDragging = false;
    this.dragStartX = 0;
    this.dragStartY = 0;

    // Node state
    this.nodes = [];
    this.edges = [];
    this.selectedNode = null;
    this.hoveredNode = null;

    this.init();
  }

  init() {
    this.resizeCanvas();
    window.addEventListener('resize', () => this.resizeCanvas());

    this.setupNodesAndEdges();
    this.bindEvents();
    this.centerGraph();
    this.animate();
  }

  resizeCanvas() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width;
    this.canvas.height = rect.height;
  }

  setupNodesAndEdges() {
    const w = this.canvas.width;
    const h = this.canvas.height;
    const count = this.rawNodes.length;

    // Arrange initially in radial layout around center
    this.nodes = this.rawNodes.map((n, i) => {
      const angle = (i / Math.max(1, count)) * Math.PI * 2;
      const radius = n.type === 'target' ? 0 : (n.type === 'ip' || n.type === 'subdomain' ? 140 : 250);
      return {
        ...n,
        x: w / 2 + Math.cos(angle) * radius + (Math.random() - 0.5) * 40,
        y: h / 2 + Math.sin(angle) * radius + (Math.random() - 0.5) * 40,
        vx: 0,
        vy: 0,
        radius: n.type === 'target' ? 24 : (n.type === 'ip' || n.type === 'subdomain' ? 18 : 14)
      };
    });

    const nodeMap = new Map(this.nodes.map(n => [n.id, n]));
    this.edges = this.rawEdges
      .map(e => ({
        ...e,
        source: nodeMap.get(e.from),
        target: nodeMap.get(e.to)
      }))
      .filter(e => e.source && e.target);
  }

  bindEvents() {
    // Mouse events for pan & select
    this.canvas.addEventListener('mousedown', (e) => {
      const pos = this.getCanvasCoords(e);
      const clickedNode = this.findNodeAt(pos.x, pos.y);

      if (clickedNode) {
        this.selectNode(clickedNode);
      } else {
        this.isDragging = true;
        this.dragStartX = e.clientX - this.panX;
        this.dragStartY = e.clientY - this.panY;
      }
    });

    window.addEventListener('mousemove', (e) => {
      if (this.isDragging) {
        this.panX = e.clientX - this.dragStartX;
        this.panY = e.clientY - this.dragStartY;
      } else {
        const rect = this.canvas.getBoundingClientRect();
        if (e.clientX >= rect.left && e.clientX <= rect.right && e.clientY >= rect.top && e.clientY <= rect.bottom) {
          const pos = this.getCanvasCoords(e);
          this.hoveredNode = this.findNodeAt(pos.x, pos.y);
          this.canvas.style.cursor = this.hoveredNode ? 'pointer' : 'grab';
        }
      }
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    // Wheel zoom
    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      this.zoom(zoomFactor, e.clientX, e.clientY);
    }, { passive: false });

    // Controls buttons
    const btnZoomIn = document.getElementById('btnZoomIn');
    const btnZoomOut = document.getElementById('btnZoomOut');
    const btnReset = document.getElementById('btnReset');

    if (btnZoomIn) btnZoomIn.addEventListener('click', () => this.zoom(1.2));
    if (btnZoomOut) btnZoomOut.addEventListener('click', () => this.zoom(0.8));
    if (btnReset) btnReset.addEventListener('click', () => this.centerGraph());

    // Filter Chips
    document.querySelectorAll('.filter-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const type = chip.getAttribute('data-type');
        if (this.activeFilters.has(type)) {
          this.activeFilters.delete(type);
          chip.classList.remove('active');
        } else {
          this.activeFilters.add(type);
          chip.classList.add('active');
        }
      });
    });

    // Search Box
    const searchInput = document.getElementById('surfaceSearch');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase().trim();
        if (!q) {
          this.selectedNode = null;
          return;
        }
        const match = this.nodes.find(n => n.label.toLowerCase().includes(q) || n.value.toLowerCase().includes(q));
        if (match) {
          this.selectNode(match);
          this.focusOnNode(match);
        }
      });
    }
  }

  getCanvasCoords(e) {
    const rect = this.canvas.getBoundingClientRect();
    const clientX = e.clientX - rect.left;
    const clientY = e.clientY - rect.top;
    return {
      x: (clientX - this.panX) / this.scale,
      y: (clientY - this.panY) / this.scale
    };
  }

  findNodeAt(x, y) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      if (!this.activeFilters.has(n.type)) continue;
      const dx = n.x - x;
      const dy = n.y - y;
      if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 4) {
        return n;
      }
    }
    return null;
  }

  zoom(factor, clientX, clientY) {
    const oldScale = this.scale;
    this.scale = Math.min(Math.max(0.2, this.scale * factor), 3.0);
    
    // Zoom toward center if no client coordinates provided
    const cx = clientX !== undefined ? clientX - this.canvas.getBoundingClientRect().left : this.canvas.width / 2;
    const cy = clientY !== undefined ? clientY - this.canvas.getBoundingClientRect().top : this.canvas.height / 2;

    this.panX = cx - (cx - this.panX) * (this.scale / oldScale);
    this.panY = cy - (cy - this.panY) * (this.scale / oldScale);
  }

  centerGraph() {
    this.scale = 1;
    this.panX = 0;
    this.panY = 0;
  }

  focusOnNode(node) {
    this.panX = this.canvas.width / 2 - node.x * this.scale;
    this.panY = this.canvas.height / 2 - node.y * this.scale;
  }

  selectNode(node) {
    this.selectedNode = node;
    this.renderInspector(node);
  }

  renderInspector(node) {
    const inspector = document.getElementById('nodeInspector');
    if (!inspector) return;

    document.getElementById('inspTitle').textContent = node.label;
    document.getElementById('inspType').textContent = node.type.toUpperCase();
    document.getElementById('inspValue').textContent = node.value;
    document.getElementById('inspSource').textContent = node.source || 'Reconnaissance Engine';
    document.getElementById('inspEvidence').textContent = node.evidence || 'N/A';

    // Find related nodes
    const related = this.edges
      .filter(e => e.source.id === node.id || e.target.id === node.id)
      .map(e => {
        const other = e.source.id === node.id ? e.target : e.source;
        return `${e.label}: ${other.label} (${other.type})`;
      });

    const relList = document.getElementById('inspRelated');
    if (relList) {
      relList.innerHTML = related.length ? related.map(r => `<li>${r}</li>`).join('') : '<li>No direct relations</li>';
    }

    inspector.classList.add('open');
  }

  animate() {
    this.updatePhysics();
    this.draw();
    requestAnimationFrame(() => this.animate());
  }

  updatePhysics() {
    // Light relaxation simulation
    const kRepel = 800;
    const kAttract = 0.03;

    // Node repulsion
    for (let i = 0; i < this.nodes.length; i++) {
      for (let j = i + 1; j < this.nodes.length; j++) {
        const a = this.nodes[i];
        const b = this.nodes[j];
        if (!this.activeFilters.has(a.type) || !this.activeFilters.has(b.type)) continue;

        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < 280) {
          let force = (kRepel / (dist * dist));
          let fx = (dx / dist) * force;
          let fy = (dy / dist) * force;
          a.vx -= fx;
          a.vy -= fy;
          b.vx += fx;
          b.vy += fy;
        }
      }
    }

    // Edge attraction
    for (const e of this.edges) {
      if (!this.activeFilters.has(e.source.type) || !this.activeFilters.has(e.target.type)) continue;
      let dx = e.target.x - e.source.x;
      let dy = e.target.y - e.source.y;
      let dist = Math.sqrt(dx * dx + dy * dy) || 1;
      let desiredDist = 120;
      let force = (dist - desiredDist) * kAttract;
      let fx = (dx / dist) * force;
      let fy = (dy / dist) * force;
      e.source.vx += fx;
      e.source.vy += fy;
      e.target.vx -= fx;
      e.target.vy -= fy;
    }

    // Apply velocities with heavy damping
    for (const n of this.nodes) {
      if (n.type === 'target') {
        n.vx = 0;
        n.vy = 0;
        continue;
      }
      n.x += n.vx;
      n.y += n.vy;
      n.vx *= 0.85;
      n.vy *= 0.85;
    }
  }

  draw() {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    ctx.save();
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.scale, this.scale);

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const edgeColor = isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.1)';
    const textPrimary = isDark ? '#f8fafc' : '#0f172a';

    // 1. Draw Edges
    for (const e of this.edges) {
      if (!this.activeFilters.has(e.source.type) || !this.activeFilters.has(e.target.type)) continue;
      const isHighlighted = this.selectedNode && (e.source.id === this.selectedNode.id || e.target.id === this.selectedNode.id);

      ctx.beginPath();
      ctx.moveTo(e.source.x, e.source.y);
      ctx.lineTo(e.target.x, e.target.y);
      ctx.strokeStyle = isHighlighted ? 'var(--accent-primary)' : edgeColor;
      ctx.lineWidth = isHighlighted ? 2.5 : 1.2;
      ctx.stroke();

      // Draw edge label if highlighted
      if (isHighlighted) {
        const midX = (e.source.x + e.target.x) / 2;
        const midY = (e.source.y + e.target.y) / 2;
        ctx.fillStyle = textPrimary;
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(e.label, midX, midY - 4);
      }
    }

    // 2. Draw Nodes
    for (const n of this.nodes) {
      if (!this.activeFilters.has(n.type)) continue;

      const isSelected = this.selectedNode && this.selectedNode.id === n.id;
      const isHovered = this.hoveredNode && this.hoveredNode.id === n.id;
      const color = this.typeColors[n.type] || '#8b5cf6';

      // Outer glow/ring for selection
      if (isSelected || isHovered) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius + 6, 0, Math.PI * 2);
        ctx.fillStyle = isSelected ? 'rgba(139, 92, 246, 0.25)' : 'rgba(255, 255, 255, 0.15)';
        ctx.fill();
      }

      // Node Body
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = isDark ? '#1e293b' : '#ffffff';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Node Label
      ctx.fillStyle = textPrimary;
      ctx.font = `${n.type === 'target' ? 'bold 12px' : '11px'} sans-serif`;
      ctx.textAlign = 'center';
      const displayLabel = n.label.length > 22 ? n.label.substring(0, 20) + '...' : n.label;
      ctx.fillText(displayLabel, n.x, n.y + n.radius + 14);
    }

    ctx.restore();
  }
}
