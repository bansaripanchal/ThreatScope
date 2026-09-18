/**
 * ThreatScope - Investigation Workspace JS
 * Handles vertical navigation, section switching, real-time status polling,
 * findings filtering, attack surface graph integration, and technical detail drawers.
 */

class WorkspaceManager {
  constructor(investigationId, initialStatus) {
    this.investigationId = investigationId;
    this.status = initialStatus;
    this.pollInterval = null;
    this.currentSection = 'overview';
    this.init();
  }

  init() {
    this.bindSectionNav();
    this.bindDrawerTriggers();
    this.bindFindingsFilters();
    this.bindDomainToggles();
    
    // Check URL hash for direct section navigation
    const initialHash = window.location.hash.replace('#', '').toLowerCase();
    const validSections = ['overview', 'findings', 'network', 'domain', 'web', 'services', 'attack-surface', 'timeline'];
    if (initialHash && validSections.includes(initialHash)) {
      this.switchSection(initialHash);
    } else {
      this.switchSection('overview');
    }

    // Handle browser back/forward navigation
    window.addEventListener('hashchange', () => {
      const hash = window.location.hash.replace('#', '').toLowerCase();
      if (hash && validSections.includes(hash)) {
        this.switchSection(hash, false);
      }
    });

    if (this.status === 'RUNNING' || this.status === 'PENDING') {
      this.startPolling();
    }
  }

  bindSectionNav() {
    document.querySelectorAll('.inv-nav-btn[data-section]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const sectionId = btn.getAttribute('data-section');
        this.switchSection(sectionId);
      });
    });
  }

  switchSection(sectionId, updateHash = true) {
    const validSections = ['overview', 'findings', 'network', 'domain', 'web', 'services', 'attack-surface', 'timeline'];
    if (!validSections.includes(sectionId)) sectionId = 'overview';
    this.currentSection = sectionId;

    // 1. Update left navigation buttons
    document.querySelectorAll('.inv-nav-btn[data-section]').forEach(btn => {
      if (btn.getAttribute('data-section') === sectionId) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    // 2. Switch visible right-side content panel
    document.querySelectorAll('.workspace-section').forEach(sec => {
      sec.classList.remove('active');
    });

    const targetSec = document.getElementById(`section-${sectionId}`);
    if (targetSec) {
      targetSec.classList.add('active');
    }

    // 3. Update URL hash without jumping/reloading
    if (updateHash && window.location.hash.replace('#', '') !== sectionId) {
      history.replaceState(null, '', '#' + sectionId);
    }

    // 4. Special handling for Attack Surface Canvas
    if (sectionId === 'attack-surface') {
      this.initOrResizeAttackSurface();
    }

    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  initOrResizeAttackSurface() {
    setTimeout(() => {
      const canvas = document.getElementById('surfaceCanvas');
      if (!canvas) return;

      if (!window.workspaceGraph && window.WORKSPACE_GRAPH_DATA && typeof AttackSurfaceGraph !== 'undefined') {
        window.workspaceGraph = new AttackSurfaceGraph('surfaceCanvas', window.WORKSPACE_GRAPH_DATA);
      } else if (window.workspaceGraph) {
        window.workspaceGraph.resizeCanvas();
        window.workspaceGraph.centerGraph();
      }
    }, 50);
  }

  bindDrawerTriggers() {
    document.querySelectorAll('[data-drawer-trigger]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const title = btn.getAttribute('data-title');
        const meaning = btn.getAttribute('data-meaning');
        const found = btn.getAttribute('data-found');
        const technical = btn.getAttribute('data-technical');
        const evidence = btn.getAttribute('data-evidence');
        const source = btn.getAttribute('data-source');
        const time = btn.getAttribute('data-time');
        const limitations = btn.getAttribute('data-limitations');
        const severity = btn.getAttribute('data-severity-val') || btn.getAttribute('data-severity');
        const asset = btn.getAttribute('data-asset');
        const recommendation = btn.getAttribute('data-recommendation');

        openDrawer(title, meaning, found, technical, evidence, source, time, limitations, severity, asset, recommendation);
      });
    });
  }

  bindFindingsFilters() {
    const chips = document.querySelectorAll('.filter-chip[data-severity]');
    const rows = document.querySelectorAll('.finding-row');

    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        chips.forEach(c => c.classList.remove('active'));
        chip.classList.add('active');

        const severity = chip.getAttribute('data-severity');
        rows.forEach(row => {
          if (severity === 'ALL' || row.getAttribute('data-severity') === severity) {
            row.style.display = '';
          } else {
            row.style.display = 'none';
          }
        });
      });
    });
  }

  bindDomainToggles() {
    document.querySelectorAll('.recon-domain-header').forEach(header => {
      header.addEventListener('click', () => {
        const card = header.closest('.recon-domain-card');
        if (!card) return;
        const details = card.querySelector('.recon-details-container');
        const toggleIcon = card.querySelector('.domain-toggle-icon');
        const toggleText = card.querySelector('.domain-toggle-text');

        if (details) {
          const isOpen = details.classList.toggle('open');
          if (toggleIcon) {
            toggleIcon.style.transform = isOpen ? 'rotate(180deg)' : 'rotate(0deg)';
          }
          if (toggleText) {
            toggleText.textContent = isOpen ? 'Hide Details' : 'View Details';
          }
        }
      });
    });
  }

  startPolling() {
    const statusPill = document.getElementById('invStatusPill');
    const timelineContainer = document.getElementById('liveTimelineEvents');
    const runningCard = document.getElementById('runningIndicatorCard');
    const operationName = document.getElementById('liveOperationName');
    const topPrimaryIp = document.getElementById('topPrimaryIp');

    this.pollInterval = setInterval(async () => {
      try {
        const resp = await fetch(`/api/investigate/${this.investigationId}/status`);
        if (!resp.ok) return;

        const data = await resp.json();
        if (!data.success) return;

        this.status = data.status;

        // Update status badge
        if (statusPill) {
          if (data.status === 'RUNNING') {
            statusPill.innerHTML = '<span class="pulse-dot"></span> RUNNING';
            statusPill.className = 'badge badge-running';
          } else if (data.status === 'COMPLETED') {
            statusPill.textContent = 'COMPLETED';
            statusPill.className = 'badge badge-success';
          } else if (data.status === 'PARTIAL') {
            statusPill.textContent = 'PARTIALLY COMPLETED';
            statusPill.className = 'badge badge-warning';
          } else if (data.status === 'FAILED') {
            statusPill.textContent = 'FAILED';
            statusPill.className = 'badge badge-danger';
          } else {
            statusPill.textContent = data.status;
            statusPill.className = `badge badge-${data.status.toLowerCase()}`;
          }
        }

        // Update live operation name in running banner
        if (operationName && data.timeline_events && data.timeline_events.length > 0) {
          const lastEvent = data.timeline_events[data.timeline_events.length - 1];
          if (data.status === 'RUNNING') {
            operationName.innerHTML = `Active Step: <strong>${this.escapeHtml(lastEvent.operation)}</strong> &mdash; ${this.escapeHtml(lastEvent.message || '')}`;
          }
        }

        // Update live timeline container
        if (timelineContainer && data.timeline_events) {
          this.renderTimeline(timelineContainer, data.timeline_events);
        }

        // When scan completes
        if (data.is_complete) {
          clearInterval(this.pollInterval);
          if (runningCard) {
            runningCard.style.display = 'none';
          }
          setTimeout(() => {
            window.location.reload();
          }, 1000);
        }
      } catch (err) {
        console.error('Status poll error:', err);
      }
    }, 1500);
  }

  renderTimeline(container, events) {
    container.innerHTML = events.map(ev => `
      <div style="display: flex; align-items: flex-start; justify-content: space-between; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-color); font-size: 0.84375rem;">
        <div>
          <div style="font-weight: 600; color: var(--text-primary);">${this.escapeHtml(ev.operation)}</div>
          <div style="font-size: 0.78125rem; color: var(--text-muted); margin-top: 0.2rem;">${this.escapeHtml(ev.message || '')}</div>
        </div>
        <div style="text-align: right; white-space: nowrap; margin-left: 1rem;">
          <span class="badge badge-${ev.status.toLowerCase()}">${this.escapeHtml(ev.status)}</span>
          <div style="font-size: 0.78125rem; color: var(--text-muted); margin-top: 0.2rem;">${ev.duration_ms ? ev.duration_ms + 'ms' : ''}</div>
        </div>
      </div>
    `).join('');
  }

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}

// Global section switch helper for in-page triggers
function switchSection(sectionId) {
  if (window.workspaceManagerInstance) {
    window.workspaceManagerInstance.switchSection(sectionId);
  }
}

