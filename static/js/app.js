/**
 * ThreatScope V2 - Global Application JS
 * Handles theme persistence, drawer management, and modal interactions.
 */

// Theme Management
(function initTheme() {
  const savedTheme = localStorage.getItem('threatscope-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
})();

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('threatscope-theme', newTheme);
  updateThemeIcon();
}

function updateThemeIcon() {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
  const btn = document.getElementById('themeToggleBtn');
  if (btn) {
    btn.innerHTML = currentTheme === 'dark' 
      ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
      : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
    btn.setAttribute('title', `Switch to ${currentTheme === 'dark' ? 'Light' : 'Dark'} Mode`);
  }
}

// Drawer Management
function openDrawer(title, meaning, findings, technical, evidence, source, time, limitations, severity, asset, recommendation) {
  const overlay = document.getElementById('globalDrawerOverlay');
  const drawer = document.getElementById('globalDrawer');
  
  if (!drawer || !overlay) return;

  document.getElementById('drawerTitle').textContent = title || 'Technical Details';
  
  // Severity badge
  const sevEl = document.getElementById('drawerSeverityBadge');
  if (sevEl) {
    if (severity) {
      sevEl.textContent = severity.toUpperCase();
      sevEl.className = 'badge badge-' + severity.toLowerCase();
      sevEl.style.display = 'inline-flex';
    } else {
      sevEl.style.display = 'none';
    }
  }

  // Asset pill
  const assetEl = document.getElementById('drawerAssetPill');
  if (assetEl) {
    if (asset) {
      assetEl.textContent = asset;
      assetEl.style.display = 'inline-block';
    } else {
      assetEl.style.display = 'none';
    }
  }

  document.getElementById('drawerFound').textContent = findings || meaning || 'No explicit observation recorded.';
  
  // Recommendation
  const recEl = document.getElementById('drawerRecommendation');
  const recSec = document.getElementById('drawerRecSection');
  if (recEl && recSec) {
    const recText = recommendation || technical || '';
    if (recText && recText !== 'N/A') {
      recEl.textContent = recText;
      recSec.style.display = 'block';
    } else {
      recSec.style.display = 'none';
    }
  }

  document.getElementById('drawerTechnical').textContent = technical || 'N/A';
  document.getElementById('drawerEvidence').textContent = evidence || 'N/A';
  document.getElementById('drawerSource').textContent = source || 'Unknown';
  document.getElementById('drawerTime').textContent = time || new Date().toISOString();
  document.getElementById('drawerLimitations').textContent = limitations || 'Standard non-destructive reconnaissance boundaries applied.';

  overlay.classList.add('open');
  drawer.classList.add('open');
}

function closeDrawer() {
  const overlay = document.getElementById('globalDrawerOverlay');
  const drawer = document.getElementById('globalDrawer');
  if (drawer) drawer.classList.remove('open');
  if (overlay) overlay.classList.remove('open');
}

// Tab Switching
function initTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabTarget = btn.getAttribute('data-tab');
      const parentContainer = btn.closest('.tabs-container') || document;
      
      parentContainer.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      parentContainer.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      
      btn.classList.add('active');
      const targetPane = document.getElementById(tabTarget);
      if (targetPane) targetPane.classList.add('active');
    });
  });
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  updateThemeIcon();
  initTabs();

  // Close drawer on overlay click
  const overlay = document.getElementById('globalDrawerOverlay');
  if (overlay) {
    overlay.addEventListener('click', closeDrawer);
  }
});
