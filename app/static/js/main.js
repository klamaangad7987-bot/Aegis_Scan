/* SecureAudit — main.js */

// ── Flash messages auto-dismiss ──────────────────────────────────────────
document.querySelectorAll('.alert[data-auto-dismiss]').forEach(el => {
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity 0.4s';
    setTimeout(() => el.remove(), 400);
  }, 4000);
});

// ── Sidebar mobile toggle ────────────────────────────────────────────────
const sidebarToggle = document.getElementById('sidebar-toggle');
const sidebar = document.querySelector('.sidebar');
if (sidebarToggle && sidebar) {
  sidebarToggle.addEventListener('click', () => {
    sidebar.classList.toggle('open');
  });
  document.addEventListener('click', (e) => {
    if (!sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
      sidebar.classList.remove('open');
    }
  });
}

// ── Vuln rows accordion ──────────────────────────────────────────────────
document.querySelectorAll('.vuln-row').forEach(row => {
  row.addEventListener('click', () => {
    row.classList.toggle('expanded');
  });
});

// ── Confirm before delete ────────────────────────────────────────────────
document.querySelectorAll('[data-confirm]').forEach(el => {
  el.addEventListener('click', (e) => {
    if (!confirm(el.dataset.confirm || 'Confirmer cette action ?')) {
      e.preventDefault();
    }
  });
});

// ── Update vuln status via API ───────────────────────────────────────────
document.querySelectorAll('.vuln-status-btn').forEach(btn => {
  btn.addEventListener('click', async (e) => {
    e.stopPropagation();
    const vulnId = btn.dataset.vulnId;
    const newStatus = btn.dataset.status;
    try {
      const res = await fetch(`/scan/vulnerability/${vulnId}/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        const badge = btn.closest('.vuln-row').querySelector('.vuln-status-badge');
        if (badge) {
          badge.textContent = newStatus;
          badge.className = `badge badge-${newStatus === 'fixed' ? 'success' : newStatus === 'false_positive' ? 'info' : 'pending'}`;
        }
        showToast(`Statut mis à jour : ${newStatus}`, 'success');
      }
    } catch (err) {
      showToast('Erreur lors de la mise à jour', 'error');
    }
  });
});

// ── Generate report ──────────────────────────────────────────────────────
document.querySelectorAll('.btn-generate-report').forEach(btn => {
  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    const scanId = btn.dataset.scanId;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Génération...';
    try {
      const res = await fetch(`/reports/generate/${scanId}`, {
        method: 'POST',
        headers: { 'X-CSRFToken': getCsrfToken() },
      });
      const data = await res.json();
      if (data.success) {
        showToast('Rapport généré avec succès !', 'success');
        setTimeout(() => { window.location.href = `/reports/download/${data.report_id}`; }, 800);
      } else {
        showToast(data.error || 'Erreur lors de la génération', 'error');
      }
    } catch (err) {
      showToast('Erreur réseau', 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<svg>...</svg> Générer PDF';
    }
  });
});

// ── Poll scan status ─────────────────────────────────────────────────────
function pollScanStatus(scanId, onComplete) {
  const interval = setInterval(async () => {
    try {
      const res = await fetch(`/scan/api/status/${scanId}`);
      const data = await res.json();
      const bar = document.getElementById('scan-progress-bar');
      const label = document.getElementById('scan-progress-label');
      if (bar) bar.style.width = `${data.progress}%`;
      if (label) label.textContent = `${data.progress}%`;
      if (data.status === 'completed' || data.status === 'failed') {
        clearInterval(interval);
        if (onComplete) onComplete(data);
        else window.location.reload();
      }
    } catch (err) {
      clearInterval(interval);
    }
  }, 2000);
  return interval;
}

// ── Toast notifications ──────────────────────────────────────────────────
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container') || createToastContainer();
  const toast = document.createElement('div');
  toast.className = `alert alert-${type}`;
  toast.style.cssText = `
    position: relative; pointer-events: all;
    min-width: 280px; max-width: 380px;
    animation: slideInRight 0.3s ease;
  `;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function createToastContainer() {
  const c = document.createElement('div');
  c.id = 'toast-container';
  c.style.cssText = `
    position: fixed; bottom: 24px; right: 24px;
    display: flex; flex-direction: column; gap: 10px;
    z-index: 9999; pointer-events: none;
  `;
  document.body.appendChild(c);
  return c;
}

// ── CSRF token helper ────────────────────────────────────────────────────
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : '';
}

// ── Number counter animation ─────────────────────────────────────────────
function animateCounter(el, target, duration = 1200) {
  const start = 0;
  const startTime = performance.now();
  const update = (now) => {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (target - start) * eased);
    if (progress < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

// Lancer les animations de compteurs au chargement
document.querySelectorAll('.stat-value[data-count]').forEach(el => {
  const target = parseInt(el.dataset.count, 10);
  if (!isNaN(target)) {
    el.textContent = '0';
    animateCounter(el, target);
  }
});

// ── Slide-in animation CSS ───────────────────────────────────────────────
const style = document.createElement('style');
style.textContent = `
  @keyframes slideInRight {
    from { opacity: 0; transform: translateX(20px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .fade-in { animation: fadeIn 0.4s ease forwards; }
`;
document.head.appendChild(style);

// Appliquer fade-in aux cartes
document.querySelectorAll('.card, .stat-card').forEach((el, i) => {
  el.style.opacity = '0';
  el.style.animationDelay = `${i * 0.05}s`;
  el.classList.add('fade-in');
});
