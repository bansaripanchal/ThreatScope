/**
 * ThreatScope V2 - Recon Comparison JS
 * Manages dual-investigation selection and comparison triggers.
 */

document.addEventListener('DOMContentLoaded', () => {
  const selectA = document.getElementById('compareSelectA');
  const selectB = document.getElementById('compareSelectB');
  const btnCompare = document.getElementById('btnRunCompare');

  if (btnCompare && selectA && selectB) {
    btnCompare.addEventListener('click', () => {
      const a = selectA.value;
      const b = selectB.value;
      if (!a || !b) {
        alert('Please select two investigations to compare.');
        return;
      }
      if (a === b) {
        alert('Please select two distinct investigations to compute deltas.');
        return;
      }
      window.location.href = `/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`;
    });
  }
});
