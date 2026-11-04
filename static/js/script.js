/* =========================================================
   script.js  –  Smart Medication Adherence System
   ========================================================= */

document.addEventListener('DOMContentLoaded', function () {

  /* ── Auto-dismiss flash messages ── */
  document.querySelectorAll('.alert').forEach(function (el) {
    setTimeout(function () {
      el.style.transition = 'opacity .5s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 500);
    }, 3500);
  });

  /* ── Adherence ring ── */
  var ring = document.getElementById('adherenceRing');
  if (ring) {
    var pct    = parseInt(ring.dataset.pct || 0);
    var radius = 54;
    var circ   = 2 * Math.PI * radius;
    var fg     = ring.querySelector('.ring-fg');
    fg.style.strokeDasharray  = circ;
    fg.style.strokeDashoffset = circ - (pct / 100) * circ;
    fg.style.stroke = pct >= 80 ? '#16a34a' : pct >= 50 ? '#d97706' : '#dc2626';
    var label = document.getElementById('ringLabel');
    if (label) label.textContent = pct + '%';
  }

  /* ── Confirm before marking missed ── */
  document.querySelectorAll('.confirm-missed').forEach(function (btn) {
    btn.addEventListener('click', function (e) {
      if (!confirm('Mark this medication as MISSED?')) e.preventDefault();
    });
  });

  /* ── Notification badge: mark all read on click ── */
  var notifBadge = document.getElementById('notifBadge');
  if (notifBadge) {
    notifBadge.addEventListener('click', function () {
      fetch('/api/notifications/read', { method: 'POST' })
        .then(function () { notifBadge.remove(); })
        .catch(function () {});
    });
  }

  /* ── History chart (adherenceChart) ── */
  var histCtx = document.getElementById('adherenceChart');
  if (histCtx && typeof Chart !== 'undefined') {
    var histLabels = JSON.parse(histCtx.dataset.labels || '[]');
    var histData   = JSON.parse(histCtx.dataset.values || '[]');
    new Chart(histCtx, {
      type: 'bar',
      data: {
        labels: histLabels,
        datasets: [{
          label: 'Adherence %',
          data: histData,
          backgroundColor: histData.map(function (v) {
            return v >= 80 ? '#16a34a' : v >= 50 ? '#d97706' : '#dc2626';
          }),
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, max: 100,
               ticks: { callback: function (v) { return v + '%'; } } }
        }
      }
    });
  }

  /* ── Dashboard weekly bar chart (weeklyChart) ── */
  var weekCtx = document.getElementById('weeklyChart');
  if (weekCtx && typeof Chart !== 'undefined') {
    var wLabels = JSON.parse(weekCtx.dataset.labels || '[]');
    var wData   = JSON.parse(weekCtx.dataset.values || '[]');
    new Chart(weekCtx, {
      type: 'bar',
      data: {
        labels: wLabels,
        datasets: [{
          label: 'Adherence %',
          data: wData,
          backgroundColor: wData.map(function (v) {
            return v >= 80 ? 'rgba(22,163,74,.8)' : v >= 50 ? 'rgba(217,119,6,.8)' : 'rgba(220,38,38,.8)';
          }),
          borderRadius: 5
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, max: 100,
               ticks: { callback: function (v) { return v + '%'; }, font: { size: 10 } } },
          x: { ticks: { font: { size: 10 } } }
        }
      }
    });
  }

  /* ── Dashboard Taken vs Missed doughnut (donutChart) ── */
  var donutCtx = document.getElementById('donutChart');
  if (donutCtx && typeof Chart !== 'undefined') {
    var tk = parseInt(donutCtx.dataset.taken   || 0);
    var ms = parseInt(donutCtx.dataset.missed  || 0);
    var pd = parseInt(donutCtx.dataset.pending || 0);
    new Chart(donutCtx, {
      type: 'doughnut',
      data: {
        labels: ['Taken', 'Missed', 'Pending'],
        datasets: [{
          data: [tk, ms, pd],
          backgroundColor: ['#16a34a', '#dc2626', '#d97706'],
          borderWidth: 2,
          borderColor: '#fff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function (c) {
                var total = tk + ms + pd;
                var pct = total ? Math.round(c.raw / total * 100) : 0;
                return c.label + ': ' + c.raw + ' (' + pct + '%)';
              }
            }
          }
        },
        cutout: '60%'
      }
    });
  }

  /* ── Analytics page charts ── */
  var analWeekCtx = document.getElementById('analyticsWeeklyChart');
  if (analWeekCtx && typeof Chart !== 'undefined') {
    var al = JSON.parse(analWeekCtx.dataset.labels || '[]');
    var av = JSON.parse(analWeekCtx.dataset.values || '[]');
    new Chart(analWeekCtx, {
      type: 'bar',
      data: {
        labels: al,
        datasets: [{
          label: 'Adherence %',
          data: av,
          backgroundColor: av.map(function (v) {
            return v >= 80 ? '#16a34a' : v >= 50 ? '#d97706' : '#dc2626';
          }),
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, max: 100,
               ticks: { callback: function (v) { return v + '%'; } } }
        }
      }
    });
  }

  var analDonutCtx = document.getElementById('analyticsDonut');
  if (analDonutCtx && typeof Chart !== 'undefined') {
    var dt = parseInt(analDonutCtx.dataset.taken   || 0);
    var dm = parseInt(analDonutCtx.dataset.missed  || 0);
    var dp = parseInt(analDonutCtx.dataset.pending || 0);
    new Chart(analDonutCtx, {
      type: 'doughnut',
      data: {
        labels: ['Taken', 'Missed', 'Pending'],
        datasets: [{
          data: [dt, dm, dp],
          backgroundColor: ['#16a34a', '#dc2626', '#d97706'],
          borderWidth: 2, borderColor: '#fff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom' },
          tooltip: {
            callbacks: {
              label: function (c) {
                var total = dt + dm + dp;
                var pct = total ? Math.round(c.raw / total * 100) : 0;
                return c.label + ': ' + c.raw + ' (' + pct + '%)';
              }
            }
          }
        },
        cutout: '55%'
      }
    });
  }

  /* ── Add Medicine: default start_date to today ── */
  var startDate = document.getElementById('start_date');
  if (startDate && !startDate.value) {
    startDate.value = new Date().toISOString().split('T')[0];
  }

  /* ── Set min date on end_date ── */
  var endDate = document.getElementById('end_date');
  if (startDate && endDate) {
    startDate.addEventListener('change', function () {
      endDate.min = startDate.value;
      if (endDate.value && endDate.value < startDate.value) {
        endDate.value = startDate.value;
      }
    });
  }

});
