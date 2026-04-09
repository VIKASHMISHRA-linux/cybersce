/* ── CHART.JS GLOBAL DEFAULTS ── */
Chart.defaults.color = '#4a6080';
Chart.defaults.font  = { family: "'Courier New', monospace", size: 11 };

const _grid  = { color: 'rgba(0,195,255,0.07)', drawBorder: false };
const _ticks = { color: '#4a6080' };
const _tooltip = {
  backgroundColor: 'rgba(10,22,40,0.95)',
  borderColor: 'rgba(0,195,255,0.3)',
  borderWidth: 1,
  titleColor: '#00c3ff',
  bodyColor: '#c8d8f0',
};

/* ── LINE CHART — Log Activity ── */
const lineCtx = document.getElementById('lineChart').getContext('2d');
const _lineGrad = lineCtx.createLinearGradient(0, 0, 0, 220);
_lineGrad.addColorStop(0, 'rgba(0,195,255,0.25)');
_lineGrad.addColorStop(1, 'rgba(0,195,255,0)');

window.lineChart = new Chart(lineCtx, {
  type: 'line',
  data: {
    labels: Array.from({ length: 12 }, (_, i) => {
      const d = new Date(Date.now() - (11 - i) * 5000);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }),
    datasets: [{
      label: 'Log Events',
      data: Array.from({ length: 12 }, () => Math.floor(Math.random() * 15)),
      borderColor: '#00c3ff', backgroundColor: _lineGrad,
      borderWidth: 2, pointBackgroundColor: '#00c3ff',
      pointRadius: 3, pointHoverRadius: 5, tension: 0.4, fill: true,
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 400 },
    plugins: { legend: { display: false }, tooltip: _tooltip },
    scales: {
      x: { grid: _grid, ticks: { ..._ticks, maxTicksLimit: 6 } },
      y: { grid: _grid, ticks: _ticks, beginAtZero: true },
    }
  }
});

/* ── PIE CHART — Risk Distribution ── */
window.pieChart = new Chart(document.getElementById('pieChart'), {
  type: 'doughnut',
  data: {
    labels: ['Low', 'Medium', 'High', 'Critical'],
    datasets: [{
      data: [40, 30, 20, 10],
      backgroundColor: [
        'rgba(0,255,156,0.75)', 'rgba(255,215,0,0.75)',
        'rgba(255,140,0,0.75)', 'rgba(255,59,59,0.75)',
      ],
      borderColor: ['#00ff9c', '#ffd700', '#ff8c00', '#ff3b3b'],
      borderWidth: 1.5, hoverOffset: 8,
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false, cutout: '65%',
    animation: { duration: 500 },
    plugins: {
      legend: { position: 'bottom', labels: { padding: 14, boxWidth: 12, color: '#c8d8f0' } },
      tooltip: _tooltip,
    }
  }
});

/* ── BAR CHART — Attack Types ── */
window.barChart = new Chart(document.getElementById('barChart'), {
  type: 'bar',
  data: {
    labels: [],
    datasets: [{
      label: 'Count',
      data: [],
      backgroundColor: [
        'rgba(255,59,59,0.7)', 'rgba(255,140,0,0.7)', 'rgba(255,215,0,0.7)',
        'rgba(0,195,255,0.7)', 'rgba(0,255,156,0.7)', 'rgba(180,100,255,0.7)',
        'rgba(255,59,59,0.5)',
      ],
      borderColor: ['#ff3b3b','#ff8c00','#ffd700','#00c3ff','#00ff9c','#b464ff','#ff3b3b'],
      borderWidth: 1, borderRadius: 4,
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 500 },
    plugins: { legend: { display: false }, tooltip: _tooltip },
    scales: {
      x: { grid: _grid, ticks: _ticks },
      y: { grid: _grid, ticks: _ticks, beginAtZero: true },
    }
  }
});

/* ── HORIZONTAL BAR — Top Countries ── */
window.countryChart = new Chart(document.getElementById('countryChart'), {
  type: 'bar',
  data: {
    labels: [],
    datasets: [{
      label: 'Attacks',
      data: [],
      backgroundColor: 'rgba(0,195,255,0.6)',
      borderColor: '#00c3ff',
      borderWidth: 1, borderRadius: 4,
    }]
  },
  options: {
    indexAxis: 'y',
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 500 },
    plugins: { legend: { display: false }, tooltip: _tooltip },
    scales: {
      x: { grid: _grid, ticks: _ticks, beginAtZero: true },
      y: { grid: { display: false }, ticks: _ticks },
    }
  }
});

/* ── UPDATE HELPERS ── */
window.pushLinePoint = function(value) {
  const c   = window.lineChart;
  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  c.data.labels.push(now);
  c.data.datasets[0].data.push(value);
  if (c.data.labels.length > 20) { c.data.labels.shift(); c.data.datasets[0].data.shift(); }
  c.update('none');
};

window.updatePieChart = function(low, medium, high, critical) {
  window.pieChart.data.datasets[0].data = [low, medium, high, critical];
  window.pieChart.update('none');
};

window.updateBarChart = function(labels, data) {
  window.barChart.data.labels = labels;
  window.barChart.data.datasets[0].data = data;
  window.barChart.update('none');
};

window.updateCountryChart = function(labels, data) {
  window.countryChart.data.labels = labels;
  window.countryChart.data.datasets[0].data = data;
  window.countryChart.update('none');
};
