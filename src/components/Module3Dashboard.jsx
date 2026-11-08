import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Doughnut, Line, Bar } from 'react-chartjs-2';
import { 
  Activity, 
  AlertTriangle, 
  Server, 
  Globe, 
  HardDriveDownload,
  Flame,
  TrendingUp,
  Cpu,
  UploadCloud
} from 'lucide-react';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

export default function Module3Dashboard({ analysisData, onNavigateToUpload }) {
  if (!analysisData || !analysisData.totalLogs) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center space-y-4 shadow-xl">
        <div className="w-16 h-16 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-cyan-400">
          <Activity className="w-8 h-8 animate-pulse" />
        </div>
        <div className="space-y-1">
          <h3 className="text-lg font-bold text-white">No hay telemetría disponible</h3>
          <p className="text-xs sm:text-sm text-slate-400 max-w-md mx-auto">
            Cargue un archivo SIEM en el Módulo 1 para generar automáticamente los gráficos, métricas y geointeligencia en tiempo real.
          </p>
        </div>
        <button
          onClick={onNavigateToUpload}
          className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs sm:text-sm inline-flex items-center gap-2 shadow-lg shadow-cyan-600/30 transition-all"
        >
          <UploadCloud className="w-4 h-4" />
          <span>Ir a Carga de Archivos</span>
        </button>
      </div>
    );
  }

  const { 
    totalLogs, 
    severityCounts, 
    hourlyBuckets, 
    incidents, 
    compromisedAssets, 
    threatActors, 
    totalExfiltratedMB,
    suspiciousLogsCount,
    fileName 
  } = analysisData;

  // Chart 1: Severity Doughnut
  const severityChartData = {
    labels: ['Crítico / Alto', 'Medio', 'Warning', 'Informacional'],
    datasets: [
      {
        data: [
          (severityCounts.Critical || 0) + (severityCounts.High || 0),
          severityCounts.Medium || 0,
          severityCounts.Warning || 0,
          severityCounts.Informational || 0
        ],
        backgroundColor: [
          '#ef4444',
          '#f59e0b',
          '#eab308',
          '#10b981'
        ],
        borderColor: '#0f172a',
        borderWidth: 2,
      }
    ]
  };

  const severityChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#cbd5e1',
          font: { size: 11, family: 'Inter' },
          padding: 12
        }
      }
    },
    cutout: '70%'
  };

  // Chart 2: Timeline Line Chart
  const timelineHours = Object.keys(hourlyBuckets).sort();
  const timelineCounts = timelineHours.map(h => hourlyBuckets[h]);

  const timelineChartData = {
    labels: timelineHours.length > 0 ? timelineHours : ['En curso'],
    datasets: [
      {
        label: 'Volumen de Eventos por Intervalo',
        data: timelineCounts.length > 0 ? timelineCounts : [totalLogs],
        borderColor: '#06b6d4',
        backgroundColor: 'rgba(6, 182, 212, 0.15)',
        fill: true,
        tension: 0.35,
        pointBackgroundColor: '#06b6d4',
        pointBorderColor: '#fff',
        pointRadius: 4
      }
    ]
  };

  const timelineChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false }
    },
    scales: {
      x: {
        grid: { color: 'rgba(51, 65, 85, 0.4)' },
        ticks: { color: '#94a3b8', font: { size: 10 } }
      },
      y: {
        grid: { color: 'rgba(51, 65, 85, 0.4)' },
        ticks: { color: '#94a3b8', font: { size: 10 } }
      }
    }
  };

  // Chart 3: Affected Assets Exposure (Bar Chart)
  const topAssets = compromisedAssets.slice(0, 8);
  const assetLabels = topAssets.map(a => a.hostname);
  const assetCounts = topAssets.map(a => a.eventCount);

  const assetChartData = {
    labels: assetLabels.length > 0 ? assetLabels : ['Sin activos'],
    datasets: [
      {
        label: 'Eventos Registrados por Hostname',
        data: assetCounts.length > 0 ? assetCounts : [0],
        backgroundColor: topAssets.map(a => 
          a.severity === 'Crítico' ? '#ef4444' : a.severity === 'Alto' ? '#f97316' : '#3b82f6'
        ),
        borderRadius: 6
      }
    ]
  };

  const assetChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: '#cbd5e1', font: { size: 11, weight: 'bold' } }
      },
      y: {
        grid: { color: 'rgba(51, 65, 85, 0.4)' },
        ticks: { color: '#94a3b8', font: { size: 10 } }
      }
    }
  };

  // Chart 4: Incidents Breakdown
  const incLabels = incidents.map(i => i.shortName);
  const incEvents = incidents.map(i => i.matchedLogsCount || i.eventCount);

  const incChartData = {
    labels: incLabels.length > 0 ? incLabels : ['Sin incidentes'],
    datasets: [
      {
        label: 'Eventos Correlacionados',
        data: incEvents.length > 0 ? incEvents : [0],
        backgroundColor: '#8b5cf6',
        borderRadius: 4
      }
    ]
  };

  const incChartOptions = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: {
        grid: { color: 'rgba(51, 65, 85, 0.4)' },
        ticks: { color: '#94a3b8', font: { size: 10 } }
      },
      y: {
        grid: { display: false },
        ticks: { color: '#cbd5e1', font: { size: 10 } }
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-900 to-slate-800 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono font-semibold uppercase tracking-wider mb-1">
          <Activity className="w-4 h-4" />
          <span>Módulo 3: Telemetría SOC & Métricas en Tiempo Real</span>
        </div>
        <h2 className="text-xl font-bold text-white">
          Dashboard Interactivo de Amenazas e Indicadores Clave
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Telemetría visual calculada al instante para <strong className="text-cyan-300 font-mono">{fileName}</strong>.
        </p>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Total Eventos</span>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-white font-mono">{totalLogs}</span>
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <span className="text-[10px] text-slate-500 mt-1">100% procesado en memoria</span>
        </div>

        <div className="bg-slate-900 border border-red-900/60 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-red-300 uppercase tracking-wider">Incidentes</span>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-red-400 font-mono">{incidents.length}</span>
            <Flame className="w-5 h-5 text-red-500" />
          </div>
          <span className="text-[10px] text-red-400 font-bold mt-1">Vectores confirmados</span>
        </div>

        <div className="bg-slate-900 border border-amber-900/60 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-amber-300 uppercase tracking-wider">Anomalías</span>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-amber-400 font-mono">{suspiciousLogsCount}</span>
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </div>
          <span className="text-[10px] text-amber-400/80 mt-1">Eventos no informacionales</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Activos en Red</span>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-purple-300 font-mono">{compromisedAssets.length}</span>
            <Server className="w-5 h-5 text-purple-400" />
          </div>
          <span className="text-[10px] text-slate-500 mt-1">Hostnames únicos</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">IPs Externas</span>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-rose-400 font-mono">{threatActors.length}</span>
            <Globe className="w-5 h-5 text-rose-400" />
          </div>
          <span className="text-[10px] text-slate-500 mt-1">Direcciones WAN</span>
        </div>

        <div className="bg-slate-900 border border-cyan-900/60 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-cyan-300 uppercase tracking-wider">Fuga Datos</span>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-cyan-300 font-mono">
              {Number(totalExfiltratedMB) > 0 ? `~${totalExfiltratedMB} MB` : '0 MB'}
            </span>
            <HardDriveDownload className="w-5 h-5 text-cyan-400" />
          </div>
          <span className="text-[10px] text-cyan-400 font-bold mt-1">Volumen saliente</span>
        </div>
      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Flame className="w-4 h-4 text-red-400" />
              <span>Distribución de Severidad en Tiempo Real</span>
            </h3>
            <span className="text-[11px] text-slate-400 font-mono">{totalLogs} eventos</span>
          </div>
          <div className="h-64 relative">
            <Doughnut data={severityChartData} options={severityChartOptions} />
          </div>
        </div>

        {/* Timeline Spikes */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <span>Actividad y Picos Temporales</span>
            </h3>
            <span className="text-[11px] text-slate-400 font-mono">Curva Dinámica</span>
          </div>
          <div className="h-64">
            <Line data={timelineChartData} options={timelineChartOptions} />
          </div>
        </div>

        {/* Affected Assets Exposure */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-purple-400" />
              <span>Tráfico y Exposición por Activo (Top Hosts)</span>
            </h3>
            <span className="text-[11px] text-slate-400 font-mono">Volumen</span>
          </div>
          <div className="h-64">
            <Bar data={assetChartData} options={assetChartOptions} />
          </div>
        </div>

        {/* Incidents Breakdown */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-indigo-400" />
              <span>Eventos por Vector de Incidente Detectado</span>
            </h3>
            <span className="text-[11px] text-slate-400 font-mono">Incidentes</span>
          </div>
          <div className="h-64">
            <Bar data={incChartData} options={incChartOptions} />
          </div>
        </div>
      </div>

      {/* External Threat Actors Table */}
      {threatActors.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>Direcciones IP Externas Identificadas</span>
            </h3>
            <span className="text-xs text-slate-400 font-mono">{threatActors.length} IPs Detectadas</span>
          </div>

          <div className="overflow-x-auto border border-slate-800 rounded-lg">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase tracking-wider">
                <tr>
                  <th className="p-3">Dirección IP</th>
                  <th className="p-3">Eventos Registrados</th>
                  <th className="p-3">Último Vector / Descripción</th>
                  <th className="p-3">Severidad Estimada</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {threatActors.map((actor, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/60">
                    <td className="p-3 font-bold text-cyan-400 whitespace-nowrap">{actor.ip}</td>
                    <td className="p-3 text-slate-300 font-sans">{actor.eventCount}</td>
                    <td className="p-3 text-amber-300 font-sans max-w-md truncate">{actor.attack}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        actor.severity === 'Crítico' 
                          ? 'text-red-400 bg-red-950/40 border-red-800' 
                          : 'text-orange-400 bg-orange-950/40 border-orange-800'
                      }`}>
                        {actor.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
