import React from 'react';
import {
  ShieldAlert,
  UploadCloud,
  LayoutDashboard,
  Flame,
  FileText,
  Download,
  Terminal,
  Activity,
  FileSpreadsheet
} from 'lucide-react';
import { STOCKHOLM_CONSULTING_INFO } from '../data/incidentDefinitions';

export default function Navbar({ activeTab, setActiveTab, onLoadSample, onClearData, totalLogs, incidentsCount, isLiveAnalyzed, fileName }) {
  const navItems = [
    { id: 'module1', label: '1. Carga & Logs SIEM', icon: UploadCloud, badge: totalLogs > 0 ? `${totalLogs} logs` : 'Vacío' },
    { id: 'module2', label: '2. Análisis & Kill Chain', icon: ShieldAlert, badge: incidentsCount > 0 ? `${incidentsCount} incidentes` : null },
    { id: 'module3', label: '3. Dashboard Interactivo', icon: LayoutDashboard },
    { id: 'module4', label: '4. Clasificación de Riesgos', icon: Flame },
    { id: 'module5', label: '5. Informe Técnico', icon: FileText },
    { id: 'module6', label: '6. Exportación de Resultados', icon: Download }
  ];

  return (
    <header className="sticky top-0 z-50 bg-[#0b1120]/95 backdrop-blur-md border-b border-slate-800 shadow-xl no-print">
      {/* Top Banner with Stockholm SOC Telemetry */}
      <div className="bg-[#0f172a] border-b border-slate-800/80 px-4 py-1.5 text-xs">
        <div className="max-w-7xl mx-auto flex flex-wrap justify-between items-center gap-2 text-slate-400">
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800/60 font-mono font-semibold">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              {STOCKHOLM_CONSULTING_INFO.socLevel}
            </span>
            <span className="hidden sm:inline text-slate-300 font-medium">
              📍 {STOCKHOLM_CONSULTING_INFO.location}
            </span>
            <span className="hidden md:inline text-slate-500">|</span>
            <span className="hidden md:inline text-slate-400 font-mono">
              Ref: {STOCKHOLM_CONSULTING_INFO.caseReference}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {fileName && (
              <span className="hidden lg:inline px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono text-[11px] truncate max-w-[200px]" title={fileName}>
                📄 {fileName}
              </span>
            )}

            {totalLogs > 0 ? (
              <button
                onClick={onClearData}
                title="Limpiar datos y dejar la aplicación vacía"
                className="px-2.5 py-0.5 rounded bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800 text-xs transition-colors"
              >
                Vaciar Datos
              </button>
            ) : (
              <button
                onClick={onLoadSample}
                title="Cargar dataset de muestra del SIEM de Estocolmo"
                className="px-2.5 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs transition-colors flex items-center gap-1"
              >
                <FileSpreadsheet className="w-3.5 h-3.5 text-cyan-400" />
                <span>Cargar Dataset Muestra</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Brand & Nav Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-2.5 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-white font-bold">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
                <span>NORDIC CYBER DEFENSE</span>
                <span className="text-cyan-400 font-light">| MOTOR SIEM EN TIEMPO REAL</span>
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Desafío Técnico Analista SOC Nivel 2 (Estocolmo, Suecia) &middot; Análisis Dinámico de Ingesta
            </p>
          </div>
        </div>

        {/* Status indicator in Real Time */}
        <div className="flex items-center gap-2">
          {totalLogs > 0 ? (
            <div className="bg-red-950/60 border border-red-800/80 rounded-lg px-3 py-1.5 flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping"></div>
              <div className="text-left">
                <div className="text-[10px] text-red-300 uppercase tracking-wider font-bold">Análisis en Tiempo Real</div>
                <div className="text-xs font-bold text-red-200">
                  {incidentsCount > 0 ? `${incidentsCount} Incidentes Detectados` : 'Tráfico Benigno Analizado'}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse"></div>
              <div className="text-left">
                <div className="text-[10px] text-amber-300 uppercase tracking-wider font-bold">Estado del Sistema</div>
                <div className="text-xs font-bold text-slate-300">Esperando Ingesta de Archivo SIEM</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Tab Navigation Menu */}
      <div className="max-w-7xl mx-auto px-4 overflow-x-auto scrollbar-thin">
        <nav className="flex space-x-1 sm:space-x-2 py-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs sm:text-sm font-medium transition-all whitespace-nowrap ${isActive
                  ? 'bg-cyan-500 text-white shadow-md shadow-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/70'
                  }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                <span>{item.label}</span>
                {item.badge && (
                  <span
                    className={`ml-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${isActive
                      ? 'bg-cyan-900/60 text-cyan-100'
                      : item.badge === 'Vacío'
                        ? 'bg-slate-800 text-slate-400 border border-slate-700'
                        : 'bg-slate-800 text-slate-300 border border-slate-700'
                      }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
