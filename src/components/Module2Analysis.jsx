import React, { useState } from 'react';
import {
  ShieldAlert,
  Clock,
  Layers,
  Zap,
  ChevronDown,
  ChevronUp,
  AlertOctagon,
  CheckCircle2,
  UploadCloud,
  Terminal,
  Activity
} from 'lucide-react';

export default function Module2Analysis({ analysisData, onNavigateToUpload }) {
  const [expandedIncident, setExpandedIncident] = useState(null);
  const [timelineFilter, setTimelineFilter] = useState('ALL');

  if (!analysisData || !analysisData.totalLogs) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center space-y-4 shadow-xl">
        <div className="w-16 h-16 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-cyan-400">
          <UploadCloud className="w-8 h-8 animate-pulse" />
        </div>
        <div className="space-y-1">
          <h3 className="text-lg font-bold text-white">No hay datos de SIEM cargados</h3>
          <p className="text-xs sm:text-sm text-slate-400 max-w-md mx-auto">
            Para ejecutar el análisis pericial, identificar IoCs y reconstruir la cadena de ataque en tiempo real, primero cargue un archivo en el Módulo 1.
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

  const { incidents, suspiciousLogs, isSecurityIncident, globalConclusion, fileName } = analysisData;

  const getSeverityColor = (sev) => {
    switch (sev) {
      case 'Crítico':
      case 'Critical':
        return 'text-rose-400 bg-rose-950/40 border-rose-800/80';
      case 'Alto':
      case 'High':
        return 'text-orange-400 bg-orange-950/40 border-orange-800/80';
      case 'Medio':
      case 'Medium':
        return 'text-amber-400 bg-amber-950/40 border-amber-800/80';
      default:
        return 'text-blue-400 bg-blue-950/40 border-blue-800/80';
    }
  };

  // Build dynamic timeline from all incidents
  const dynamicTimeline = incidents.flatMap(inc => {
    return (inc.matchedLogs || []).slice(0, 5).map(mlog => ({
      time: mlog.Timestamp,
      incidentId: inc.id,
      severity: inc.severity,
      phase: inc.killChainPhase,
      title: `${inc.shortName}: ${mlog.Event_Description || 'Evento anómalo'}`,
      source: mlog.Source_IP || inc.threatActor,
      target: `${mlog.Hostname} ${mlog.Destination ? '-> ' + mlog.Destination : ''}`,
      technique: inc.mitreTechniques[0] ? `${inc.mitreTechniques[0].id} (${inc.mitreTechniques[0].name})` : 'MITRE ATT&CK',
      desc: mlog.Process_CommandLine || mlog.Event_Description || inc.summary
    }));
  }).sort((a, b) => String(a.time).localeCompare(String(b.time)));

  const filteredTimeline = timelineFilter === 'ALL'
    ? dynamicTimeline
    : dynamicTimeline.filter(e => e.incidentId === timelineFilter);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-900 to-slate-800 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono font-semibold uppercase tracking-wider mb-1">
          <ShieldAlert className="w-4 h-4" />
          <span>Módulo 2: Motor de Detección & Correlación en Tiempo Real</span>
        </div>
        <h2 className="text-xl font-bold text-white">
          Análisis Forense de Seguridad & Reconstrucción de Kill Chain
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Correlación dinámica generada a partir de <strong className="text-cyan-300 font-mono">{fileName}</strong> ({analysisData.totalLogs} eventos analizados).
        </p>
      </div>

      {/* Conclusive Verdict Banner in Real-Time */}
      <div className={`border-2 rounded-xl p-6 shadow-2xl relative overflow-hidden ${isSecurityIncident
          ? 'bg-gradient-to-r from-red-950/70 via-slate-900 to-slate-900 border-red-600/80'
          : 'bg-gradient-to-r from-emerald-950/70 via-slate-900 to-slate-900 border-emerald-600/80'
        }`}>
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div className="space-y-2">
            <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wide border ${isSecurityIncident
                ? 'bg-red-500/20 text-red-400 border-red-500/50'
                : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50'
              }`}>
              <AlertOctagon className="w-4 h-4" />
              <span>DICTAMEN PERICIAL EMITIDO EN TIEMPO REAL</span>
            </div>
            <h3 className="text-lg sm:text-xl font-bold text-white">
              {globalConclusion}
            </h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-4xl">
              {isSecurityIncident
                ? `El motor de correlación identificó ${incidents.length} cluster(s) de incidentes críticos con patrones consistentes de ataque externo, escalada de privilegios o exfiltración. La hipótesis de falso positivo queda descartada tras comprobar ejecuciones anómalas e interacciones no autorizadas.`
                : "No se identificaron patrones hostiles estructurados en este archivo. El tráfico analizado se compone de eventos informacionales rutinarios del sistema operativo y actividades de red autorizadas."}
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2 text-center text-xs font-mono w-full lg:w-auto">
            <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px] uppercase">Incidentes</span>
              <span className={`text-xl font-bold ${isSecurityIncident ? 'text-red-400' : 'text-emerald-400'}`}>
                {incidents.length}
              </span>
            </div>
            <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px] uppercase">Alertas Sospechosas</span>
              <span className="text-xl font-bold text-cyan-400">{suspiciousLogs.length}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Cyber Kill Chain Stages Visualizer */}
      {incidents.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3 shadow-lg">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <span>Distribución de Incidentes por Fase de Intrusión (Cyber Kill Chain)</span>
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 text-xs">
            {incidents.map((inc) => (
              <div key={inc.id} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] text-cyan-400 font-mono font-bold">{inc.id}</span>
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${getSeverityColor(inc.severity)}`}>
                      {inc.severity}
                    </span>
                  </div>
                  <span className="text-white font-bold text-xs block">{inc.shortName}</span>
                  <span className="text-slate-400 text-[11px] mt-1 block truncate font-mono">{inc.killChainPhase}</span>
                </div>
                <div className="mt-2 pt-2 border-t border-slate-800 text-[10px] text-slate-500 font-mono">
                  {inc.matchedLogsCount} registros asociados
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Incident Cards */}
      {incidents.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              <span>Detalle de los {incidents.length} Incidentes Detectados</span>
            </h3>
            <span className="text-xs text-slate-400 font-mono">Haga clic para expandir / contraer</span>
          </div>

          <div className="space-y-3">
            {incidents.map((inc) => {
              const isExpanded = expandedIncident === inc.id;
              return (
                <div
                  key={inc.id}
                  className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl overflow-hidden transition-all shadow-md"
                >
                  <div
                    onClick={() => setExpandedIncident(isExpanded ? null : inc.id)}
                    className="p-4 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900/90 hover:bg-slate-800/50"
                  >
                    <div className="flex items-start sm:items-center gap-3">
                      <span className="px-2.5 py-1 rounded bg-slate-800 text-cyan-400 font-mono text-xs font-bold border border-slate-700">
                        {inc.id}
                      </span>
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <h4 className="text-sm font-bold text-white">{inc.name}</h4>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityColor(inc.severity)}`}>
                            {inc.severity} (CVSS: {inc.cvssScore})
                          </span>
                        </div>
                        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                          <span>🎯 Objetivo: <strong className="text-slate-300">{inc.primaryTarget}</strong></span>
                          <span>⏱ {inc.timeframe || 'Tiempo real'}</span>
                          <span>📊 {inc.matchedLogsCount || inc.eventCount} eventos SIEM</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end sm:self-center">
                      <span className="px-2 py-0.5 rounded-full text-[10px] bg-red-950/80 text-red-300 border border-red-800 font-mono font-semibold">
                        {inc.status}
                      </span>
                      {isExpanded ? (
                        <ChevronUp className="w-5 h-5 text-slate-400" />
                      ) : (
                        <ChevronDown className="w-5 h-5 text-slate-400" />
                      )}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="p-5 border-t border-slate-800 space-y-4 bg-slate-950/60 text-xs">
                      <div className="p-3 bg-slate-900/90 rounded-lg border border-slate-800">
                        <span className="text-cyan-400 font-bold block mb-1">Resumen del Hallazgo:</span>
                        <p className="text-slate-300 leading-relaxed">{inc.summary}</p>
                      </div>

                      <div className="space-y-1.5">
                        <span className="text-amber-400 font-bold block">Reconstrucción Forense Técnica:</span>
                        <pre className="bg-black/80 p-3.5 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-200 whitespace-pre-wrap leading-relaxed">
                          {inc.technicalDetails}
                        </pre>
                      </div>

                      <div className="space-y-1.5">
                        <span className="text-slate-400 font-bold block">Técnicas MITRE ATT&CK Asignadas:</span>
                        <div className="flex flex-wrap gap-2">
                          {inc.mitreTechniques.map((tech) => (
                            <span
                              key={tech.id}
                              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-purple-950/60 text-purple-300 border border-purple-800/70 font-mono text-[11px]"
                            >
                              <span className="font-bold text-white">{tech.id}</span>
                              <span>&bull;</span>
                              <span>{tech.name}</span>
                            </span>
                          ))}
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <span className="text-red-400 font-bold block">Indicadores de Compromiso (IoCs) Detectados:</span>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {inc.iocs.map((ioc, idx) => (
                            <div key={idx} className="bg-slate-900 p-2.5 rounded border border-slate-800 flex flex-col justify-between">
                              <div className="flex items-center justify-between text-[10px] text-slate-400">
                                <span className="uppercase font-semibold text-cyan-400">{ioc.type}</span>
                                <span className="text-slate-500">{ioc.description}</span>
                              </div>
                              <code className="text-amber-300 font-mono font-bold mt-1 text-[11px] select-all break-all">
                                {ioc.value}
                              </code>
                            </div>
                          ))}
                        </div>
                      </div>

                      {inc.matchedLogs && inc.matchedLogs.length > 0 && (
                        <div className="space-y-1.5 pt-2">
                          <span className="text-slate-400 font-bold block">
                            Evidencias Directas en el Archivo ({inc.matchedLogs.length} eventos):
                          </span>
                          <div className="max-h-48 overflow-y-auto border border-slate-800 rounded-lg">
                            <table className="w-full text-left text-[11px] font-mono">
                              <thead className="bg-slate-900 text-slate-400 sticky top-0">
                                <tr>
                                  <th className="p-2">Log ID</th>
                                  <th className="p-2">Timestamp</th>
                                  <th className="p-2">Host</th>
                                  <th className="p-2">Usuario</th>
                                  <th className="p-2">Detalle / Comando</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-slate-800">
                                {inc.matchedLogs.slice(0, 10).map((mlog) => (
                                  <tr key={mlog.Log_ID} className="hover:bg-slate-800/60">
                                    <td className="p-2 text-cyan-400 font-semibold">{mlog.Log_ID}</td>
                                    <td className="p-2 text-slate-400">{mlog.Timestamp}</td>
                                    <td className="p-2 text-slate-200">{mlog.Hostname}</td>
                                    <td className="p-2 text-slate-300">{mlog.User || '-'}</td>
                                    <td className="p-2 text-amber-200 max-w-xs truncate" title={mlog.Process_CommandLine || mlog.Event_Description}>
                                      {mlog.Process_CommandLine || mlog.Event_Description}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Dynamic Chronological Timeline */}
      {dynamicTimeline.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                <span>Línea de Tiempo Reconstruida en Tiempo Real</span>
              </h3>
              <p className="text-xs text-slate-400">
                Secuencia cronológica de eventos correlacionados con la intrusión.
              </p>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-400">Filtrar por Incidente:</span>
              <select
                value={timelineFilter}
                onChange={(e) => setTimelineFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-300"
              >
                <option value="ALL">Todos los Eventos de la Cadena</option>
                {incidents.map(i => (
                  <option key={i.id} value={i.id}>{i.id}: {i.shortName}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="relative pl-6 sm:pl-8 space-y-4 before:absolute before:left-2.5 sm:before:left-3 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
            {filteredTimeline.map((item, idx) => (
              <div key={idx} className="relative group">
                <div className={`absolute -left-6 sm:-left-8 top-1.5 w-3.5 h-3.5 rounded-full border-2 border-slate-900 ${item.severity === 'Crítico' ? 'bg-red-500' : 'bg-orange-500'
                  }`}></div>

                <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1.5">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-400 font-mono font-bold">{item.time}</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                        {item.incidentId}
                      </span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityColor(item.severity)}`}>
                      {item.severity}
                    </span>
                  </div>

                  <h4 className="text-xs font-bold text-white">{item.title}</h4>
                  <p className="text-[11px] text-slate-300 font-mono truncate">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
