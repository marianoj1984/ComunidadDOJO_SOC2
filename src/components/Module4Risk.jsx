import React, { useState } from 'react';
import { 
  Flame, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  HelpCircle, 
  Sliders, 
  Layers,
  Lock,
  FileCheck,
  TrendingUp,
  Cpu,
  UploadCloud,
  ShieldCheck
} from 'lucide-react';

export default function Module4Risk({ analysisData, onNavigateToUpload }) {
  const [selectedRiskFilter, setSelectedRiskFilter] = useState('ALL');

  if (!analysisData) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center space-y-4 max-w-2xl mx-auto shadow-2xl">
        <div className="w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto text-amber-400">
          <Flame className="w-8 h-8" />
        </div>
        <h3 className="text-xl font-bold text-white">Esperando Ingesta de Datos SIEM</h3>
        <p className="text-sm text-slate-400 leading-relaxed">
          No hay registros cargados actualmente en el sistema. Ingeste un archivo de logs (Excel o CSV) en el Módulo 1 para computar en tiempo real la matriz de riesgos, la puntuación CVSS v3.1 y la justificación de impacto sobre la tríada de seguridad.
        </p>
        <button
          onClick={onNavigateToUpload}
          className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs sm:text-sm inline-flex items-center gap-2 shadow-lg shadow-cyan-600/30 transition-all"
        >
          <UploadCloud className="w-4 h-4" />
          <span>Ir al Módulo 1 (Carga & Ingesta)</span>
        </button>
      </div>
    );
  }

  const riskRatings = [
    {
      level: "Crítico",
      scoreRange: "9.0 - 10.0",
      color: "from-red-500/20 to-red-950/40 border-red-500/60 text-red-400",
      badgeColor: "bg-red-500/20 text-red-300 border-red-500/50",
      description: "Compromiso total de activos centrales, ejecución remota de código (RCE), robo consumado de propiedad confidencial y preparativos destructivos (pre-ransomware).",
      actionRequired: "Respuesta inmediata (0-4 horas), aislamiento total de la máquina y revocación de credenciales."
    },
    {
      level: "Alto",
      scoreRange: "7.0 - 8.9",
      color: "from-orange-500/20 to-orange-950/40 border-orange-500/60 text-orange-400",
      badgeColor: "bg-orange-500/20 text-orange-300 border-orange-500/50",
      description: "Exfiltración masiva de datos, implantación de persistencia encubierta mediante servicios o ataques dirigidos de credenciales contra controladores de dominio.",
      actionRequired: "Contención prioritaria (4-12 horas), saneamiento del endpoint y bloqueo en firewall/proxy."
    },
    {
      level: "Medio",
      scoreRange: "4.0 - 6.9",
      color: "from-amber-500/20 to-amber-950/40 border-amber-500/60 text-amber-400",
      badgeColor: "bg-amber-500/20 text-amber-300 border-amber-500/50",
      description: "Intentos no exitosos pero continuos de autenticación forzada, reconocimientos locales de privilegios o anomalías operativas de bajo impacto directo.",
      actionRequired: "Monitoreo reforzado, revisión de políticas de auditoría y hardening de contraseñas."
    },
    {
      level: "Bajo",
      scoreRange: "0.1 - 3.9",
      color: "from-blue-500/20 to-blue-950/40 border-blue-500/60 text-blue-400",
      badgeColor: "bg-blue-500/20 text-blue-300 border-blue-500/50",
      description: "Ruido de fondo normal en el SIEM: intentos fallidos de tipeo de usuario único, reinicios de servicios programados o consultas DNS legítimas.",
      actionRequired: "Registro rutinario en bitácora sin requerimiento de intervención manual."
    }
  ];

  // Derive findings dynamically from detected incidents
  const dynamicFindings = analysisData.incidents.map(inc => {
    // CIA derivation
    let cia = { c: "Bajo", i: "Bajo", a: "Bajo" };
    if (inc.severity === "Crítico") {
      cia = { c: "Alto", i: "Alto", a: inc.name.includes("VSS") || inc.name.includes("Ransomware") ? "Alto" : "Medio" };
    } else if (inc.severity === "Alto") {
      cia = { c: "Alto", i: inc.name.includes("Persistencia") ? "Alto" : "Bajo", a: "Bajo" };
    } else {
      cia = { c: "Medio", i: "Bajo", a: "Bajo" };
    }

    return {
      id: inc.id,
      name: inc.name,
      severity: inc.severity,
      cvss: inc.cvssScore,
      vector: inc.cvssVector,
      probability: inc.severity === 'Crítico' ? "Muy Alta (100% Confirmada)" : "Alta (Detectado en Telemetría)",
      probabilityJustification: inc.technicalDetails || inc.summary,
      impact: inc.severity === 'Crítico' 
        ? "Catastrófico (Compromiso de Activo Crítico o Fuga Confirmada)" 
        : "Severo (Riesgo Operacional y de Privacidad)",
      impactJustification: inc.impact || inc.summary,
      cia: cia,
      mitreTechniques: inc.mitreTechniques || [],
      matchedLogsCount: inc.matchedLogsCount || inc.eventCount || 0
    };
  });

  const filteredFindings = selectedRiskFilter === 'ALL'
    ? dynamicFindings
    : dynamicFindings.filter(f => f.severity === selectedRiskFilter);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-900 to-slate-800 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono font-semibold uppercase tracking-wider mb-1">
          <Flame className="w-4 h-4" />
          <span>Módulo 4: Metodología de Clasificación de Riesgo & Evaluación Técnica</span>
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-bold text-white">
              Matriz de Riesgo y Justificación Pericial del Impacto
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              Ponderación fundamentada en el estándar internacional CVSS v3.1, la probabilidad técnica de explotación activa y el impacto directo en la tríada de seguridad (Confidencialidad, Integridad y Disponibilidad).
            </p>
          </div>
          <div className="text-right flex-shrink-0">
            <span className="inline-block px-3 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-cyan-300">
              Evaluando: <strong className="text-white">{analysisData.fileName}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* 4-Tier Risk Ladder Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {riskRatings.map((r, idx) => (
          <div 
            key={idx}
            className={`bg-gradient-to-br ${r.color} border rounded-xl p-4 flex flex-col justify-between shadow-lg space-y-3`}
          >
            <div>
              <div className="flex items-center justify-between">
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border ${r.badgeColor}`}>
                  {r.level}
                </span>
                <span className="text-xs font-mono text-slate-300 font-semibold">CVSS {r.scoreRange}</span>
              </div>
              <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                {r.description}
              </p>
            </div>

            <div className="pt-2 border-t border-slate-800/80 text-[11px] text-slate-400">
              <strong className="text-slate-200 block mb-0.5">Acción Requerida:</strong>
              {r.actionRequired}
            </div>
          </div>
        ))}
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-semibold">Filtrar por Nivel de Riesgo:</span>
          {['ALL', 'Crítico', 'Alto', 'Medio', 'Bajo'].map((tier) => (
            <button
              key={tier}
              onClick={() => setSelectedRiskFilter(tier)}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition-colors ${
                selectedRiskFilter === tier
                  ? 'bg-cyan-500 text-white shadow'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {tier === 'ALL' ? `Todos los Hallazgos (${dynamicFindings.length})` : tier}
            </button>
          ))}
        </div>
      </div>

      {/* Detailed Technical Justification Table */}
      {filteredFindings.length === 0 ? (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
          <p className="font-semibold text-slate-300">No hay hallazgos bajo el filtro seleccionado ({selectedRiskFilter}).</p>
          <p className="text-xs mt-1 text-slate-500">
            {dynamicFindings.length === 0 
              ? "No se confirmaron incidentes hostiles en los logs cargados."
              : "Seleccione 'Todos los Hallazgos' para inspeccionar los incidentes clasificados."}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredFindings.map((finding) => (
            <div 
              key={finding.id}
              className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-5 space-y-4 shadow-xl transition-all"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 rounded bg-slate-800 text-cyan-400 font-mono text-xs font-bold border border-slate-700">
                    {finding.id}
                  </span>
                  <h3 className="text-sm sm:text-base font-bold text-white">
                    {finding.name}
                  </h3>
                </div>

                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-1 font-mono text-xs">
                    <span className="text-slate-400">CVSS v3.1:</span>
                    <span className="text-red-400 font-extrabold text-sm">{finding.cvss}</span>
                  </div>
                  <span className={`px-2.5 py-0.5 rounded text-xs font-bold border ${
                    finding.severity === 'Crítico' 
                      ? 'bg-red-500/20 text-red-300 border-red-500/50' 
                      : 'bg-orange-500/20 text-orange-300 border-orange-500/50'
                  }`}>
                    {finding.severity}
                  </span>
                </div>
              </div>

              {/* CVSS Vector */}
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-500 text-[10px] uppercase">Vector de Evaluación:</span>
                <span className="text-cyan-300 select-all">{finding.vector}</span>
              </div>

              {/* Probability & Impact Rationale Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                {/* Likelihood / Probability */}
                <div className="bg-slate-950/80 p-3.5 rounded-lg border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-amber-400 font-bold uppercase tracking-wider text-[11px] flex items-center gap-1">
                      <TrendingUp className="w-3.5 h-3.5" />
                      <span>Probabilidad de Explotación:</span>
                    </span>
                    <span className="text-amber-300 font-semibold">{finding.probability}</span>
                  </div>
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    {finding.probabilityJustification}
                  </p>
                </div>

                {/* Potential Business Impact */}
                <div className="bg-slate-950/80 p-3.5 rounded-lg border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-rose-400 font-bold uppercase tracking-wider text-[11px] flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>Impacto Potencial en la Organización:</span>
                    </span>
                    <span className="text-rose-300 font-semibold">{finding.impact}</span>
                  </div>
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    {finding.impactJustification}
                  </p>
                </div>
              </div>

              {/* CIA Triad Impact Badges */}
              <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono pt-1 text-slate-400">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-semibold text-slate-300">Afectación Tríada CIA:</span>
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                    Confidencialidad: <strong className="text-red-400">{finding.cia.c}</strong>
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                    Integridad: <strong className="text-orange-400">{finding.cia.i}</strong>
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                    Disponibilidad: <strong className="text-amber-400">{finding.cia.a}</strong>
                  </span>
                </div>

                <div className="text-[11px] text-slate-500">
                  Evidencias vinculadas: <span className="font-bold text-cyan-400">{finding.matchedLogsCount} registros</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
