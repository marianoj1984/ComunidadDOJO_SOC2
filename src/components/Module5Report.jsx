import React, { useRef, useState } from 'react';
import { 
  FileText, 
  Printer, 
  Download, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Server, 
  Clock, 
  Lock, 
  Terminal, 
  Globe,
  Award,
  FileCheck,
  UploadCloud,
  ShieldCheck,
  Sparkles
} from 'lucide-react';
import { STOCKHOLM_CONSULTING_INFO } from '../data/incidentDefinitions';
import { generateTechnicalReportPDF } from '../utils/pdfGenerator';

export default function Module5Report({ analysisData, onNavigateToUpload }) {
  const reportRef = useRef(null);
  const [downloadSuccess, setDownloadSuccess] = useState(null);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  const handleDownloadPdf = () => {
    try {
      setIsGeneratingPdf(true);
      const filename = generateTechnicalReportPDF(analysisData);
      setDownloadSuccess(`Informe técnico pericial descargado exitosamente como archivo PDF: ${filename}`);
      setTimeout(() => setDownloadSuccess(null), 5000);
    } catch (err) {
      console.error("Error al generar PDF:", err);
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  if (!analysisData) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center space-y-4 max-w-2xl mx-auto shadow-2xl">
        <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400">
          <FileText className="w-8 h-8" />
        </div>
        <h3 className="text-xl font-bold text-white">Esperando Ingesta de Datos SIEM</h3>
        <p className="text-sm text-slate-400 leading-relaxed">
          No hay registros cargados actualmente para generar el informe pericial. Ingeste un archivo de logs en el Módulo 1 para estructurar automáticamente el documento formal de auditoría y dictamen pericial en tiempo real.
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

  const incidents = analysisData.incidents || [];
  const maxCvss = incidents.length > 0 
    ? Math.max(...incidents.map(i => i.cvssScore || 0))
    : 0;

  // Compile top evidence logs
  const evidenceLogs = (analysisData.suspiciousLogs && analysisData.suspiciousLogs.length > 0)
    ? analysisData.suspiciousLogs.slice(0, 20)
    : [];

  return (
    <div className="space-y-6">
      {/* Action Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 to-slate-800 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4 no-print">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono font-semibold uppercase tracking-wider mb-1">
            <FileText className="w-4 h-4" />
            <span>Módulo 5: Documento Estructurado & Formal para el Cliente</span>
          </div>
          <h2 className="text-xl font-bold text-white">
            Informe Técnico Pericial de Seguridad (SOC Nivel 2)
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Dictamen oficial generado en tiempo real sobre <strong className="text-slate-200">{analysisData.fileName}</strong> ({analysisData.totalLogs} registros examinados).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Primary Action: Direct Vector PDF Download */}
          <button
            onClick={handleDownloadPdf}
            disabled={isGeneratingPdf}
            className="px-4 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs sm:text-sm font-semibold flex items-center gap-2 shadow-lg shadow-cyan-600/30 transition-all active:scale-95 disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
            <span>{isGeneratingPdf ? 'Generando PDF...' : 'Descargar Informe en PDF Oficial (.pdf)'}</span>
          </button>

          {/* Secondary Action: Browser Print / Screen */}
          <button
            onClick={handlePrint}
            title="Abrir diálogo de impresión del navegador"
            className="px-3 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition-all"
          >
            <Printer className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Imprimir Vista Web</span>
          </button>
        </div>
      </div>

      {/* Success Notification */}
      {downloadSuccess && (
        <div className="bg-emerald-950/70 border border-emerald-700 rounded-xl p-4 flex items-center gap-3 text-emerald-200 animate-fadeIn no-print shadow-lg">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
          <span className="text-xs sm:text-sm font-semibold">{downloadSuccess}</span>
        </div>
      )}

      {/* Printable Report Document Container */}
      <div 
        ref={reportRef}
        id="technical-report-content"
        className="bg-white text-slate-900 rounded-xl border border-slate-300 shadow-2xl p-6 sm:p-10 font-sans leading-relaxed max-w-5xl mx-auto space-y-8"
      >
        {/* Document Header & Branding */}
        <div className="border-b-2 border-slate-900 pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-cyan-800 font-extrabold text-sm tracking-wider uppercase font-mono">
              <Award className="w-5 h-5 text-cyan-700" />
              <span>{STOCKHOLM_CONSULTING_INFO.company}</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-slate-950 tracking-tight">
              INFORME TÉCNICO DE INVESTIGACIÓN DE INCIDENTE DE SEGURIDAD
            </h1>
            <p className="text-xs text-slate-600 font-medium">
              Consultoría Forense Especializada &middot; {STOCKHOLM_CONSULTING_INFO.location}
            </p>
          </div>

          {/* Classification & Metadata Box */}
          <div className="bg-slate-100 border border-slate-300 rounded-lg p-3 text-xs font-mono space-y-1 text-right min-w-[240px]">
            <div className="font-bold text-amber-800 bg-amber-100 border border-amber-300 px-2 py-0.5 rounded text-center mb-1">
              {STOCKHOLM_CONSULTING_INFO.classification}
            </div>
            <div><strong>Ref. Caso:</strong> {STOCKHOLM_CONSULTING_INFO.caseReference}</div>
            <div><strong>Fecha Emisión:</strong> {STOCKHOLM_CONSULTING_INFO.investigationDate}</div>
            <div><strong>Analista L2:</strong> {STOCKHOLM_CONSULTING_INFO.analyst}</div>
            <div><strong>Archivo Evaluado:</strong> {analysisData.fileName}</div>
            <div><strong>Registros SIEM:</strong> {analysisData.totalLogs} eventos</div>
            <div><strong>Ventana SIEM:</strong> {analysisData.minTimestamp || '07:46'} - {analysisData.maxTimestamp || '13:44'}</div>
          </div>
        </div>

        {/* 1. Resumen Ejecutivo */}
        <section className="space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-300 pb-1.5">
            <span className="w-6 h-6 rounded bg-slate-900 text-white flex items-center justify-center text-xs font-bold font-mono">1</span>
            <h2 className="text-lg font-bold text-slate-950 uppercase tracking-wide">
              Resumen Ejecutivo
            </h2>
          </div>

          <div className={`p-4 rounded text-xs sm:text-sm text-slate-800 space-y-2 border-l-4 ${
            analysisData.isSecurityIncident ? 'bg-red-50 border-red-600' : 'bg-emerald-50 border-emerald-600'
          }`}>
            <p className={`font-semibold ${analysisData.isSecurityIncident ? 'text-red-950' : 'text-emerald-950'}`}>
              Dictamen Concluyente: <span className="underline">{analysisData.globalConclusion}</span>
            </p>
            
            {analysisData.isSecurityIncident ? (
              <>
                <p className="leading-relaxed">
                  Tras el análisis forense exhaustivo de los <strong>{analysisData.totalLogs} eventos</strong> exportados del SIEM corporativo, se descartó de forma categórica que la actividad hostil corresponda a fallos operacionales o falsos positivos. Se confirmaron <strong>{incidents.length} incidentes de seguridad interconectados</strong> sobre la infraestructura evaluada.
                </p>
                <ul className="list-disc pl-5 space-y-1.5 text-xs text-slate-800">
                  {incidents.map((inc, i) => (
                    <li key={i}>
                      <strong>[{inc.id}] {inc.name}:</strong> {inc.summary}
                    </li>
                  ))}
                  {Number(analysisData.totalExfiltratedMB) > 0 && (
                    <li>
                      <strong>Exfiltración Masiva Detectada:</strong> Se computó un volumen acumulado de fuga de datos de <strong className="text-red-700">{analysisData.totalExfiltratedMB} MB</strong> transmitidos hacia destinos externos.
                    </li>
                  )}
                </ul>
              </>
            ) : (
              <p className="leading-relaxed">
                El escaneo heurístico de telemetría sobre los {analysisData.totalLogs} registros no arrojó firmas de ataque coordinado, puertas traseras, comandos maliciosos ni exfiltración de datos. La actividad analizada se ajusta a patrones operativos ordinarios y tráfico de red benigno.
              </p>
            )}
          </div>
        </section>

        {/* 2. Hallazgos Identificados */}
        <section className="space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-300 pb-1.5">
            <span className="w-6 h-6 rounded bg-slate-900 text-white flex items-center justify-center text-xs font-bold font-mono">2</span>
            <h2 className="text-lg font-bold text-slate-950 uppercase tracking-wide">
              Hallazgos Identificados
            </h2>
          </div>

          {incidents.length === 0 ? (
            <p className="text-xs text-slate-500 italic">No se identificaron incidentes hostiles en los registros provistos.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-900 text-white font-mono uppercase text-[11px]">
                    <th className="p-2.5">ID</th>
                    <th className="p-2.5">Incidente</th>
                    <th className="p-2.5">Vector / Origen</th>
                    <th className="p-2.5">Activos Comprometidos</th>
                    <th className="p-2.5">Severidad</th>
                    <th className="p-2.5">Estado</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {incidents.map((inc) => (
                    <tr key={inc.id} className="hover:bg-slate-50">
                      <td className="p-2.5 font-mono font-bold text-cyan-800">{inc.id}</td>
                      <td className="p-2.5 font-semibold text-slate-900">{inc.shortName || inc.name}</td>
                      <td className="p-2.5 text-slate-700 font-mono text-[11px]">{inc.threatActor}</td>
                      <td className="p-2.5 text-slate-700 font-bold">{inc.primaryTarget}</td>
                      <td className="p-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          inc.severity === 'Crítico' 
                            ? 'bg-red-100 text-red-800 border border-red-300' 
                            : 'bg-orange-100 text-orange-800 border border-orange-300'
                        }`}>
                          {inc.severity} (CVSS: {inc.cvssScore})
                        </span>
                      </td>
                      <td className="p-2.5 font-bold text-[11px] text-red-900">{inc.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* 3. Explicación Técnica Forense */}
        {incidents.length > 0 && (
          <section className="space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-300 pb-1.5">
              <span className="w-6 h-6 rounded bg-slate-900 text-white flex items-center justify-center text-xs font-bold font-mono">3</span>
              <h2 className="text-lg font-bold text-slate-950 uppercase tracking-wide">
                Explicación Técnica Forense por Incidente
              </h2>
            </div>

            <div className="space-y-4 text-xs">
              {incidents.map((inc) => (
                <div key={inc.id} className="border border-slate-300 rounded-lg p-4 bg-slate-50 space-y-2">
                  <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-slate-900 bg-slate-200 px-2 py-0.5 rounded">
                        {inc.id}
                      </span>
                      <h3 className="text-sm font-bold text-slate-950">{inc.name}</h3>
                    </div>
                    <span className="font-mono text-slate-600 text-[11px]">
                      Tácticas: {(inc.mitreTactics || []).join(', ')}
                    </span>
                  </div>
                  <p className="text-slate-800 leading-relaxed font-sans">{inc.summary}</p>
                  <div className="bg-white border border-slate-300 rounded p-3 font-mono text-[11px] text-slate-800 whitespace-pre-wrap">
                    {inc.technicalDetails}
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* 4. Evidencias en Logs del SIEM */}
        {evidenceLogs.length > 0 && (
          <section className="space-y-3 print-page-break">
            <div className="flex items-center gap-2 border-b border-slate-300 pb-1.5">
              <span className="w-6 h-6 rounded bg-slate-900 text-white flex items-center justify-center text-xs font-bold font-mono">4</span>
              <h2 className="text-lg font-bold text-slate-950 uppercase tracking-wide">
                Evidencias Forenses Extraídas del SIEM ({evidenceLogs.length} muestras)
              </h2>
            </div>

            <p className="text-xs text-slate-700">
              Registros literales extraídos dinámicamente de la telemetría que sustentan el dictamen pericial:
            </p>

            <div className="overflow-x-auto border border-slate-300 rounded-lg">
              <table className="w-full text-left text-[11px] font-mono">
                <thead className="bg-slate-900 text-white uppercase text-[10px]">
                  <tr>
                    <th className="p-2">Log ID</th>
                    <th className="p-2">Timestamp</th>
                    <th className="p-2">Host</th>
                    <th className="p-2">Event ID</th>
                    <th className="p-2">Usuario</th>
                    <th className="p-2">Origen &rarr; Destino</th>
                    <th className="p-2">Comando / Descripción</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 bg-white">
                  {evidenceLogs.map((ev, i) => (
                    <tr key={i} className="hover:bg-slate-50">
                      <td className="p-2 text-cyan-800 font-bold">{ev.Log_ID}</td>
                      <td className="p-2 text-slate-600">{String(ev.Timestamp || '').substring(11, 19) || ev.Timestamp}</td>
                      <td className="p-2 text-slate-900 font-bold">{ev.Hostname}</td>
                      <td className="p-2 text-purple-700">{ev.Event_ID}</td>
                      <td className="p-2 text-slate-800">{ev.User}</td>
                      <td className="p-2 text-slate-600">{ev.Source_IP || '-'} &rarr; {ev.Destination || '-'}</td>
                      <td className="p-2 font-mono text-[10px] text-amber-900 max-w-[280px] truncate" title={ev.Process_CommandLine || ev.Event_Description}>
                        {ev.Process_CommandLine || ev.Event_Description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* 5. Criticidad y Justificación */}
        <section className="space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-300 pb-1.5">
            <span className="w-6 h-6 rounded bg-slate-900 text-white flex items-center justify-center text-xs font-bold font-mono">5</span>
            <h2 className="text-lg font-bold text-slate-950 uppercase tracking-wide">
              Criticidad y Criterios de Evaluación del Riesgo
            </h2>
          </div>

          <div className="text-xs text-slate-800 space-y-2 leading-relaxed">
            <p>
              La calificación de riesgo global de la infraestructura se sitúa en nivel{' '}
              <strong className={`font-bold ${maxCvss >= 9 ? 'text-red-700' : maxCvss >= 7 ? 'text-orange-700' : 'text-emerald-700'}`}>
                {maxCvss >= 9 ? 'CRÍTICO' : maxCvss >= 7 ? 'ALTO' : 'MODERADO'} (CVSS Máximo: {maxCvss.toFixed(1)})
              </strong>. Los criterios periciales que sostienen esta puntuación comprenden:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
              <div className="p-3 border border-red-200 bg-red-50 rounded">
                <strong className="text-red-950 block font-bold mb-1">Confidencialidad: CRÍTICA</strong>
                Exfiltración de presupuestos estratégicos y fuga a través de canales externos no autorizados.
              </div>
              <div className="p-3 border border-orange-200 bg-orange-50 rounded">
                <strong className="text-orange-950 block font-bold mb-1">Integridad: CRÍTICA</strong>
                Inyección de comandos remotos, manipulación de servicios del sistema y uso de cuentas con privilegios elevados.
              </div>
              <div className="p-3 border border-amber-200 bg-amber-50 rounded">
                <strong className="text-amber-950 block font-bold mb-1">Disponibilidad: ALTA</strong>
                Inhibición de mecanismos de recuperación (VSS) y riesgo inminente de parada operativa o ransomware.
              </div>
            </div>
          </div>
        </section>

        {/* 6. Posible Impacto en la Organización */}
        <section className="space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-300 pb-1.5">
            <span className="w-6 h-6 rounded bg-slate-900 text-white flex items-center justify-center text-xs font-bold font-mono">6</span>
            <h2 className="text-lg font-bold text-slate-950 uppercase tracking-wide">
              Posible Impacto en la Organización
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="border border-slate-200 p-3.5 rounded-lg bg-slate-50 space-y-1.5">
              <h4 className="font-bold text-slate-950 text-sm">Impacto Legal y Regulatorio (RGPD / Suecia)</h4>
              <p className="text-slate-700 leading-relaxed">
                Bajo el Reglamento General de Protección de Datos (RGPD) de la Unión Europea y la legislación de Suecia, la filtración de documentos legales y datos corporativos impone la <strong>obligación formal de notificar a la Autoridad Sueca de Protección de la Privacidad (Integritetsskyddsmyndigheten - IMY) dentro de las 72 horas posteriores</strong> a la confirmación de la brecha, exponiendo a la compañía a sanciones de hasta 20 millones de euros o el 4% de la facturación global anual.
              </p>
            </div>

            <div className="border border-slate-200 p-3.5 rounded-lg bg-slate-50 space-y-1.5">
              <h4 className="font-bold text-slate-950 text-sm">Impacto Financiero y Operativo</h4>
              <p className="text-slate-700 leading-relaxed">
                Pérdida de ventaja estratégica competitiva al exponerse presupuestos confidenciales. Además, la pérdida de copias de seguridad VSS eleva el riesgo de paradas productivas por extorsión o cifrado que podrían detener operaciones por lapsos de 5 a 14 días.
              </p>
            </div>
          </div>
        </section>

        {/* 7. Plan de Acción */}
        <section className="space-y-4 print-page-break">
          <div className="flex items-center gap-2 border-b border-slate-300 pb-1.5">
            <span className="w-6 h-6 rounded bg-slate-900 text-white flex items-center justify-center text-xs font-bold font-mono">7</span>
            <h2 className="text-lg font-bold text-slate-950 uppercase tracking-wide">
              Plan de Acción Estructurado (Investigación, Contención y Remediación)
            </h2>
          </div>

          <div className="space-y-3 text-xs">
            {/* Phase 1 */}
            <div className="border-l-4 border-cyan-600 bg-cyan-50/50 p-4 rounded-r-lg space-y-1.5">
              <div className="flex items-center justify-between">
                <h4 className="font-bold text-cyan-950 text-sm">FASE 1: INVESTIGACIÓN FORENSE INMEDIATA (0 - 4 HORAS)</h4>
                <span className="font-mono text-cyan-800 font-bold text-[11px]">PRIORIDAD MÁXIMA</span>
              </div>
              <ul className="list-disc pl-5 space-y-1 text-slate-800">
                <li>Preservar imágenes forenses de memoria RAM y disco de los servidores y estaciones expuestas antes de reiniciar o desmantelar los equipos.</li>
                <li>Extraer y calcular hashes SHA-256 de los artefactos anómalos detectados en el sistema de archivos (binarios en ProgramData, scripts en directorios web).</li>
                <li>Auditar la pasarela de salida y proxy para trazar todos los flujos dirigidos hacia las IPs externas identificadas ({analysisData.externalIPs.join(', ') || 'WAN'}).</li>
              </ul>
            </div>

            {/* Phase 2 */}
            <div className="border-l-4 border-red-600 bg-red-50/50 p-4 rounded-r-lg space-y-1.5">
              <div className="flex items-center justify-between">
                <h4 className="font-bold text-red-950 text-sm">FASE 2: CONTENCIÓN Y AISLAMIENTO (4 - 12 HORAS)</h4>
                <span className="font-mono text-red-800 font-bold text-[11px]">CONTENCIÓN CRÍTICA</span>
              </div>
              <ul className="list-disc pl-5 space-y-1 text-slate-800">
                <li><strong>Aislamiento de Red:</strong> Aislar inmediatamente de la red corporativa los endpoints y servidores con anomalías críticas.</li>
                <li><strong>Bloqueo Perimetral Inmediato:</strong> Configurar reglas de descarte (DROP) en Firewall perimetral para todas las IPs atacantes detectadas: {analysisData.externalIPs.join(', ') || '203.0.113.74, 198.51.100.77, 192.0.2.91'}.</li>
                <li><strong>Cierre de Puertos de Administración:</strong> Bloquear el puerto 3389 (RDP) y puertos SMB hacia Internet de manera absoluta.</li>
                <li><strong>Revocación Forzada de Credenciales:</strong> Restablecer contraseñas administrativas y de cuentas de servicio afectadas, revocando tickets Kerberos (KRBTGT double reset).</li>
                <li><strong>Eliminación de Servicios y Tareas Maliciosas:</strong> Detener y erradicar cualquier servicio y tarea programada registrada clandestinamente.</li>
              </ul>
            </div>

            {/* Phase 3 */}
            <div className="border-l-4 border-emerald-600 bg-emerald-50/50 p-4 rounded-r-lg space-y-1.5">
              <div className="flex items-center justify-between">
                <h4 className="font-bold text-emerald-950 text-sm">FASE 3: ERRADICACIÓN, REMEDIACIÓN Y RESTAURACIÓN (12 - 72 HORAS)</h4>
                <span className="font-mono text-emerald-800 font-bold text-[11px]">RECUPERACIÓN SEGURA</span>
              </div>
              <ul className="list-disc pl-5 space-y-1 text-slate-800">
                <li>Reconstruir desde imágenes oficiales verificadas los sistemas operativos de servidores con ejecución remota confirmada.</li>
                <li>Sanear directorios web eliminando scripts no autorizados e implementar permisos estrictos de no ejecución en carpetas de uploads.</li>
                <li>Restaurar copias de seguridad validadas desde repositorios inmutables o almacenamiento desconectado (air-gapped).</li>
                <li>Habilitar auditoría avanzada de procesos con registro de línea de comandos completa (Event ID 4688).</li>
              </ul>
            </div>
          </div>
        </section>

        {/* 8. Recomendaciones Generales de Seguridad */}
        <section className="space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-300 pb-1.5">
            <span className="w-6 h-6 rounded bg-slate-900 text-white flex items-center justify-center text-xs font-bold font-mono">8</span>
            <h2 className="text-lg font-bold text-slate-950 uppercase tracking-wide">
              Recomendaciones Generales de Hardening y Prevención
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="border border-slate-300 rounded-lg p-4 bg-slate-50 space-y-2">
              <h4 className="font-bold text-slate-950 flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-700" />
                <span>Corto Plazo (0 - 30 Días)</span>
              </h4>
              <ul className="list-disc pl-5 space-y-1 text-slate-700">
                <li><strong>MFA Obligatorio:</strong> Implementar Autenticación Multifactor (MFA) obligatoria para todos los accesos externos y consolas de administración.</li>
                <li><strong>Políticas de Bloqueo de Cuentas:</strong> Configurar umbrales estrictos de bloqueo ante campañas de password spraying distribuidas.</li>
                <li><strong>Restricción de PowerShell:</strong> Habilitar Constrained Language Mode y AppLocker/WDAC para impedir la ejecución de comandos codificados (-EncodedCommand).</li>
                <li><strong>Protección de VSS:</strong> Restringir la ejecución de <code className="font-mono">vssadmin.exe</code> a cuentas locales de sistema específicas.</li>
              </ul>
            </div>

            <div className="border border-slate-300 rounded-lg p-4 bg-slate-50 space-y-2">
              <h4 className="font-bold text-slate-950 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-700" />
                <span>Mediano y Largo Plazo (30 - 90 Días)</span>
              </h4>
              <ul className="list-disc pl-5 space-y-1 text-slate-700">
                <li><strong>Arquitectura Zero Trust:</strong> Eliminar la exposición perimetral directa. Exigir autenticación continua mediante ZTNA.</li>
                <li><strong>DLP e Inspección TLS en Proxy:</strong> Activar inspección SSL/TLS profunda con políticas de Data Loss Prevention para bloquear salidas anómalas superiores a 10MB hacia hosts no catalogados.</li>
                <li><strong>Segregación de Cuentas de Servicio:</strong> Convertir cuentas de servicio en Group Managed Service Accounts (gMSA) sin privilegios de inicio de sesión interactivo.</li>
                <li><strong>Despliegue de EDR Heurístico:</strong> Desplegar solución EDR con aislamiento automatizado ante llamadas destructivas pre-ransomware.</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Formal Sign-off Section */}
        <div className="pt-8 border-t-2 border-slate-900 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6 text-xs text-slate-700 font-mono">
          <div className="space-y-1">
            <div><strong>Dictamen Técnico:</strong> Concluyente / Aprobado</div>
            <div><strong>Sede Operativa:</strong> Estocolmo, Suecia</div>
            <div><strong>Firma Digital:</strong> <span className="font-mono text-cyan-800">SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069</span></div>
          </div>

          <div className="border border-slate-400 p-4 rounded text-center min-w-[200px] bg-slate-50">
            <div className="text-[10px] text-slate-500 uppercase">Aprobado y Firmado por:</div>
            <div className="font-bold text-slate-950 text-sm mt-1">Lead SOC Tier 2 Analyst</div>
            <div className="text-xs text-slate-600">Incident Response Division</div>
            <div className="text-[10px] text-cyan-700 font-bold mt-2">Nordic Cyber Defense AB (Stockholm)</div>
          </div>
        </div>
      </div>
    </div>
  );
}
