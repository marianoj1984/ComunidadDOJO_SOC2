import React, { useState } from 'react';
import {
  Download,
  Printer,
  FileText,
  FileSpreadsheet,
  Code,
  CheckCircle2,
  Share2,
  ShieldCheck,
  Building2,
  Lock,
  Layers,
  Sparkles,
  UploadCloud
} from 'lucide-react';
import { downloadFile } from '../utils/analyzer';
import { STOCKHOLM_CONSULTING_INFO } from '../data/incidentDefinitions';
import { generateTechnicalReportPDF } from '../utils/pdfGenerator';

export default function Module6Export({ analysisData, onNavigateToUpload }) {
  const [downloadSuccess, setDownloadSuccess] = useState(null);

  if (!analysisData) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center space-y-4 max-w-2xl mx-auto shadow-2xl">
        <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400">
          <Download className="w-8 h-8" />
        </div>
        <h3 className="text-xl font-bold text-white">Esperando Ingesta de Datos SIEM</h3>
        <p className="text-sm text-slate-400 leading-relaxed">
          No hay datos procesados para exportar. Ingeste un archivo de logs en el Módulo 1 para habilitar la generación y descarga en tiempo real de reportes en PDF, paquetes de IoCs en CSV/JSON y documentación en Markdown.
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

  // Generate and download genuine PDF
  const handleDownloadPDF = () => {
    try {
      const filename = generateTechnicalReportPDF(analysisData);
      setDownloadSuccess(`Informe técnico descargado exitosamente como archivo PDF: ${filename}`);
      setTimeout(() => setDownloadSuccess(null), 5000);
    } catch (err) {
      console.error("Error al generar PDF:", err);
    }
  };

  const handlePrintPDF = () => {
    window.print();
  };

  // Compile all IoCs dynamically from detected incidents
  const allIoCs = (analysisData.incidents || []).flatMap(inc =>
    (inc.iocs || []).map(ioc => ({
      incidentId: inc.id,
      incidentName: inc.shortName || inc.name,
      severity: inc.severity,
      type: ioc.type,
      iocValue: ioc.value,
      description: ioc.description
    }))
  );

  const handleExportIoCsCSV = () => {
    let csv = "Incident_ID,Incident_Name,Severity,IoC_Type,IoC_Value,Description\n";
    allIoCs.forEach(i => {
      csv += `"${i.incidentId}","${i.incidentName}","${i.severity}","${i.type}","${i.iocValue}","${i.description}"\n`;
    });
    downloadFile(csv, `IoCs_Incident_Investigation_${STOCKHOLM_CONSULTING_INFO.caseReference}.csv`, 'text/csv');
    setDownloadSuccess(`Listado de IoCs (${allIoCs.length} registros) descargado en formato CSV.`);
    setTimeout(() => setDownloadSuccess(null), 4000);
  };

  const handleExportIoCsJSON = () => {
    const jsonOutput = JSON.stringify({
      reportReference: STOCKHOLM_CONSULTING_INFO.caseReference,
      generatedAt: new Date().toISOString(),
      organization: STOCKHOLM_CONSULTING_INFO.company,
      analyzedFile: analysisData.fileName,
      totalLogsEvaluated: analysisData.totalLogs,
      iocsCount: allIoCs.length,
      iocs: allIoCs
    }, null, 2);
    downloadFile(jsonOutput, `IoCs_STIX_Format_${STOCKHOLM_CONSULTING_INFO.caseReference}.json`, 'application/json');
    setDownloadSuccess("Listado de IoCs descargado en formato JSON estructurado.");
    setTimeout(() => setDownloadSuccess(null), 4000);
  };

  const handleExportMarkdownReport = () => {
    let md = `# INFORME TÉCNICO DE INVESTIGACIÓN DE INCIDENTES DE SEGURIDAD (SOC L2)
**Organización Emisora:** ${STOCKHOLM_CONSULTING_INFO.company} (${STOCKHOLM_CONSULTING_INFO.location})  
**Referencia:** ${STOCKHOLM_CONSULTING_INFO.caseReference}  
**Fecha:** ${STOCKHOLM_CONSULTING_INFO.investigationDate}  
**Archivo Evaluado:** ${analysisData.fileName} (${analysisData.totalLogs} logs)  
**Clasificación:** ${STOCKHOLM_CONSULTING_INFO.classification}  
**Dictamen Concluyente:** ${analysisData.globalConclusion}  

---

## 1. RESUMEN EJECUTIVO
${analysisData.isSecurityIncident
        ? `Se confirman ${analysisData.incidents.length} incidentes de seguridad interconectados sobre la infraestructura corporativa tras el análisis pericial de ${analysisData.totalLogs} eventos de registro. Se descarta cualquier hipótesis de falso positivo.\n\nPrincipales vectores constatados:\n` +
        analysisData.incidents.map(i => `- **[${i.id}] ${i.name}:** ${i.summary}`).join('\n') +
        (Number(analysisData.totalExfiltratedMB) > 0 ? `\n- **Volumen de Exfiltración:** Se verificó la fuga de ~${analysisData.totalExfiltratedMB} MB de información.` : '')
        : `El análisis forense de los ${analysisData.totalLogs} eventos concluye que no existen incidentes de seguridad confirmados ni indicios de compromiso persistente. La actividad evaluada se clasifica como benigna o falsos positivos operativos.`
      }

---

## 2. HALLAZGOS Y EVIDENCIAS FORENSES

`;
    (analysisData.incidents || []).forEach(inc => {
      md += `### [${inc.id}] ${inc.name}\n`;
      md += `- **Severidad:** ${inc.severity} (CVSS: ${inc.cvssScore})\n`;
      md += `- **Activo Objetivo:** ${inc.primaryTarget}\n`;
      md += `- **Actor de Amenaza:** ${inc.threatActor}\n`;
      md += `- **Ventana Temporal:** ${inc.timeframe}\n`;
      md += `- **Tácticas MITRE:** ${(inc.mitreTactics || []).join(', ')}\n`;
      md += `- **Resumen:** ${inc.summary}\n\n`;
      md += `**Detalle Técnico:**\n${inc.technicalDetails}\n\n`;
      md += `**IoCs Asociados:**\n`;
      (inc.iocs || []).forEach(ioc => {
        md += `- ${ioc.type}: \`${ioc.value}\` (${ioc.description})\n`;
      });
      md += `\n---\n\n`;
    });

    md += `## 3. PLAN DE ACCIÓN Y RECOMENDACIONES
### Fase 1: Investigación Inmediata (0-4h)
- Adquisición de imágenes de memoria y disco de los activos involucrados.
- Extracción y cotejo de hashes de malware y artefactos identificados.

### Fase 2: Contención y Aislamiento (4-12h)
- Aislamiento de red de los equipos comprometidos.
- Bloqueo en Firewall de las IPs detectadas: ${analysisData.externalIPs.join(', ') || 'N/A'}.
- Cierre perimetral del puerto 3389 (RDP) y accesos administrativos sin MFA.
- Revocación forzada de contraseñas de cuentas afectadas y reset de tickets Kerberos.

### Fase 3: Remediación y Restauración (12-72h)
- Reconstrucción desde medios verificados de los servidores vulnerados.
- Restauración de copias inmutables de servidores de archivos.
- Notificación formal al regulador sueco de privacidad (IMY) bajo el RGPD (plazo 72 horas) ante confirmación de fuga de datos.

*Informe emitido en Estocolmo por Lead SOC Analyst Level 2.*
`;

    downloadFile(md, `Informe_Tecnico_SOC_L2_${STOCKHOLM_CONSULTING_INFO.caseReference}.md`, 'text/markdown');
    setDownloadSuccess("Informe técnico completo descargado en formato Markdown (.md).");
    setTimeout(() => setDownloadSuccess(null), 4000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-900 to-slate-800 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono font-semibold uppercase tracking-wider mb-1">
          <Download className="w-4 h-4" />
          <span>Módulo 6: Centro de Exportación de Resultados & Entregables</span>
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-bold text-white">
              Exportación del Informe Técnico & Paquetes de Inteligencia de Amenazas
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              Descargue el informe pericial estructurado directamente en archivo PDF (.pdf) o exporte los Indicadores de Compromiso (IoCs) para ingesta directa en Firewalls, EDRs y plataformas SIEM.
            </p>
          </div>
          <div className="text-right flex-shrink-0">
            <span className="inline-block px-3 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-cyan-300">
              Datos: <strong className="text-white">{analysisData.fileName}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Success Notification */}
      {downloadSuccess && (
        <div className="bg-emerald-950/70 border border-emerald-700 rounded-xl p-4 flex items-center gap-3 text-emerald-200 animate-fadeIn shadow-lg">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
          <span className="text-xs sm:text-sm font-semibold">{downloadSuccess}</span>
        </div>
      )}

      {/* Main Export Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {/* Card 1: Official PDF Report Download */}
        <div className="bg-slate-900 border-2 border-cyan-500/50 hover:border-cyan-400 rounded-xl p-6 flex flex-col justify-between shadow-xl shadow-cyan-950/20 transition-all space-y-4">
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-xl bg-cyan-950 border border-cyan-700 flex items-center justify-center text-cyan-400 shadow-md">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono font-bold text-cyan-400 tracking-wider">Entregable Oficial Directo</span>
              <h3 className="text-base font-bold text-white mt-0.5">Informe Técnico Formal en PDF (.pdf)</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Descarga directa del documento pericial completo en PDF vectorial oficial: membrete de Estocolmo, tablas de evidencias SIEM, análisis RGPD y plan de acción estructurado.
            </p>
          </div>

          <div className="space-y-2 pt-2">
            <button
              onClick={handleDownloadPDF}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs sm:text-sm flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/30 transition-all active:scale-95"
            >
              <Download className="w-4 h-4" />
              <span>Descargar Archivo PDF (.pdf)</span>
            </button>
            <button
              onClick={handlePrintPDF}
              className="w-full py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 text-xs flex items-center justify-center gap-1.5 transition-all"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>O abrir vista de impresión</span>
            </button>
          </div>
        </div>

        {/* Card 2: IoCs Package CSV */}
        <div className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-6 flex flex-col justify-between shadow-xl transition-all space-y-4">
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-xl bg-amber-950 border border-amber-800 flex items-center justify-center text-amber-400 shadow-md">
              <FileSpreadsheet className="w-6 h-6" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono font-bold text-amber-400 tracking-wider">Threat Intelligence</span>
              <h3 className="text-base font-bold text-white mt-0.5">Matriz de IoCs (Formato CSV)</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Descarga estructurada de todas las direcciones IP atacantes, rutas de malware, scripts, URIs y nombres de servicios para bloqueo perimetral en EDR / Firewall.
            </p>
          </div>

          <button
            onClick={handleExportIoCsCSV}
            className="w-full py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white font-semibold text-xs sm:text-sm flex items-center justify-center gap-2 border border-slate-700 transition-all active:scale-95"
          >
            <Download className="w-4 h-4 text-amber-400" />
            <span>Descargar IoCs en CSV ({allIoCs.length} IoCs)</span>
          </button>
        </div>

        {/* Card 3: IoCs JSON & STIX 2.1 */}
        <div className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-6 flex flex-col justify-between shadow-xl transition-all space-y-4">
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-xl bg-purple-950 border border-purple-800 flex items-center justify-center text-purple-400 shadow-md">
              <Code className="w-6 h-6" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono font-bold text-purple-400 tracking-wider">Integración SIEM / SOAR</span>
              <h3 className="text-base font-bold text-white mt-0.5">Indicadores en JSON (STIX Ready)</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Exportación en formato JSON normalizado para alimentar herramientas de orquestación de seguridad (SOAR), MISP y motores de detección automatizados.
            </p>
          </div>

          <button
            onClick={handleExportIoCsJSON}
            className="w-full py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white font-semibold text-xs sm:text-sm flex items-center justify-center gap-2 border border-slate-700 transition-all active:scale-95"
          >
            <Download className="w-4 h-4 text-purple-400" />
            <span>Descargar IoCs en JSON</span>
          </button>
        </div>

        {/* Card 4: Full Report in Markdown */}
        <div className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-6 flex flex-col justify-between shadow-xl transition-all space-y-4">
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-xl bg-emerald-950 border border-emerald-800 flex items-center justify-center text-emerald-400 shadow-md">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono font-bold text-emerald-400 tracking-wider">Documentación Técnica</span>
              <h3 className="text-base font-bold text-white mt-0.5">Informe Técnico en Markdown (.md)</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Texto estructurado en formato Markdown estándar para su inclusión en repositorios internos de documentación, Confluence, GitHub o wikis de ingeniería.
            </p>
          </div>

          <button
            onClick={handleExportMarkdownReport}
            className="w-full py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white font-semibold text-xs sm:text-sm flex items-center justify-center gap-2 border border-slate-700 transition-all active:scale-95"
          >
            <Download className="w-4 h-4 text-emerald-400" />
            <span>Descargar Informe en .md</span>
          </button>
        </div>

        {/* Card 5: Deliverables Checklist for Stockholm Client */}
        <div className="md:col-span-2 bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-xl p-6 space-y-3">
          <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <span>Estado de Telemetría Forense & Entregables en Vivo</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-300 font-mono">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <span>Módulo 1: Archivo evaluado ({analysisData.totalLogs} logs)</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <span>Módulo 2: {analysisData.incidents.length} Incidentes / MITRE ATT&CK</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <span>Módulo 3: Telemetría & Distribuciones en Vivo</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <span>Módulo 4: Evaluación de Riesgo CVSS v3.1 & CIA</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <span>Módulo 5: Dictamen Pericial Oficial Preparado</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <span>Módulo 6: {allIoCs.length} IoCs Listos para Exportación</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
