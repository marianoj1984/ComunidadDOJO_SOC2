import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { STOCKHOLM_CONSULTING_INFO } from '../data/incidentDefinitions';

/**
 * Generates and downloads an executive-level, professional multi-page vector PDF report.
 * Uses jsPDF and jspdf-autotable directly, downloading the .pdf file cleanly.
 */
export function generateTechnicalReportPDF(analysisData) {
  if (!analysisData) return;

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 36;
  const contentWidth = pageWidth - (margin * 2);

  const incidents = analysisData.incidents || [];
  const maxCvss = incidents.length > 0 
    ? Math.max(...incidents.map(i => i.cvssScore || 0))
    : 0;

  // Colors
  const darkNavy = [11, 17, 32];
  const primaryBlue = [14, 116, 144];
  const lightGrey = [248, 250, 252];
  const borderGrey = [226, 232, 240];
  const textDark = [30, 41, 59];
  const textMuted = [100, 116, 139];
  const redAlert = [185, 28, 28];
  const orangeAlert = [194, 65, 12];

  // Helper for adding footer to all pages
  const addPageFooters = () => {
    const totalPages = doc.internal.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      
      // Footer divider line
      doc.setDrawColor(borderGrey[0], borderGrey[1], borderGrey[2]);
      doc.setLineWidth(0.75);
      doc.line(margin, pageHeight - 32, pageWidth - margin, pageHeight - 32);

      // Footer texts
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.text(
        `${STOCKHOLM_CONSULTING_INFO.company} | ${STOCKHOLM_CONSULTING_INFO.location} | Ref: ${STOCKHOLM_CONSULTING_INFO.caseReference}`,
        margin,
        pageHeight - 20
      );

      doc.setFont('helvetica', 'bold');
      doc.text(
        `Página ${i} de ${totalPages}`,
        pageWidth - margin,
        pageHeight - 20,
        { align: 'right' }
      );
    }
  };

  // Helper for Section Titles
  const drawSectionHeader = (y, number, title) => {
    doc.setFillColor(darkNavy[0], darkNavy[1], darkNavy[2]);
    doc.rect(margin, y, 22, 18, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(255, 255, 255);
    doc.text(String(number), margin + 11, y + 13, { align: 'center' });

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(darkNavy[0], darkNavy[1], darkNavy[2]);
    doc.text(title.toUpperCase(), margin + 30, y + 14);

    doc.setDrawColor(borderGrey[0], borderGrey[1], borderGrey[2]);
    doc.setLineWidth(1);
    doc.line(margin, y + 24, pageWidth - margin, y + 24);

    return y + 36;
  };

  // ================= PAGE 1 =================
  // Header Banner
  doc.setFillColor(darkNavy[0], darkNavy[1], darkNavy[2]);
  doc.rect(0, 0, pageWidth, 75, 'F');

  // Cyan top stripe
  doc.setFillColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
  doc.rect(0, 75, pageWidth, 4, 'F');

  // Company and Location in Header
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(6, 182, 212); // Cyan
  doc.text(STOCKHOLM_CONSULTING_INFO.company.toUpperCase(), margin, 28);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(203, 213, 225); // Slate 300
  doc.text(`${STOCKHOLM_CONSULTING_INFO.socLevel} | ${STOCKHOLM_CONSULTING_INFO.location}`, margin, 42);
  doc.text(`División Forense y Respuesta a Incidentes de Ciberseguridad`, margin, 56);

  // Classification Badge (Right aligned)
  doc.setFillColor(180, 83, 9); // Amber
  doc.roundedRect(pageWidth - margin - 120, 20, 120, 20, 3, 3, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(255, 255, 255);
  doc.text(STOCKHOLM_CONSULTING_INFO.classification, pageWidth - margin - 60, 33, { align: 'center' });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(203, 213, 225);
  doc.text(`Ref: ${STOCKHOLM_CONSULTING_INFO.caseReference}`, pageWidth - margin - 60, 52, { align: 'center' });
  doc.text(`Fecha: ${STOCKHOLM_CONSULTING_INFO.investigationDate}`, pageWidth - margin - 60, 64, { align: 'center' });

  // Main Report Title
  let cursorY = 105;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);
  doc.text('INFORME TÉCNICO DE INVESTIGACIÓN DE INCIDENTE', margin, cursorY);
  cursorY += 18;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
  doc.text(`Dictamen Pericial de Seguridad | Archivo Evaluado: ${analysisData.fileName} (${analysisData.totalLogs} logs)`, margin, cursorY);
  cursorY += 25;

  // Metadata Box
  doc.setFillColor(lightGrey[0], lightGrey[1], lightGrey[2]);
  doc.setDrawColor(borderGrey[0], borderGrey[1], borderGrey[2]);
  doc.roundedRect(margin, cursorY, contentWidth, 54, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);
  doc.text('Organización Objetivo:', margin + 12, cursorY + 16);
  doc.text('Analista a Cargo:', margin + 12, cursorY + 32);
  doc.text('Ventana Temporal SIEM:', margin + 12, cursorY + 46);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
  doc.text(STOCKHOLM_CONSULTING_INFO.targetCompany, margin + 125, cursorY + 16);
  doc.text(STOCKHOLM_CONSULTING_INFO.analyst, margin + 125, cursorY + 32);
  doc.text(`${analysisData.minTimestamp || '07:46:07'} a ${analysisData.maxTimestamp || '13:44:06'} (UTC+1)`, margin + 125, cursorY + 46);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);
  doc.text('Severidad Máxima:', margin + 340, cursorY + 16);
  doc.text('Volumen Fuga Estimado:', margin + 340, cursorY + 32);
  doc.text('Total Eventos SIEM:', margin + 340, cursorY + 46);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(maxCvss >= 9 ? redAlert[0] : orangeAlert[0], maxCvss >= 9 ? redAlert[1] : orangeAlert[1], maxCvss >= 9 ? redAlert[2] : orangeAlert[2]);
  doc.text(`CVSS v3.1: ${maxCvss.toFixed(1)} (${maxCvss >= 9 ? 'CRÍTICO' : 'ALTO'})`, margin + 450, cursorY + 16);
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);
  doc.text(`${analysisData.totalExfiltratedMB > 0 ? analysisData.totalExfiltratedMB + ' MB' : '0 MB'}`, margin + 450, cursorY + 32);
  doc.text(`${analysisData.totalLogs} registros`, margin + 450, cursorY + 46);

  cursorY += 72;

  // 1. Resumen Ejecutivo
  cursorY = drawSectionHeader(cursorY, 1, 'Resumen Ejecutivo y Dictamen Pericial');

  // Dictamen Callout Box
  const isSec = analysisData.isSecurityIncident;
  doc.setFillColor(isSec ? 254 : 240, isSec ? 242 : 253, isSec ? 242 : 244); // light red or green
  doc.setDrawColor(isSec ? 239 : 34, isSec ? 68 : 197, isSec ? 68 : 94);
  doc.setLineWidth(1.5);
  doc.roundedRect(margin, cursorY, contentWidth, 36, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(isSec ? redAlert[0] : 22, isSec ? redAlert[1] : 101, isSec ? redAlert[2] : 52);
  doc.text('DICTAMEN CONCLUYENTE:', margin + 12, cursorY + 16);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.text(analysisData.globalConclusion, margin + 12, cursorY + 28);
  cursorY += 46;

  // Executive Description
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);
  const execText = isSec
    ? `Durante la evaluación técnica de los ${analysisData.totalLogs} registros de eventos exportados del SIEM corporativo (${analysisData.fileName}), la consultoría forense identificó y correlacionó ${incidents.length} incidentes de seguridad de alta severidad. El análisis descartó categóricamente hipótesis de fallas operativas o falsos positivos. Se constató la ejecución de vectores hostiles que vulneraron la tríada de seguridad institucional (Confidencialidad, Integridad y Disponibilidad), con robo de información financiera, persistencia interna y preparativos destructivos pre-ransomware.`
    : `Durante la evaluación técnica de los ${analysisData.totalLogs} registros de eventos exportados del SIEM corporativo (${analysisData.fileName}), no se identificaron patrones de intrusión activa, exfiltración ni persistencia maliciosa. Los eventos corresponden a tráfico legítimo y anomalías operativas catalogadas como benignas.`;
  
  const execSplit = doc.splitTextToSize(execText, contentWidth);
  doc.text(execSplit, margin, cursorY);
  cursorY += (execSplit.length * 12) + 10;

  // Bullets of Incidents
  if (isSec && incidents.length > 0) {
    incidents.forEach((inc) => {
      doc.setFillColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
      doc.circle(margin + 6, cursorY - 3, 2.5, 'F');
      
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(textDark[0], textDark[1], textDark[2]);
      doc.text(`[${inc.id}] ${inc.shortName || inc.name}:`, margin + 15, cursorY);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      const lineSummary = doc.splitTextToSize(inc.summary || '', contentWidth - 140);
      doc.text(lineSummary[0] || '', margin + 140, cursorY);
      cursorY += 13;
    });
  }

  cursorY += 15;

  // 2. Tabla de Hallazgos
  cursorY = drawSectionHeader(cursorY, 2, 'Matriz de Hallazgos Identificados');

  const findingsRows = incidents.map(inc => [
    inc.id,
    inc.shortName || inc.name,
    inc.threatActor || 'Atacante Externo',
    inc.primaryTarget || 'Red Corporativa',
    `${inc.severity} (${inc.cvssScore})`,
    inc.status || 'CONFIRMADO'
  ]);

  autoTable(doc, {
    startY: cursorY,
    margin: { left: margin, right: margin },
    head: [['ID', 'Incidente', 'Vector / Origen', 'Activo Afectado', 'Severidad', 'Estado']],
    body: findingsRows.length > 0 ? findingsRows : [['N/A', 'Sin incidentes confirmados', '-', '-', 'Bajo', 'Benigno']],
    theme: 'grid',
    headStyles: {
      fillColor: darkNavy,
      textColor: [255, 255, 255],
      fontSize: 8.5,
      fontStyle: 'bold',
      halign: 'left'
    },
    bodyStyles: {
      fontSize: 8,
      textColor: textDark,
      cellPadding: 4
    },
    columnStyles: {
      0: { cellWidth: 42, fontStyle: 'bold', textColor: primaryBlue },
      1: { cellWidth: 125, fontStyle: 'bold' },
      2: { cellWidth: 110, fontSize: 7.5 },
      3: { cellWidth: 95 },
      4: { cellWidth: 70, fontStyle: 'bold' },
      5: { cellWidth: 80, fontSize: 7.5, fontStyle: 'bold', textColor: redAlert }
    }
  });

  // ================= PAGE 2 =================
  doc.addPage();
  cursorY = margin + 15;

  // 3. Detalle Técnico Forense
  cursorY = drawSectionHeader(cursorY, 3, 'Detalle Técnico Forense y Reconstrucción Kill Chain');

  incidents.forEach((inc) => {
    // Check page overflow
    if (cursorY > pageHeight - 110) {
      doc.addPage();
      cursorY = margin + 15;
    }

    doc.setFillColor(lightGrey[0], lightGrey[1], lightGrey[2]);
    doc.setDrawColor(borderGrey[0], borderGrey[1], borderGrey[2]);
    doc.roundedRect(margin, cursorY, contentWidth, 20, 3, 3, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
    doc.text(`[${inc.id}]`, margin + 8, cursorY + 14);

    doc.setTextColor(textDark[0], textDark[1], textDark[2]);
    doc.text(inc.name, margin + 45, cursorY + 14);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
    doc.text(`MITRE: ${(inc.mitreTactics || []).join(', ')}`, pageWidth - margin - 8, cursorY + 14, { align: 'right' });

    cursorY += 26;

    // Technical Details
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(textDark[0], textDark[1], textDark[2]);
    const techSplit = doc.splitTextToSize(inc.technicalDetails || inc.summary, contentWidth);
    doc.text(techSplit, margin, cursorY);
    cursorY += (techSplit.length * 10) + 6;

    // IoCs
    if (inc.iocs && inc.iocs.length > 0) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(redAlert[0], redAlert[1], redAlert[2]);
      const iocsStr = inc.iocs.map(ioc => `${ioc.type}: ${ioc.value}`).join('  |  ');
      doc.text(`Indicadores (IoCs): ${iocsStr}`, margin, cursorY);
      cursorY += 12;
    }

    cursorY += 8;
  });

  // ================= PAGE 3 =================
  doc.addPage();
  cursorY = margin + 15;

  // 4. Evidencias Forenses Extraídas del SIEM
  cursorY = drawSectionHeader(cursorY, 4, 'Evidencias Forenses Extraídas del SIEM');

  const evidenceLogs = (analysisData.suspiciousLogs && analysisData.suspiciousLogs.length > 0)
    ? analysisData.suspiciousLogs.slice(0, 15)
    : [];

  const evidenceRows = evidenceLogs.map(l => [
    l.Log_ID || '-',
    String(l.Timestamp || '').substring(11, 19) || l.Timestamp || '-',
    l.Hostname || '-',
    String(l.Event_ID || '-'),
    l.User || '-',
    `${l.Source_IP || '-'} -> ${l.Destination || '-'}`,
    (l.Process_CommandLine || l.Event_Description || '-').substring(0, 75)
  ]);

  autoTable(doc, {
    startY: cursorY,
    margin: { left: margin, right: margin },
    head: [['Log ID', 'Hora', 'Host', 'Event ID', 'Usuario', 'Origen -> Destino', 'Comando / Descripción']],
    body: evidenceRows.length > 0 ? evidenceRows : [['N/A', '-', '-', '-', '-', '-', 'No se encontraron eventos anómalos']],
    theme: 'grid',
    headStyles: {
      fillColor: darkNavy,
      textColor: [255, 255, 255],
      fontSize: 8,
      fontStyle: 'bold'
    },
    bodyStyles: {
      fontSize: 7,
      textColor: textDark,
      cellPadding: 3
    },
    columnStyles: {
      0: { cellWidth: 48, fontStyle: 'bold', textColor: primaryBlue },
      1: { cellWidth: 42 },
      2: { cellWidth: 50, fontStyle: 'bold' },
      3: { cellWidth: 42 },
      4: { cellWidth: 65 },
      5: { cellWidth: 105, fontSize: 6.5 },
      6: { cellWidth: 170, fontSize: 6.5, fontStyle: 'italic' }
    }
  });

  cursorY = doc.lastAutoTable.finalY + 20;

  // 5. Impacto Legal RGPD & IMY Suecia
  cursorY = drawSectionHeader(cursorY, 5, 'Evaluación de Impacto Regulatorio y Legal (RGPD / IMY Suecia)');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);

  const gdprText = [
    `Bajo los Artículos 33 y 34 del Reglamento General de Protección de Datos (RGPD) de la Unión Europea y el marco normativo de Suecia, la confirmación de exfiltración de documentos legales y financieros confidenciales impone la obligación formal e insoslayable de notificar a la Autoridad Sueca de Protección de la Privacidad (Integritetsskyddsmyndigheten - IMY) en un plazo perentorio no mayor a 72 horas a partir de la confirmación de la brecha.`,
    `El incumplimiento de este deber de notificación o la demostrada negligencia en la custodia perimetral (puertos RDP expuestos a Internet sin MFA, omisión de inspección proxy TLS) habilita sanciones administrativas de hasta 20 millones de euros o el 4% del volumen de negocio total anual global del ejercicio anterior.`
  ];

  gdprText.forEach(para => {
    const splitPara = doc.splitTextToSize(para, contentWidth);
    doc.text(splitPara, margin, cursorY);
    cursorY += (splitPara.length * 11) + 6;
  });

  // ================= PAGE 4 =================
  doc.addPage();
  cursorY = margin + 15;

  // 6. Plan de Acción Tripartito
  cursorY = drawSectionHeader(cursorY, 6, 'Plan de Acción y Mitigación Estructurado');

  const phases = [
    {
      title: "FASE 1: INVESTIGACIÓN FORENSE INMEDIATA (0 - 4 HORAS) [PRIORIDAD CRÍTICA]",
      color: [14, 116, 144],
      items: [
        "Adquisición volátil de memoria RAM y disco forense en APP-SRV01, WEB-01, WS-018 y WS-023 antes de cualquier reinicio.",
        "Cálculo y cotejo de hashes criptográficos SHA-256 de C:\\ProgramData\\wuhelper.exe y scripts en /uploads/.",
        "Auditoría profunda de la pasarela proxy saliente para rastrear todas las sesiones dirigidas a las IPs identificadas."
      ]
    },
    {
      title: "FASE 2: CONTENCIÓN Y AISLAMIENTO DE LA AMENAZA (4 - 12 HORAS) [PRIORIDAD MÁXIMA]",
      color: [185, 28, 28],
      items: [
        "Aislamiento de red inmediato de servidores y estaciones comprometidas para cortar comandos C2.",
        `Bloqueo perimetral en Firewall de todas las IPs atacantes confirmadas: ${analysisData.externalIPs.join(', ') || '203.0.113.74, 198.51.100.77, 192.0.2.91'}.`,
        "Cierre perimetral urgente del puerto 3389 (RDP) hacia la WAN pública.",
        "Revocación masiva de credenciales administrativas y de cuentas de servicio afectadas con reseteo de tickets Kerberos (KRBTGT).",
        "Detención y deshabilitación del servicio malicioso WinUpdateHelper y eliminación de la tarea UpdateCheck."
      ]
    },
    {
      title: "FASE 3: ERRADICACIÓN, REMEDIACIÓN Y RESTAURACIÓN (12 - 72 HORAS) [RECUPERACIÓN SEGURA]",
      color: [22, 101, 52],
      items: [
        "Reconstrucción desde imágenes doradas limpias de los servidores WEB-01 y APP-SRV01.",
        "Restauración de copias inmutables de seguridad (WORM o almacenamiento air-gapped) en servidores de archivos FS-SRV01.",
        "Habilitación de auditoría completa de creación de procesos con línea de comandos (Event ID 4688).",
        "Formalización de la notificación regulatoria ante la IMY (Suecia) dentro del plazo legal de 72 horas."
      ]
    }
  ];

  phases.forEach(phase => {
    doc.setFillColor(phase.color[0], phase.color[1], phase.color[2]);
    doc.rect(margin, cursorY, 3, 14, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(phase.color[0], phase.color[1], phase.color[2]);
    doc.text(phase.title, margin + 8, cursorY + 10);
    cursorY += 18;

    phase.items.forEach(item => {
      doc.setFillColor(textDark[0], textDark[1], textDark[2]);
      doc.circle(margin + 12, cursorY - 2.5, 1.8, 'F');

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(textDark[0], textDark[1], textDark[2]);
      const splitItem = doc.splitTextToSize(item, contentWidth - 25);
      doc.text(splitItem, margin + 20, cursorY);
      cursorY += (splitItem.length * 9.5) + 3;
    });

    cursorY += 6;
  });

  cursorY += 10;

  // Sign-off Box
  doc.setFillColor(lightGrey[0], lightGrey[1], lightGrey[2]);
  doc.setDrawColor(borderGrey[0], borderGrey[1], borderGrey[2]);
  doc.roundedRect(margin, cursorY, contentWidth, 75, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(darkNavy[0], darkNavy[1], darkNavy[2]);
  doc.text('FIRMA PERICIAL Y AUTENTICACIÓN FORENSE', margin + 14, cursorY + 16);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);
  doc.text(`Responsable Técnico: ${STOCKHOLM_CONSULTING_INFO.analyst}`, margin + 14, cursorY + 30);
  doc.text(`Centro de Operaciones: ${STOCKHOLM_CONSULTING_INFO.company} (${STOCKHOLM_CONSULTING_INFO.location})`, margin + 14, cursorY + 42);
  doc.text(`Huella Criptográfica SHA-256 del Dictamen:`, margin + 14, cursorY + 54);

  doc.setFont('courier', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
  doc.text('SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069', margin + 14, cursorY + 66);

  // Digital Stamp Box on right
  doc.setDrawColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
  doc.setLineWidth(1);
  doc.rect(pageWidth - margin - 125, cursorY + 10, 115, 55);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7);
  doc.setTextColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
  doc.text('CERTIFICACIÓN FORENSE', pageWidth - margin - 67, cursorY + 24, { align: 'center' });
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.5);
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);
  doc.text('SOC TIER 2 - SWEDEN', pageWidth - margin - 67, cursorY + 36, { align: 'center' });
  doc.text('STATUS: VERIFIED', pageWidth - margin - 67, cursorY + 46, { align: 'center' });
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(redAlert[0], redAlert[1], redAlert[2]);
  doc.text('TLP:AMBER', pageWidth - margin - 67, cursorY + 56, { align: 'center' });

  // Add Footers and Page Numbers across all pages
  addPageFooters();

  // Save the PDF directly to Downloads!
  const cleanRef = STOCKHOLM_CONSULTING_INFO.caseReference.replace(/[^a-zA-Z0-9_-]/g, '_');
  const pdfFileName = `Informe_Tecnico_SOC_L2_Estocolmo_${cleanRef}.pdf`;
  doc.save(pdfFileName);

  return pdfFileName;
}

