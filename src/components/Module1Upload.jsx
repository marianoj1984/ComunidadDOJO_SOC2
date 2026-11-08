import React, { useState, useMemo } from 'react';
import * as XLSX from 'xlsx';
import {
  UploadCloud,
  FileSpreadsheet,
  CheckCircle2,
  AlertTriangle,
  Search,
  Filter,
  ArrowUpDown,
  Download,
  Eye,
  RefreshCw,
  Server,
  User,
  Shield,
  Clock,
  Terminal,
  Trash2,
  Play
} from 'lucide-react';
import { REQUIRED_COLUMNS, validateSIEMLogs, downloadFile } from '../utils/analyzer';

export default function Module1Upload({
  logs,
  onLogsLoaded,
  onClearData,
  onLoadStockholmSample,
  onLoadAltSample,
  currentFileName
}) {
  const [dragActive, setDragActive] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [uploadSuccess, setUploadSuccess] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);

  // Table filters & pagination
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterHost, setFilterHost] = useState('ALL');
  const [filterResult, setFilterResult] = useState('ALL');
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [sortField, setSortField] = useState('Timestamp');
  const [sortDirection, setSortDirection] = useState('asc');
  const [selectedEventModal, setSelectedEventModal] = useState(null);

  // Drag handlers
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const processFile = (file) => {
    setIsProcessing(true);
    setUploadError(null);
    setUploadSuccess(null);

    const fileName = file.name.toLowerCase();
    if (!fileName.endsWith('.xlsx') && !fileName.endsWith('.xls') && !fileName.endsWith('.csv')) {
      setUploadError("Formato no admitido. Por favor cargue un archivo Excel (.xlsx, .xls) o delimitado por comas (.csv).");
      setIsProcessing(false);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = new Uint8Array(e.target.result);
        const workbook = XLSX.read(data, { type: 'array' });
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const jsonRecords = XLSX.utils.sheet_to_json(worksheet, { defval: null });

        // Normalize timestamp to string
        jsonRecords.forEach(r => {
          if (r.Timestamp instanceof Date) {
            r.Timestamp = r.Timestamp.toISOString().replace('T', ' ').substring(0, 19);
          } else if (typeof r.Timestamp === 'number') {
            const parsedDate = new Date(Math.round((r.Timestamp - 25569) * 86400 * 1000));
            r.Timestamp = parsedDate.toISOString().replace('T', ' ').substring(0, 19);
          }
        });

        const validation = validateSIEMLogs(jsonRecords);
        if (!validation.isValid) {
          setUploadError(validation.error);
          setIsProcessing(false);
          return;
        }

        onLogsLoaded(jsonRecords, file.name);
        setUploadSuccess(`Archivo "${file.name}" cargado y analizado en tiempo real (${jsonRecords.length} eventos).`);
        setIsProcessing(false);
      } catch (err) {
        console.error("Error al procesar el archivo Excel:", err);
        setUploadError(`Error al leer el archivo Excel: ${err.message}`);
        setIsProcessing(false);
      }
    };
    reader.onerror = () => {
      setUploadError("Error en la lectura del archivo.");
      setIsProcessing(false);
    };
    reader.readAsArrayBuffer(file);
  };

  // Distinct values for dropdown filters
  const uniqueHosts = useMemo(() => {
    if (!logs) return [];
    return Array.from(new Set(logs.map(l => l.Hostname).filter(Boolean))).sort();
  }, [logs]);

  const uniqueSeverities = useMemo(() => {
    if (!logs) return [];
    return Array.from(new Set(logs.map(l => l.Severity).filter(Boolean)));
  }, [logs]);

  const uniqueResults = useMemo(() => {
    if (!logs) return [];
    return Array.from(new Set(logs.map(l => l.Result).filter(Boolean)));
  }, [logs]);

  // Filtering and sorting logs
  const filteredLogs = useMemo(() => {
    if (!logs) return [];

    return logs.filter(log => {
      // Search term
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const matches =
          (log.Log_ID && String(log.Log_ID).toLowerCase().includes(term)) ||
          (log.Hostname && String(log.Hostname).toLowerCase().includes(term)) ||
          (log.User && String(log.User).toLowerCase().includes(term)) ||
          (log.Source_IP && String(log.Source_IP).toLowerCase().includes(term)) ||
          (log.Destination && String(log.Destination).toLowerCase().includes(term)) ||
          (log.Event_ID && String(log.Event_ID).toLowerCase().includes(term)) ||
          (log.Event_Description && String(log.Event_Description).toLowerCase().includes(term)) ||
          (log.Process_CommandLine && String(log.Process_CommandLine).toLowerCase().includes(term));

        if (!matches) return false;
      }

      // Severity filter
      if (filterSeverity !== 'ALL' && log.Severity !== filterSeverity) {
        return false;
      }

      // Hostname filter
      if (filterHost !== 'ALL' && log.Hostname !== filterHost) {
        return false;
      }

      // Result filter
      if (filterResult !== 'ALL' && log.Result !== filterResult) {
        return false;
      }

      // Only suspicious
      if (onlySuspicious) {
        const isSusp =
          log.Severity === 'High' ||
          log.Severity === 'Medium' ||
          log.Severity === 'Warning' ||
          (log.Process_CommandLine && (
            log.Process_CommandLine.toLowerCase().includes('powershell') ||
            log.Process_CommandLine.toLowerCase().includes('vssadmin') ||
            log.Process_CommandLine.toLowerCase().includes('wuhelper') ||
            log.Process_CommandLine.toLowerCase().includes('mimikatz') ||
            log.Process_CommandLine.toLowerCase().includes('whoami') ||
            log.Process_CommandLine.toLowerCase().includes('tar') ||
            log.Process_CommandLine.toLowerCase().includes('7z')
          ));
        if (!isSusp) return false;
      }

      return true;
    }).sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];
      if (valA === undefined || valA === null) valA = '';
      if (valB === undefined || valB === null) valB = '';

      if (sortDirection === 'asc') {
        return String(valA).localeCompare(String(valB));
      } else {
        return String(valB).localeCompare(String(valA));
      }
    });
  }, [logs, searchTerm, filterSeverity, filterHost, filterResult, onlySuspicious, sortField, sortDirection]);

  // Pagination slice
  const paginatedLogs = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredLogs.slice(start, start + pageSize);
  }, [filteredLogs, currentPage, pageSize]);

  const totalPages = Math.ceil(filteredLogs.length / pageSize) || 1;

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'Critical':
      case 'Crítico':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'High':
      case 'Alto':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'Medium':
      case 'Medio':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'Warning':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
      case 'Informational':
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    }
  };

  const handleExportFilteredCSV = () => {
    if (!filteredLogs.length) return;
    const worksheet = XLSX.utils.json_to_sheet(filteredLogs);
    const csvOutput = XLSX.utils.sheet_to_csv(worksheet);
    downloadFile(csvOutput, `siem_filtered_logs_${new Date().toISOString().substring(0, 10)}.csv`, 'text/csv');
  };

  return (
    <div className="space-y-6">
      {/* Module Title & Context */}
      <div className="bg-gradient-to-r from-slate-900 to-slate-800 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono font-semibold uppercase tracking-wider mb-1">
              <FileSpreadsheet className="w-4 h-4" />
              <span>Módulo 1: Ingesta, Validación & Previsualización de SIEM</span>
            </div>
            <h2 className="text-xl font-bold text-white">
              Carga y Exploración de Registros de Eventos
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Importe cualquier archivo exportado del SIEM corporativo (<code className="text-cyan-300 font-mono">.xlsx</code>, <code className="text-cyan-300 font-mono">.csv</code>).
              El motor verificará la integridad de columnas obligatorias y estructurará el análisis pericial en <strong>tiempo real</strong>.
            </p>
          </div>

          {logs && logs.length > 0 && (
            <div className="flex items-center gap-2">
              <button
                onClick={onClearData}
                className="px-3.5 py-2 rounded-lg bg-red-950/80 hover:bg-red-900 text-red-200 text-xs font-semibold flex items-center gap-1.5 border border-red-800 transition-all"
              >
                <Trash2 className="w-4 h-4" />
                <span>Limpiar Archivo</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Drag and Drop Upload Area */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-all ${dragActive
            ? 'border-cyan-400 bg-cyan-950/30'
            : logs && logs.length > 0
              ? 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
              : 'border-cyan-500/50 bg-slate-900/70 hover:border-cyan-400 shadow-xl'
          }`}
      >
        <input
          type="file"
          id="file-upload"
          accept=".xlsx,.xls,.csv"
          onChange={handleFileInput}
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-3">
          <div className="w-14 h-14 rounded-full bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center text-cyan-400 shadow-inner">
            <UploadCloud className="w-7 h-7 animate-bounce" />
          </div>

          <div className="space-y-1">
            <label
              htmlFor="file-upload"
              className="text-sm sm:text-base font-semibold text-white hover:text-cyan-400 cursor-pointer transition-colors"
            >
              {logs && logs.length > 0
                ? "Arrastre otro archivo para reemplazar el actual o haga clic aquí"
                : "Haga clic para seleccionar archivo SIEM o arrastre y suelte aquí (.xlsx / .csv)"}
            </label>
            <p className="text-xs text-slate-400">
              Formatos soportados: Microsoft Excel (<code className="text-slate-300">.xlsx, .xls</code>) o delimitado por comas (<code className="text-slate-300">.csv</code>)
            </p>
          </div>

          {/* Quick Sample Load Buttons */}
          <div className="pt-2 flex flex-wrap justify-center items-center gap-3">
            <span className="text-xs text-slate-500 font-mono">O cargue una muestra de prueba:</span>
            <button
              onClick={onLoadStockholmSample}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-medium flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <Play className="w-3.5 h-3.5 text-cyan-400" />
              <span>Caso Estocolmo (715 logs)</span>
            </button>
            <button
              onClick={onLoadAltSample}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-purple-300 border border-slate-700 text-xs font-medium flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <Play className="w-3.5 h-3.5 text-purple-400" />
              <span>Escenario Alternativo (25 logs)</span>
            </button>
          </div>

          <div className="pt-2 flex flex-wrap justify-center items-center gap-2 text-[11px] text-slate-500 font-mono">
            <span>Columnas Requeridas:</span>
            {REQUIRED_COLUMNS.map((col) => (
              <span key={col} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {col}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Alerts for Status */}
      {uploadError && (
        <div className="bg-red-950/60 border border-red-800/80 rounded-xl p-4 flex items-start gap-3 text-red-200 animate-fadeIn">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div className="text-xs sm:text-sm">
            <div className="font-semibold text-red-300">Error de Validación de Formato</div>
            <p className="text-red-200/90 mt-0.5">{uploadError}</p>
          </div>
        </div>
      )}

      {uploadSuccess && (
        <div className="bg-emerald-950/60 border border-emerald-800/80 rounded-xl p-4 flex items-start gap-3 text-emerald-200 animate-fadeIn">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
          <div className="text-xs sm:text-sm flex-1 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <div className="font-semibold text-emerald-300">Insumo Validado y Analizado en Tiempo Real</div>
              <p className="text-emerald-200/90 mt-0.5">{uploadSuccess}</p>
            </div>
            <span className="px-2.5 py-1 rounded-full bg-emerald-900/80 text-emerald-300 border border-emerald-700 text-xs font-mono font-bold w-fit">
              {logs ? `${logs.length} Registros Activos` : 'Listo'}
            </span>
          </div>
        </div>
      )}

      {/* Empty State Banner when no file is loaded */}
      {(!logs || logs.length === 0) && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-10 text-center space-y-3">
          <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-slate-400">
            <Clock className="w-6 h-6 text-cyan-400" />
          </div>
          <h3 className="text-base font-bold text-white">
            Esperando Ingesta de Datos del SIEM
          </h3>
          <p className="text-xs sm:text-sm text-slate-400 max-w-lg mx-auto leading-relaxed">
            Por favor cargue un archivo exportado del SIEM (<code className="text-cyan-300">.xlsx</code> o <code className="text-cyan-300">.csv</code>) o seleccione uno de los casos de prueba superiores. El sistema generará el análisis de seguridad, gráficos de telemetría, matriz de riesgos e informe pericial en <strong>tiempo real</strong>.
          </p>
        </div>
      )}

      {/* SIEM Log Exploration Table Controls (only rendered when logs are loaded) */}
      {logs && logs.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4 shadow-xl animate-fadeIn">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            {/* Search bar */}
            <div className="relative flex-1 min-w-[240px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                placeholder="Buscar por ID, Hostname, IP, Usuario, Event_ID, comando..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>

            {/* Quick Filters */}
            <div className="flex flex-wrap items-center gap-2">
              {/* Host Filter */}
              <select
                value={filterHost}
                onChange={(e) => { setFilterHost(e.target.value); setCurrentPage(1); }}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">Todos los Hostnames ({uniqueHosts.length})</option>
                {uniqueHosts.map(h => (
                  <option key={h} value={h}>{h}</option>
                ))}
              </select>

              {/* Severity Filter */}
              <select
                value={filterSeverity}
                onChange={(e) => { setFilterSeverity(e.target.value); setCurrentPage(1); }}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">Todas las Severidades</option>
                {uniqueSeverities.map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>

              {/* Result Filter */}
              <select
                value={filterResult}
                onChange={(e) => { setFilterResult(e.target.value); setCurrentPage(1); }}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">Todos los Resultados</option>
                {uniqueResults.map(r => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>

              {/* Only Suspicious Toggle */}
              <button
                onClick={() => { setOnlySuspicious(!onlySuspicious); setCurrentPage(1); }}
                className={`px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${onlySuspicious
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
                  }`}
              >
                <Shield className="w-3.5 h-3.5" />
                <span>Solo Sospechosos</span>
              </button>

              {/* Export filtered to CSV */}
              <button
                onClick={handleExportFilteredCSV}
                title="Descargar vista actual como CSV"
                className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
              >
                <Download className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Counter & Summary */}
          <div className="flex flex-wrap items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800/80">
            <div>
              Mostrando <span className="text-white font-bold">{filteredLogs.length}</span> de <span className="text-white font-bold">{logs.length}</span> eventos
              {currentFileName && <span className="ml-2 font-mono text-cyan-400">({currentFileName})</span>}
              {onlySuspicious && <span className="ml-2 text-amber-400 font-semibold">(Filtro de anomalías activo)</span>}
            </div>

            <div className="flex items-center gap-2">
              <span>Filas por página:</span>
              <select
                value={pageSize}
                onChange={(e) => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-xs text-slate-300"
              >
                <option value="15">15</option>
                <option value="20">20</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
            </div>
          </div>

          {/* The Log Table */}
          <div className="overflow-x-auto border border-slate-800 rounded-lg">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 text-slate-400 uppercase font-mono tracking-wider border-b border-slate-800">
                  <th className="p-2.5 cursor-pointer hover:text-white" onClick={() => handleSort('Log_ID')}>
                    <div className="flex items-center gap-1">
                      <span>Log ID</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="p-2.5 cursor-pointer hover:text-white" onClick={() => handleSort('Timestamp')}>
                    <div className="flex items-center gap-1">
                      <span>Timestamp</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="p-2.5 cursor-pointer hover:text-white" onClick={() => handleSort('Hostname')}>
                    <div className="flex items-center gap-1">
                      <span>Hostname</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="p-2.5 cursor-pointer hover:text-white" onClick={() => handleSort('Event_ID')}>
                    <div className="flex items-center gap-1">
                      <span>Event ID</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="p-2.5 cursor-pointer hover:text-white" onClick={() => handleSort('User')}>
                    <div className="flex items-center gap-1">
                      <span>Usuario</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="p-2.5">Origen &rarr; Destino</th>
                  <th className="p-2.5">Severidad</th>
                  <th className="p-2.5">Resultado</th>
                  <th className="p-2.5">Descripción / Comando</th>
                  <th className="p-2.5 text-center">Detalle</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {paginatedLogs.length === 0 ? (
                  <tr>
                    <td colSpan="10" className="p-8 text-center text-slate-500">
                      No se encontraron eventos coincidentes con los filtros seleccionados.
                    </td>
                  </tr>
                ) : (
                  paginatedLogs.map((log) => {
                    const isHighRisk = log.Severity === 'High' || log.Severity === 'Critical' || log.Severity === 'Warning';
                    return (
                      <tr
                        key={log.Log_ID}
                        className={`hover:bg-slate-800/60 transition-colors ${isHighRisk ? 'bg-slate-900/40' : ''}`}
                      >
                        <td className="p-2.5 text-cyan-400 font-semibold whitespace-nowrap">{log.Log_ID}</td>
                        <td className="p-2.5 text-slate-400 whitespace-nowrap">{log.Timestamp}</td>
                        <td className="p-2.5 text-slate-200 font-bold whitespace-nowrap">
                          <span className="flex items-center gap-1">
                            <Server className="w-3 h-3 text-slate-400" />
                            {log.Hostname}
                          </span>
                        </td>
                        <td className="p-2.5 text-purple-300 font-semibold whitespace-nowrap">{log.Event_ID}</td>
                        <td className="p-2.5 text-slate-300 whitespace-nowrap max-w-[120px] truncate" title={log.User}>
                          {log.User || '-'}
                        </td>
                        <td className="p-2.5 text-slate-400 whitespace-nowrap">
                          <span className="text-slate-300">{log.Source_IP || '-'}</span>
                          <span className="text-slate-500 mx-1">&rarr;</span>
                          <span className="text-slate-300">{log.Destination || '-'}</span>
                        </td>
                        <td className="p-2.5 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(log.Severity)}`}>
                            {log.Severity || 'Informational'}
                          </span>
                        </td>
                        <td className="p-2.5 whitespace-nowrap">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] ${log.Result === 'Success' || log.Result === 'Allowed' || log.Result === '200'
                              ? 'text-emerald-400 bg-emerald-950/40'
                              : 'text-rose-400 bg-rose-950/40'
                            }`}>
                            {log.Result || '-'}
                          </span>
                        </td>
                        <td className="p-2.5 text-slate-300 font-sans max-w-[280px] truncate">
                          {log.Process_CommandLine ? (
                            <div className="flex items-center gap-1 text-amber-300 font-mono text-[11px]" title={log.Process_CommandLine}>
                              <Terminal className="w-3 h-3 flex-shrink-0" />
                              <span className="truncate">{log.Process_CommandLine}</span>
                            </div>
                          ) : (
                            <span className="text-slate-400 truncate" title={log.Event_Description}>
                              {log.Event_Description || '-'}
                            </span>
                          )}
                        </td>
                        <td className="p-2.5 text-center">
                          <button
                            onClick={() => setSelectedEventModal(log)}
                            className="p-1 text-slate-400 hover:text-cyan-400 transition-colors"
                            title="Ver detalle forense completo"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination controls */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
            <div className="text-xs text-slate-400">
              Página <span className="text-white font-bold">{currentPage}</span> de <span className="text-white font-bold">{totalPages}</span>
            </div>

            <div className="flex items-center space-x-1">
              <button
                onClick={() => setCurrentPage(1)}
                disabled={currentPage === 1}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-xs text-slate-300"
              >
                &laquo; Primera
              </button>
              <button
                onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                disabled={currentPage === 1}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-xs text-slate-300"
              >
                Anterior
              </button>
              <button
                onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                disabled={currentPage === totalPages}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-xs text-slate-300"
              >
                Siguiente
              </button>
              <button
                onClick={() => setCurrentPage(totalPages)}
                disabled={currentPage === totalPages}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-xs text-slate-300"
              >
                Última &raquo;
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Raw Event Detail Modal */}
      {selectedEventModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-slate-900 border border-cyan-500/40 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="p-1.5 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800">
                  <Terminal className="w-4 h-4" />
                </span>
                <h3 className="text-base font-bold text-white">
                  Detalle Forense del Evento: <span className="text-cyan-400 font-mono">{selectedEventModal.Log_ID}</span>
                </h3>
              </div>
              <button
                onClick={() => setSelectedEventModal(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Timestamp</span>
                <span className="text-slate-200 font-bold">{selectedEventModal.Timestamp}</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Hostname</span>
                <span className="text-cyan-400 font-bold">{selectedEventModal.Hostname}</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Event ID</span>
                <span className="text-purple-300 font-bold">{selectedEventModal.Event_ID}</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Usuario</span>
                <span className="text-amber-300 font-bold">{selectedEventModal.User || 'N/A'}</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">IP Origen</span>
                <span className="text-slate-200">{selectedEventModal.Source_IP || 'N/A'}</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Destino</span>
                <span className="text-slate-200">{selectedEventModal.Destination || 'N/A'}</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Severidad</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(selectedEventModal.Severity)}`}>
                  {selectedEventModal.Severity}
                </span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Resultado</span>
                <span className="text-slate-200">{selectedEventModal.Result || 'N/A'}</span>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-xs text-slate-400 font-semibold block">Descripción del Evento:</span>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs text-slate-300">
                {selectedEventModal.Event_Description || 'Sin descripción'}
              </div>
            </div>

            {selectedEventModal.Process_CommandLine && (
              <div className="space-y-2">
                <span className="text-xs text-amber-400 font-semibold block flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Línea de Comandos / Payload Registrado:</span>
                </span>
                <div className="bg-black/90 p-3 rounded-lg border border-amber-600/50 font-mono text-xs text-amber-200 break-all select-all">
                  {selectedEventModal.Process_CommandLine}
                </div>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedEventModal(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
              >
                Cerrar Detalle
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
