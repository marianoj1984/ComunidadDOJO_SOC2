import React, { useState, useMemo } from 'react';
import defaultLogs from './data/siem_logs.json';
import altLogs from './data/siem_logs_alt.json';
import { analyzeSIEMLogs } from './utils/analyzer';
import { STOCKHOLM_CONSULTING_INFO } from './data/incidentDefinitions';

// Components
import Navbar from './components/Navbar';
import Module1Upload from './components/Module1Upload';
import Module2Analysis from './components/Module2Analysis';
import Module3Dashboard from './components/Module3Dashboard';
import Module4Risk from './components/Module4Risk';
import Module5Report from './components/Module5Report';
import Module6Export from './components/Module6Export';

export default function App() {
  const [activeTab, setActiveTab] = useState('module1');
  // Starts with NO file loaded by default (empty state)
  const [logs, setLogs] = useState(null);
  const [currentFileName, setCurrentFileName] = useState(null);

  // Compute full forensic analysis in real-time whenever logs change
  const analysisData = useMemo(() => {
    if (!logs || !Array.isArray(logs) || logs.length === 0) return null;
    return analyzeSIEMLogs(logs, currentFileName || 'archivo_siem.xlsx');
  }, [logs, currentFileName]);

  const handleLogsLoaded = (newLogs, fileName) => {
    setLogs(newLogs);
    setCurrentFileName(fileName);
  };

  const handleClearData = () => {
    setLogs(null);
    setCurrentFileName(null);
  };

  const handleLoadStockholmSample = () => {
    setLogs(defaultLogs);
    setCurrentFileName('SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx');
  };

  const handleLoadAltSample = () => {
    setLogs(altLogs);
    setCurrentFileName('SIEM_Logs_Escenario_Alternativo.xlsx');
  };

  const handleNavigateToUpload = () => {
    setActiveTab('module1');
  };

  return (
    <div className="min-h-screen bg-[#080d1a] text-slate-100 flex flex-col font-sans">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onLoadSample={handleLoadStockholmSample}
        onClearData={handleClearData}
        totalLogs={logs?.length || 0}
        incidentsCount={analysisData?.incidents?.length || 0}
        isLiveAnalyzed={!!analysisData}
        fileName={currentFileName}
      />

      {/* Main Body Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {activeTab === 'module1' && (
          <Module1Upload
            logs={logs}
            onLogsLoaded={handleLogsLoaded}
            onClearData={handleClearData}
            onLoadStockholmSample={handleLoadStockholmSample}
            onLoadAltSample={handleLoadAltSample}
            currentFileName={currentFileName}
          />
        )}

        {activeTab === 'module2' && (
          <Module2Analysis
            analysisData={analysisData}
            onNavigateToUpload={handleNavigateToUpload}
          />
        )}

        {activeTab === 'module3' && (
          <Module3Dashboard
            analysisData={analysisData}
            onNavigateToUpload={handleNavigateToUpload}
          />
        )}

        {activeTab === 'module4' && (
          <Module4Risk
            analysisData={analysisData}
            onNavigateToUpload={handleNavigateToUpload}
          />
        )}

        {activeTab === 'module5' && (
          <Module5Report
            analysisData={analysisData}
            onNavigateToUpload={handleNavigateToUpload}
          />
        )}

        {activeTab === 'module6' && (
          <Module6Export
            analysisData={analysisData}
            onNavigateToUpload={handleNavigateToUpload}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="bg-[#0b1120] border-t border-slate-800/80 py-4 px-6 text-xs text-slate-500 text-center no-print mt-12">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-400">{STOCKHOLM_CONSULTING_INFO.company}</span>
            <span>&bull;</span>
            <span>{STOCKHOLM_CONSULTING_INFO.location}</span>
          </div>
          <div>
            Desafío Técnico Analista SOC Nivel 2 &middot; Ref:{' '}
            <span className="font-mono text-slate-400">{STOCKHOLM_CONSULTING_INFO.caseReference}</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
