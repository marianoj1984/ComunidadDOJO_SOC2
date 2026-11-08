// Incident Definitions, IoCs, MITRE Mapping, and Forensic Telemetry
// Prepared by SOC Level 2 Analyst (Stockholm, Sweden)

export const STOCKHOLM_CONSULTING_INFO = {
  company: "Nordic Cyber Defense & Consulting AB",
  location: "Stockholm, Sweden (Sveavägen 44, SE-111 34)",
  socLevel: "SOC Tier 2 - Advanced Threat Hunting & Incident Response",
  analyst: "Lead Incident Response Analyst L2",
  caseReference: "SEC-STK-2026-1023-IR",
  investigationDate: "2026-11-05",
  incidentWindow: "2026-10-23 07:46:07 - 13:44:06 UTC+1",
  classification: "CONFIDENCIAL / TLP:AMBER",
  targetCompany: "Nordic Enterprise Corporation (Sector Financiero / Corporativo)",
  conclusion: "CONFIRMADO: MÚLTIPLES INCIDENTES DE SEGURIDAD COORDINADOS (NO ES FALSO POSITIVO)"
};

export const CONFIRMED_INCIDENTS = [
  {
    id: "INC-01",
    name: "Campaña Externa de Password Spraying contra Controlador de Dominio",
    shortName: "Password Spraying (DC-01)",
    severity: "Alto",
    cvssScore: 7.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    threatActor: "APT / Botnet Externa (IP: 203.0.113.74)",
    timeframe: "2026-10-23 08:25:00 - 08:40:00 (15 min)",
    primaryTarget: "DC-01 (Domain Controller)",
    affectedAccounts: [
      "CORP\\jlopez", "CORP\\aperez", "CORP\\helpdesk", "CORP\\mgarcia",
      "CORP\\rrojas", "CORP\\slopez", "CORP\\backupsvc", "CORP\\dtorres"
    ],
    eventCount: 35,
    eventIds: [4625],
    status: "Bloqueado / No Exitoso en DC-01 (Tentativas continuas)",
    killChainPhase: "Reconnaissance / Delivery (Credential Access)",
    mitreTactics: ["Credential Access"],
    mitreTechniques: [
      { id: "T1110.003", name: "Password Spraying" },
      { id: "T1078.002", name: "Valid Accounts: Domain Accounts" }
    ],
    summary: "El atacante lanzó ráfagas sincronizadas de autenticación fallida cada ~19 segundos contra el Domain Controller (DC-01) rotando entre 8 cuentas corporativas clave (incluyendo helpdesk y backupsvc) para evadir los umbrales estándar de bloqueo de cuentas.",
    technicalDetails: "Se registraron 35 intentos fallidos consecutivos (Event_ID 4625, 'bad password') originados en la IP pública 203.0.113.74. La dispersión temporal constante de 19 segundos demuestra el uso de scripts automatizados de ataque (p. ej., SprayingToolkit o CrackMapExec). Aunque el controlador de dominio rechazó las contraseñas, la exposición del protocolo de autenticación directamente hacia Internet sin MFA ni geobloqueo representa una vulnerabilidad crítica.",
    iocs: [
      { type: "IP Externa", value: "203.0.113.74", description: "IP atacante origen del password spraying hacia DC-01" },
      { type: "Cuentas Comprometidas en Foco", value: "CORP\\backupsvc, CORP\\helpdesk, CORP\\admin", description: "Objetivos de alto privilegio buscados por el atacante" }
    ],
    sampleLogIds: ["EVT-00057", "EVT-00058", "EVT-00060", "EVT-00061", "EVT-00063", "EVT-00065", "EVT-00066", "EVT-00068"],
    impact: "Riesgo de compromiso de credenciales corporativas y escalada de privilegios a nivel de dominio si alguna cuenta posee contraseñas débiles o reutilizadas."
  },
  {
    id: "INC-02",
    name: "Brecha Externa RDP, Escalada de Privilegios, Movimiento Lateral y Exfiltración Financiera",
    shortName: "RDP Compromise & Data Exfil (APP-SRV01 -> FS-SRV01)",
    severity: "Crítico",
    cvssScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    threatActor: "Actor Hostil Externo (IP: 198.51.100.77 -> Exfiltración a 203.0.113.88:443)",
    timeframe: "2026-10-23 09:02:00 - 09:22:00 (20 min)",
    primaryTarget: "APP-SRV01 (Servidor de Aplicaciones) y FS-SRV01 (Servidor de Archivos)",
    affectedAccounts: ["CORP\\admin"],
    eventCount: 15,
    eventIds: [4625, 4624, 4672, 4688, 4104, 5140, 5145, 5156, 4634],
    status: "EXITOSO - EXFILTRACIÓN CONSUMADA",
    killChainPhase: "Exploitation -> Privilege Escalation -> Lateral Movement -> Exfiltration",
    mitreTactics: [
      "Initial Access", "Privilege Escalation", "Execution", "Discovery",
      "Lateral Movement", "Collection", "Exfiltration"
    ],
    mitreTechniques: [
      { id: "T1110.001", name: "Password Guessing / Brute Force" },
      { id: "T1021.001", name: "Remote Desktop Protocol (RDP)" },
      { id: "T1078.001", name: "Default/Admin Accounts" },
      { id: "T1059.001", name: "PowerShell EncodedCommand" },
      { id: "T1087.001", name: "Local Account Discovery" },
      { id: "T1135", name: "Network Share Discovery" },
      { id: "T1021.002", name: "SMB/Windows Admin Shares" },
      { id: "T1560.001", name: "Archive via Utility (tar.exe)" },
      { id: "T1048.003", name: "Exfiltration Over Alternative Protocol" }
    ],
    summary: "Fuerza bruta RDP exitosa contra la cuenta CORP\\admin en APP-SRV01, ejecución de comandos PowerShell ofuscados, enumeración de shares de red, salto lateral hacia FS-SRV01, robo del archivo confidencial Budget2027.xlsx, empaquetado mediante tar.exe y exfiltración hacia 203.0.113.88:443.",
    technicalDetails: `Secuencia cronológica forense detallada:
- 09:02 a 09:05: 4 intentos fallidos de RDP (Event_ID 4625, LogonType=10) desde 198.51.100.77.
- 09:06:00 (EVT-00188): LOGON RDP EXITOSO (Event_ID 4624, LogonType=10) con la cuenta CORP\\admin.
- 09:07:00 (EVT-00193): Asignación de privilegios especiales (Event_ID 4672).
- 09:09:00 (EVT-00198): Creación de proceso sospechoso: powershell.exe -NoProfile -EncodedCommand [REDACTED_SYNTHETIC].
- 09:11:00 (EVT-00207): Bloque de script PowerShell (Event_ID 4104): 'Get-LocalGroupMember Administrators; Get-SmbShare'.
- 09:13:00 (EVT-00214): Enumeración de recursos compartidos de red: 'net.exe view \\\\FS-SRV01'.
- 09:15:00 a 09:16:00 (EVT-00222, EVT-00225): Movimiento lateral hacia FS-SRV01 (LogonType=3 desde 10.10.2.15).
- 09:17:00 a 09:18:00 (EVT-00227, EVT-00231): Acceso a share '\\\\FS-SRV01\\Finance' y lectura directa del archivo 'Finance\\Budget2027.xlsx'.
- 09:20:00 (EVT-00232): Empaquetado y compresión de archivos robados: 'tar.exe -a -c -f C:\\Temp\\finance.zip C:\\Temp\\reports'.
- 09:21:00 (EVT-00235): Conexión de exfiltración saliente permitida por Firewall hacia 203.0.113.88:443 mediante powershell.exe.
- 09:22:00 (EVT-00237): Cierre de sesión de CORP\\admin (Event_ID 4634).`,
    iocs: [
      { type: "IP Atacante (RDP)", value: "198.51.100.77", description: "IP externa de origen de la conexión RDP no autorizada" },
      { type: "IP Exfiltración", value: "203.0.113.88:443", description: "Destino C2/exfiltración de finance.zip" },
      { type: "Comando Sospechoso", value: "tar.exe -a -c -f C:\\Temp\\finance.zip C:\\Temp\\reports", description: "Staging de datos confidenciales robados" },
      { type: "Archivo Comprometido", value: "\\\\FS-SRV01\\Finance\\Budget2027.xlsx", description: "Presupuesto financiero confidencial exfiltrado" }
    ],
    sampleLogIds: ["EVT-00174", "EVT-00188", "EVT-00198", "EVT-00207", "EVT-00214", "EVT-00225", "EVT-00227", "EVT-00231", "EVT-00232", "EVT-00235"],
    impact: "Pérdida de confidencialidad de presupuestos estratégicos 2027, compromiso total de credenciales de administrador de dominio y control operativo sobre servidores centrales."
  },
  {
    id: "INC-03",
    name: "Eliminación de Copias Shadow de Volumen (VSS) y Recolección Masiva de Archivos Financieros (Pre-Ransomware)",
    shortName: "Pre-Ransomware & VSS Shadow Deletion (WS-023)",
    severity: "Crítico",
    cvssScore: 8.9,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    threatActor: "Amenaza Interna / Cuenta de Servicio Comprometida (CORP\\backupsvc en WS-023)",
    timeframe: "2026-10-23 09:36:00 - 09:43:00 (7 min)",
    primaryTarget: "WS-023 y FS-SRV01 (Recurso Compartido Finance)",
    affectedAccounts: ["CORP\\backupsvc"],
    eventCount: 20,
    eventIds: [4688, 4663, 5145],
    status: "EN PROCESO / ACTIVIDAD DE ALTO PELIGRO",
    killChainPhase: "Impact / Inhibit System Recovery (Ransomware Preparation)",
    mitreTactics: ["Defense Evasion", "Impact", "Collection"],
    mitreTechniques: [
      { id: "T1490", name: "Inhibit System Recovery: Delete Volume Shadow Copies" },
      { id: "T1059.001", name: "PowerShell EncodedCommand" },
      { id: "T1080", name: "Taint Shared Content" },
      { id: "T1078.002", name: "Abuse of Service Accounts (backupsvc)" }
    ],
    summary: "Uso indebido de la cuenta de servicio CORP\\backupsvc desde la estación WS-023: ejecución de PowerShell codificado, barrido automatizado de 16 documentos contables en FS-SRV01 y ejecución inmediata de 'vssadmin.exe delete shadows /all /quiet' para destruir puntos de restauración.",
    technicalDetails: `Detalle cronológico:
- 09:36:00 (EVT-00280): En WS-023 (IP 10.10.1.44), el usuario CORP\\backupsvc ejecuta 'powershell.exe -NoProfile -EncodedCommand <base64_redacted>'.
- 09:37:00 a 09:41:00 (EVT-00284 a EVT-00309): En FS-SRV01, se leen en rápida sucesión 16 archivos contables: '\\\\FS-SRV01\\Finance\\FY2026\\document_000.xlsx' hasta 'document_015.xlsx' (Event_ID 4663, Severity Warning).
- 09:42:00 (EVT-00314): Ejecución de comando crítico: 'vssadmin.exe delete shadows /all /quiet' en WS-023. Este es el indicador definitivo de un ataque de ransomware inminente destinado a impedir la recuperación de datos sin pagar el rescate.
- 09:43:00 (EVT-00315): Verificación de permisos y acceso a \\\\FS-SRV01\\Finance.`,
    iocs: [
      { type: "Comando Crítico", value: "vssadmin.exe delete shadows /all /quiet", description: "Destrucción forzada de copias de seguridad de volumen shadow" },
      { type: "Cuenta Comprometida", value: "CORP\\backupsvc", description: "Cuenta de servicio de backup manipulada fuera de su ventana habitual" },
      { type: "Host Origen", value: "WS-023 (10.10.1.44)", description: "Estación de trabajo desde la que se orquestó la recolección y borrado" }
    ],
    sampleLogIds: ["EVT-00280", "EVT-00284", "EVT-00286", "EVT-00289", "EVT-00314", "EVT-00315"],
    impact: "Destrucción inminente de la capacidad de recuperación ante desastres de la compañía y alto riesgo de cifrado masivo (Ransomware) de recursos financieros compartidos."
  },
  {
    id: "INC-04",
    name: "Exfiltración Masiva de Archivos Legales hacia Proxy Externo Malicioso",
    shortName: "Mass Data Exfiltration (WS-018 -> 198.51.100.88)",
    severity: "Alto",
    cvssScore: 8.2,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    threatActor: "Amenaza Interna / Host Comprometido (WS-018 / CORP\\rrojas)",
    timeframe: "2026-10-23 10:42:00 - 10:49:18 (7 min)",
    primaryTarget: "WS-018 (Workstation) -> Destino Externo 198.51.100.88:443",
    affectedAccounts: ["CORP\\rrojas"],
    eventCount: 23,
    eventIds: [4688, "PROXY_ACCESS"],
    status: "EXITOSO - 255.4 MB EXFILTRADOS",
    killChainPhase: "Exfiltration Over Web Service",
    mitreTactics: ["Collection", "Exfiltration"],
    mitreTechniques: [
      { id: "T1560.001", name: "Archive via Utility (7z.exe)" },
      { id: "T1567", name: "Exfiltration Over Web Service" },
      { id: "T1071.001", name: "Web Protocols: HTTPS POST" }
    ],
    summary: "Compresión de toda la documentación legal corporativa ('C:\\Legal\\*.docx') mediante 7z.exe hacia una carpeta pública compartida, seguida de 22 transmisiones HTTPS POST continuas hacia una IP externa maliciosa a través del proxy corporativo por un volumen total de 255.4 Megabytes.",
    technicalDetails: `Detalle cronológico:
- 10:42:00 (EVT-00428): En WS-018 (IP 10.10.1.31), CORP\\rrojas ejecuta: '7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx'.
- 10:43:00 a 10:49:18 (EVT-00430 a EVT-00461): Se generan 22 eventos 'PROXY_ACCESS' hacia la dirección IP externa 198.51.100.88:443 con URIs estructurados '/upload/session/1' hasta '/upload/session/22'.
- En cada chunk se transfirieron entre 5.8 MB y 17.3 MB.
- Suma total de bytes transferidos: 255,423,942 bytes (~255.4 MB) de contratos, acuerdos y propiedad legal corporativa.
- El canal utilizó HTTPS pero fue categorizado como 'Warning / Allowed' por la falta de políticas de prevención de fuga de datos (DLP).`,
    iocs: [
      { type: "IP Externa Destino", value: "198.51.100.88:443", description: "Endpoint receptor de la exfiltración masiva" },
      { type: "Ruta de Archivo Staged", value: "C:\\Users\\Public\\archive.7z", description: "Contenedor comprimido con documentos legales" },
      { type: "Comando Utilizado", value: "7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx", description: "Empaquetado de contratos y acuerdos legales" },
      { type: "Volumen Exfiltrado", value: "255.4 MB (22 sesiones POST)", description: "Transferencia masiva de propiedad intelectual" }
    ],
    sampleLogIds: ["EVT-00428", "EVT-00430", "EVT-00431", "EVT-00432", "EVT-00435", "EVT-00445", "EVT-00460", "EVT-00461"],
    impact: "Exposición masiva de secretos comerciales, litigios y contratos confidenciales protegidos bajo regulaciones de privacidad y normativas de confidencialidad."
  },
  {
    id: "INC-05",
    name: "Establecimiento de Persistencia mediante Servicio Malicioso y Tarea Programada (Trojan Beaconing)",
    shortName: "Trojan Persistence & Beaconing (APP-SRV01)",
    severity: "Alto",
    cvssScore: 8.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    threatActor: "Actor Hostil Interno / Backdoor Implantado (Usuario CORP\\helpdesk en APP-SRV01)",
    timeframe: "2026-10-23 11:37:00 - 12:04:00+ (Actividad periódica activa)",
    primaryTarget: "APP-SRV01 (Servidor de Aplicaciones)",
    affectedAccounts: ["CORP\\helpdesk"],
    eventCount: 7,
    eventIds: [4698, 7045, 4688],
    status: "ACTIVO - BALIZA PERIÓDICA EN EJECUCIÓN",
    killChainPhase: "Installation / Persistence & Command & Control",
    mitreTactics: ["Persistence", "Privilege Escalation", "Defense Evasion", "Command and Control"],
    mitreTechniques: [
      { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task" },
      { id: "T1543.003", name: "Create or Modify System Process: Windows Service" },
      { id: "T1036.005", name: "Masquerading: Match Legitimate Name (WinUpdateHelper)" }
    ],
    summary: "Creación clandestina de una tarea programada ('UpdateCheck') y de un nuevo servicio en el sistema operativo ('WinUpdateHelper' apuntando a 'C:\\ProgramData\\wuhelper.exe') que se ejecuta de forma recurrente cada 6 minutos exactos, simulando ser una actualización de Windows legítima.",
    technicalDetails: `Detalle cronológico:
- 11:37:00 (EVT-00523): Event_ID 4698 (Severity Warning). Creación de tarea programada: TaskName=\\Microsoft\\Windows\\UpdateCheck; Action=powershell.exe -File C:\\ProgramData\\updatecheck.ps1.
- 11:38:00 (EVT-00524): Event_ID 7045 (Severity Warning). Instalación de servicio en Windows: ServiceName=WinUpdateHelper; ImagePath=C:\\ProgramData\\wuhelper.exe.
- 11:40:00 (EVT-00528): Ejecución del binario wuhelper.exe.
- 11:46:00 (EVT-00542): Ejecución del binario wuhelper.exe (intervalo de 6 minutos).
- 11:52:00 (EVT-00548): Ejecución del binario wuhelper.exe (intervalo de 6 minutos).
- 11:58:00 (EVT-00559): Ejecución del binario wuhelper.exe (intervalo de 6 minutos).
- 12:04:00 (EVT-00564): Ejecución del binario wuhelper.exe (intervalo de 6 minutos).
Este patrón cíclico es característico de balizas C2 (Command & Control Beacon) o recolectores de pulsaciones / datos locales.`,
    iocs: [
      { type: "Binario Malicioso", value: "C:\\ProgramData\\wuhelper.exe", description: "Troyano disfrazado de Windows Update Helper" },
      { type: "Script Malicioso", value: "C:\\ProgramData\\updatecheck.ps1", description: "Script ejecutado por la tarea programada oculta" },
      { type: "Nombre de Servicio", value: "WinUpdateHelper", description: "Servicio malicioso persistente registrado en SCM" },
      { type: "Tarea Programada", value: "\\Microsoft\\Windows\\UpdateCheck", description: "Tarea programada en el Programador de Tareas" },
      { type: "Frecuencia de Beacon", value: "Cada 6 minutos (360 segundos)", description: "Temporizador de comunicación C2 persistente" }
    ],
    sampleLogIds: ["EVT-00523", "EVT-00524", "EVT-00528", "EVT-00542", "EVT-00548", "EVT-00559", "EVT-00564"],
    impact: "Persistencia permanente del atacante en el servidor de aplicaciones, permitiendo el reingreso continuo incluso si se cambian contraseñas o se reinicia la máquina."
  },
  {
    id: "INC-06",
    name: "Explotación de Aplicación Web: Inyección de Web Shell y Ejecución Remota de Código (RCE)",
    shortName: "Web Shell & RCE (WEB-01)",
    severity: "Crítico",
    cvssScore: 9.3,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    threatActor: "Atacante Externo Web (IP: 192.0.2.91)",
    timeframe: "2026-10-23 12:10:00 - 12:15:00 (5 min)",
    primaryTarget: "WEB-01:443 (Servidor IIS)",
    affectedAccounts: ["IIS APPPOOL\\DefaultAppPool"],
    eventCount: 22,
    eventIds: ["HTTP_ACCESS", 4688],
    status: "RCE CONFIRMADO - CONTROL DE SERVIDOR WEB",
    killChainPhase: "Exploitation / Execution (Web Shell)",
    mitreTactics: ["Initial Access", "Execution", "Persistence", "Discovery"],
    mitreTechniques: [
      { id: "T1190", name: "Exploit Public-Facing Application" },
      { id: "T1505.003", name: "Server Software Component: Web Shell" },
      { id: "T1059.003", name: "Command and Scripting Interpreter: Windows Command Shell" },
      { id: "T1033", name: "System Owner/User Discovery (whoami)" }
    ],
    summary: "El atacante sondeó y activó una web shell alojada en '/uploads/test.aspx?cmd=whoami', escaneó rutas de administración y endpoints de exportación de API, y a las 12:15:00 detonó la ejecución del proceso 'cmd.exe /c whoami' bajo la cuenta de servicio 'IIS APPPOOL\\DefaultAppPool'.",
    technicalDetails: `Detalle cronológico:
- 12:10:00 (EVT-00571): Petición GET '/uploads/test.aspx?cmd=whoami' responde 200 OK desde la IP externa 192.0.2.91.
- 12:10:12 a 12:14:00 (EVT-00572 a EVT-00596): Peticiones agresivas contra '/login?user=admin', '/admin/' y '/api/v1/export' generando errores 500 y respuestas 200 de volcado de datos.
- 12:15:00 (EVT-00599): Event_ID 4688 (Severity Warning). Creación del proceso:
  - Host: WEB-01
  - Usuario: IIS APPPOOL\\DefaultAppPool
  - Proceso: cmd.exe /c whoami
  - Origen: Invocado directamente por la pasarela HTTP a través de la web shell cargada en el directorio /uploads/.`,
    iocs: [
      { type: "IP Atacante Web", value: "192.0.2.91", description: "IP externa atacante explotando el servidor web" },
      { type: "Ruta de Web Shell", value: "/uploads/test.aspx", description: "Web shell ASPX cargada en el directorio público de uploads" },
      { type: "Comando Ejecutado", value: "cmd.exe /c whoami", description: "Comando de reconocimiento detonado por el proceso web" },
      { type: "Ruta de Fuga de API", value: "/api/v1/export", description: "Endpoint de API web sondeado para extracción de datos" }
    ],
    sampleLogIds: ["EVT-00571", "EVT-00572", "EVT-00576", "EVT-00577", "EVT-00583", "EVT-00596", "EVT-00599"],
    impact: "Control remoto completo sobre el servidor web perimetral, permitiendo escalada de privilegios a SYSTEM, pivoteo a la base de datos interna (DB-SRV01) y defacement o filtración del código fuente."
  }
];

export const FALSE_POSITIVE_ANALYSIS = {
  determination: "INCIDENTE CONFIRMADO (NO ES UN FALSO POSITIVO)",
  justification: `La hipótesis de falso positivo queda TOTALMENTE DESCARTADA tras la correlación exhaustiva de eventos por las siguientes razones técnicas irrefutables:
1. No se trata de una anomalía estadística aislada o de un usuario olvidando su contraseña: se identificaron patrones deliberados de evasión (19s entre intentos de spray, rotación de usuarios).
2. Se verificaron ejecuciones exitosas de código malicioso ('tar.exe', 'vssadmin delete shadows', 'wuhelper.exe', 'cmd.exe /c whoami').
3. Se confirmaron dos flujos reales de exfiltración de datos a través del perímetro hacia IPs externas no corporativas (203.0.113.88 y 198.51.100.88), sumando más de 255 Megabytes.
4. Múltiples vectores de ataque concurrentes (RDP externo expuesto, Web Shell en IIS, Tarea Programada/Servicio) demuestran un ataque coordinado y multifacético contra los activos críticos de la organización.`
};

