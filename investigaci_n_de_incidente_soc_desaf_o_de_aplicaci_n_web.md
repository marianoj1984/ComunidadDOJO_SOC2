# Investigación de un Posible Incidente de Seguridad
## Desafío Técnico - Analista SOC Nivel 2 (Estocolmo, Suecia)

---

## 1. Contexto del Escenario
* **Rol:** Analista SOC Nivel 2 en una consultora de ciberseguridad con sede en Estocolmo, Suecia.
* **Cliente:** Empresa que reporta un posible incidente de seguridad en su infraestructura corporativa.
* **Insumo:** Un archivo Excel exportado desde el SIEM de la organización que contiene los registros de eventos (logs).

---

## 2. Misión del Desafío
Analizar los registros del SIEM para buscar **Indicadores de Compromiso (IoCs)**, correlacionar los eventos temporales y de red, y determinar de manera concluyente si existió uno o múltiples incidentes de seguridad (o si se trata de un falso positivo). El resultado final debe plasmarse en una **aplicación web interactiva** capaz de procesar la información y generar un informe técnico profesional.

---

## 3. Requerimientos Funcionales de la Aplicación Web

La solución debe construirse como una aplicación web interactiva que cumpla con los siguientes **6 módulos principales**:

### 1. Carga de Archivos
* **Funcionalidad:** Importar y visualizar el archivo Excel exportado del SIEM de manera intuitiva (interfaz drag-and-drop o selector de archivos).
* **Validación:** Comprobación de formato, columnas requeridas y previsualización tabular de los registros de eventos.

### 2. Análisis de Seguridad
* **Funcionalidad:** Identificar eventos sospechosos (intentos fallidos de autenticación, movimientos laterales, exfiltración de datos, anomalías de red o privilegios elevados).
* **Correlación:** Relacionar eventos dispersos en una línea de tiempo unificada para reconstruir la cadena de ataque (Kill Chain / ATT&CK framework).

### 3. Dashboard Interactivo
* **Funcionalidad:** Elaborar estadísticas clave y gráficos interactivos segmentados por nivel de criticidad, tipo de evento, origen geográfico o activos afectados.

### 4. Clasificación de Riesgos
* **Funcionalidad:** Asignar una calificación de riesgo a los hallazgos:
  * **Crítico**
  * **Alto**
  * **Medio**
  * **Bajo**
* **Justificación:** Proveer argumentos técnicos basados en el impacto potencial y la probabilidad de explotación.

### 5. Generación de Informe Técnico
* **Funcionalidad:** Compilar un documento estructurado, formal y completo que incluya:
  * **Resumen Ejecutivo:** Visión general para la alta gerencia.
  * **Hallazgos Identificados:** Listado de anomalías detectadas.
  * **Explicación Técnica:** Detalle analítico de cada hallazgo.
  * **Evidencias en Logs:** Fragmentos o referencias exactas extraídas del Excel del SIEM.
  * **Criticidad y Justificación:** Criterios de evaluación de riesgo.
  * **Posible Impacto en la Organización:** Consecuencias operativas, financieras o reputacionales.
  * **Plan de Acción:** Fases estructuradas de **Investigación, Contención y Remediación**.
  * **Recomendaciones Generales de Seguridad:** Medidas preventivas a corto y largo plazo.

### 6. Exportación de Resultados
* **Funcionalidad:** Descarga del informe técnico estructurado en formato PDF con diseño profesional listo para ser entregado al cliente en Estocolmo.