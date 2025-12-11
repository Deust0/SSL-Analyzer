#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║              TESTSSL.SH HTML REPORT ANALYZER v2.1 - VERSIÓN FINAL             ║
║                    Generador Avanzado de Tablas de Resumen                    ║
║                                                                               ║
║  VERSIÓN 2.1 - FINAL CON LÓGICA CONFIRMADA:                                  ║
║  - Protocolos vulnerables (SSLv2, SSLv3, TLSv1, TLSv1.1):                    ║
║    ❌ X ROJO si "offered" (habilitados = inseguro)                           ║
║    ✓ OK VERDE si "not offered" (deshabilitados = seguro)                    ║
║                                                                               ║
║  - Protocolos seguros (TLSv1.2, TLSv1.3):                                    ║
║    ✓ OK VERDE si "offered" (habilitados = seguro)                           ║
║    ❌ X ROJO si "not offered" (no disponibles = problema)                    ║
║                                                                               ║
║  Uso:                                                                        ║
║  python3 testssl_analyzer.py [directorio_con_htmls]                        ║
║  python3 testssl_analyzer.py . --csv --json                                ║
║                                                                               ║
║  Python: 3.6+                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

import re
import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

# ============================================================================
# CLASES Y ESTRUCTURAS DE DATOS
# ============================================================================

@dataclass
class SecurityScan:
    """Almacena resultados de un escaneo de seguridad SSL/TLS"""
    ip: str
    puerto: str
    protocolos: Dict[str, bool]  # True = vulnerable, False = OK
    vulnerabilidades: Dict[str, bool]  # True = vulnerable, False = OK
    archivo_origen: str = ""
    
    def to_dict(self):
        """Convierte el objeto a diccionario"""
        return {
            'ip': self.ip,
            'puerto': self.puerto,
            'protocolos': self.protocolos,
            'vulnerabilidades': self.vulnerabilidades,
            'archivo_origen': self.archivo_origen
        }


class TestSSLParser:
    """
    Parser v2.1 para archivos HTML de testssl.sh
    Extrae información de protocolos y vulnerabilidades con lógica comprobada
    """
    
    def __init__(self, file_path: str):
        """Inicializa el parser con un archivo HTML"""
        self.file_path = file_path
        self.filename = os.path.basename(file_path)
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.content = f.read()
        
        self.ip = self._extract_ip()
        self.puerto = self._extract_puerto()
    
    def _extract_ip(self) -> str:
        """Extrae la IP del archivo"""
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)_p\d+', self.filename)
        if match:
            return match.group(1)
        return "Unknown"
    
    def _extract_puerto(self) -> str:
        """Extrae el puerto del archivo"""
        match = re.search(r'_p(\d+)', self.filename)
        if match:
            return match.group(1)
        return "Unknown"
    
    def parse_protocols(self) -> Dict[str, bool]:
        """
        VERSIÓN 2.1 FINAL - Extrae información de protocolos TLS/SSL
        
        LÓGICA COMPROBADA Y CONFIRMADA:
        
        PROTOCOLOS VULNERABLES (SSLv2, SSLv3, TLSv1, TLSv1.1):
        - ❌ X ROJO   ← si "offered" (habilitados = inseguro)
        - ✓ OK VERDE  ← si "not offered" (deshabilitados = seguro)
        
        PROTOCOLOS SEGUROS (TLSv1.2, TLSv1.3):
        - ✓ OK VERDE  ← si "offered" (habilitados = seguro)
        - ❌ X ROJO   ← si "not offered" (no disponibles = problema)
        
        Retorna: {protocolo: es_vulnerable}
        """
        protocolos = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        # Buscar la sección "Testing protocols"
        proto_section = re.search(
            r'Testing protocols.*?(?=Testing cipher|Testing server)',
            self.content,
            re.DOTALL | re.IGNORECASE
        )
        
        if not proto_section:
            return protocolos
        
        section = proto_section.group(0)
        
        # PATRONES v2.1: Buscar hasta fin de línea para evitar ambigüedades
        patterns = {
            'SSLv2': r'SSLv2\s*</span>([^\n]*)',
            'SSLv3': r'SSLv3\s*</span>([^\n]*)',
            'TLSv1': r'(?:TLS 1|TLSv1)(?:\.0)?\s+</span>([^\n]*)',
            'TLSv1.1': r'(?:TLS 1\.1|TLSv1\.1)\s+</span>([^\n]*)',
            'TLSv1.2': r'(?:TLS 1\.2|TLSv1\.2)\s+</span>([^\n]*)',
            'TLSv1.3': r'(?:TLS 1\.3|TLSv1\.3)\s+</span>([^\n]*)'
        }
        
        for proto, pattern in patterns.items():
            match = re.search(pattern, section, re.IGNORECASE)
            
            if match:
                captura = match.group(1).strip().lower()
                
                # Detectar palabras clave en la MISMA línea
                tiene_offered = 'offered' in captura
                tiene_not_offered = 'not offered' in captura
                
                # LÓGICA v2.1 - COMPROBADA Y CONFIRMADA
                if proto in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    # PROTOCOLOS VULNERABLES:
                    # ❌ X ROJO si "offered" (habilitado = inseguro)
                    # ✓ OK VERDE si "not offered" (deshabilitado = seguro)
                    protocolos[proto] = tiene_offered and not tiene_not_offered
                else:
                    # PROTOCOLOS SEGUROS (TLSv1.2, TLSv1.3):
                    # ✓ OK VERDE si "offered" (habilitado = seguro)
                    # ❌ X ROJO si "not offered" (no disponible = problema)
                    protocolos[proto] = tiene_not_offered
        
        return protocolos
    
    def parse_vulnerabilities(self) -> Dict[str, bool]:
        """
        Extrae información de vulnerabilidades conocidas.
        Retorna: {vulnerabilidad: es_vulnerable}
        """
        vulnerabilidades = {
            'Heartbleed': False,
            'CCS': False,
            'Ticketbleed': False,
            'Opossum': False,
            'ROBOT': False,
            'Secure Renegotiation': False,
            'Client-Init Renegotiation': False,
            'CRIME': False,
            'BREACH': False,
            'POODLE': False,
            'TLS Fallback': False,
            'SWEET32': False,
            'FREAK': False,
            'DROWN': False,
            'LOGJAM': False,
            'BEAST': False,
            'LUCKY13': False,
            'Winshock': False,
            'RC4': False
        }
        
        vuln_section = re.search(
            r'Testing vulnerabilities.*?(?=Running client|$)',
            self.content,
            re.DOTALL | re.IGNORECASE
        )
        
        if not vuln_section:
            return vulnerabilidades
        
        section = vuln_section.group(0)
        
        patterns = {
            'Heartbleed': r'Heartbleed.*?(?:VULNERABLE|not vulnerable)',
            'CCS': r'CCS.*?(?:VULNERABLE|not vulnerable)',
            'Ticketbleed': r'Ticketbleed.*?(?:VULNERABLE|not vulnerable)',
            'Opossum': r'Opossum.*?(?:VULNERABLE|not vulnerable)',
            'ROBOT': r'ROBOT.*?(?:VULNERABLE|not vulnerable|does not support)',
            'Secure Renegotiation': r'Secure Renegotiation.*?(?:supported|NOT)',
            'Client-Init Renegotiation': r'Client-Initiated.*?(?:VULNERABLE|not vulnerable)',
            'CRIME': r'CRIME.*?(?:VULNERABLE|not vulnerable)',
            'BREACH': r'BREACH.*?(?:VULNERABLE|no gzip|HTTP compression)',
            'POODLE': r'POODLE.*?(?:VULNERABLE|not vulnerable)',
            'TLS Fallback': r'FALLBACK.*?(?:supported|not|prevention)',
            'SWEET32': r'SWEET32.*?(?:VULNERABLE|not vulnerable)',
            'FREAK': r'FREAK.*?(?:VULNERABLE|not vulnerable)',
            'DROWN': r'DROWN.*?(?:VULNERABLE|not vulnerable)',
            'LOGJAM': r'LOGJAM.*?(?:VULNERABLE|not vulnerable|no DH)',
            'BEAST': r'BEAST.*?(?:VULNERABLE|not vulnerable)',
            'LUCKY13': r'LUCKY13.*?(?:VULNERABLE|not vulnerable)',
            'Winshock': r'Winshock.*?(?:VULNERABLE|not vulnerable)',
            'RC4': r'RC4.*?(?:detected|no RC4)'
        }
        
        for vuln, pattern in patterns.items():
            match = re.search(pattern, section, re.IGNORECASE | re.DOTALL)
            
            if match:
                text = match.group(0).lower()
                if 'vulnerable' in text and 'not vulnerable' not in text:
                    vulnerabilidades[vuln] = True
                elif 'detected' in text and 'no rc4' not in text:
                    vulnerabilidades[vuln] = True
                else:
                    vulnerabilidades[vuln] = False
        
        return vulnerabilidades
    
    def get_result(self) -> SecurityScan:
        """Retorna el resultado completo del parseo"""
        return SecurityScan(
            ip=self.ip,
            puerto=self.puerto,
            protocolos=self.parse_protocols(),
            vulnerabilidades=self.parse_vulnerabilities(),
            archivo_origen=self.filename
        )


# ============================================================================
# GENERADORES DE REPORTES
# ============================================================================

class HTMLReportGenerator:
    """Genera reportes HTML profesionales con colores explícitos"""
    
    @staticmethod
    def generate(datos: List[SecurityScan], output_file: str = "reporte_ssl_vulnerabilidades.html"):
        """Genera un reporte HTML con tabla visual mejorada"""
        
        todos_protocolos = set()
        todas_vulns = set()
        
        for escan in datos:
            todos_protocolos.update(escan.protocolos.keys())
            todas_vulns.update(escan.vulnerabilidades.keys())
        
        todos_protocolos = sorted(list(todos_protocolos))
        todas_vulns = sorted(list(todas_vulns))
        
        html = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Vulnerabilidades SSL/TLS - testssl.sh</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 30px;
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            text-align: center;
            font-size: 2.5em;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        
        .section-title {
            font-size: 1.5em;
            color: #333;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        thead {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: bold;
            position: sticky;
            top: 0;
        }
        
        th {
            padding: 18px;
            text-align: left;
            font-size: 0.95em;
        }
        
        td {
            padding: 14px 18px;
            border-bottom: 1px solid #e0e0e0;
            font-size: 0.95em;
        }
        
        tbody tr:hover {
            background-color: #f5f5f5;
            transition: background-color 0.2s ease;
        }
        
        tbody tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        
        .ip-puerto {
            font-weight: bold;
            color: #333;
            font-family: 'Courier New', monospace;
            font-size: 1.05em;
        }
        
        /* COLORES EXPLÍCITOS v2.1 */
        .ok {
            background-color: #d4edda;
            color: #155724;
            padding: 8px 12px;
            border-radius: 6px;
            font-weight: bold;
            text-align: center;
            border: 2px solid #28a745;
            font-size: 0.9em;
            display: inline-block;
            width: 90%;
        }
        
        .vulnerable {
            background-color: #f8d7da;
            color: #721c24;
            padding: 8px 12px;
            border-radius: 6px;
            font-weight: bold;
            text-align: center;
            border: 2px solid #dc3545;
            font-size: 0.9em;
            display: inline-block;
            width: 90%;
        }
        
        .legend {
            display: flex;
            gap: 30px;
            margin: 30px 0;
            padding: 20px;
            background: #f5f5f5;
            border-radius: 8px;
            flex-wrap: wrap;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .legend-badge {
            width: 100px;
            padding: 10px;
            border-radius: 6px;
            font-weight: bold;
            text-align: center;
            min-width: 100px;
            font-size: 0.9em;
        }
        
        .summary {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 1.1em;
        }
        
        .footer {
            text-align: center;
            color: #666;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            font-size: 0.9em;
        }
        
        .version-badge {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            margin-top: 10px;
        }
        
        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Reporte de Vulnerabilidades SSL/TLS</h1>
        <p class="subtitle">Análisis automático con testssl.sh
            <span class="version-badge">v2.1 Final</span>
        </p>
        
        <div class="legend">
            <div class="legend-item">
                <span class="legend-badge ok">✓ OK</span>
                <span><strong style="color: green;">VERDE</strong> - Seguro / No vulnerable</span>
            </div>
            <div class="legend-item">
                <span class="legend-badge vulnerable">❌ X</span>
                <span><strong style="color: red;">ROJO</strong> - Vulnerable / Requiere acción</span>
            </div>
        </div>
"""
        
        html += """
        <h2 class="section-title">📋 Análisis de Protocolos TLS/SSL</h2>
        <table>
            <thead>
                <tr>
                    <th>IP:Puerto</th>
"""
        
        for protocolo in todos_protocolos:
            html += f"                    <th>{protocolo}</th>\n"
        
        html += """                </tr>
            </thead>
            <tbody>
"""
        
        datos_ordenados = HTMLReportGenerator._sort_by_ip_port(datos)
        
        for escan in datos_ordenados:
            html += f"""                <tr>
                    <td class="ip-puerto">{escan.ip}:{escan.puerto}</td>
"""
            for protocolo in todos_protocolos:
                es_vulnerable = escan.protocolos.get(protocolo, False)
                clase = "vulnerable" if es_vulnerable else "ok"
                signo = "❌ X" if es_vulnerable else "✓ OK"
                html += f"                    <td><span class=\"{clase}\">{signo}</span></td>\n"
            
            html += "                </tr>\n"
        
        html += """            </tbody>
        </table>
"""
        
        html += """
        <h2 class="section-title">⚠️ Análisis de Vulnerabilidades Conocidas</h2>
        <table>
            <thead>
                <tr>
                    <th>IP:Puerto</th>
"""
        
        for vuln in todas_vulns:
            html += f"                    <th>{vuln}</th>\n"
        
        html += """                </tr>
            </thead>
            <tbody>
"""
        
        for escan in datos_ordenados:
            html += f"""                <tr>
                    <td class="ip-puerto">{escan.ip}:{escan.puerto}</td>
"""
            for vuln in todas_vulns:
                es_vulnerable = escan.vulnerabilidades.get(vuln, False)
                clase = "vulnerable" if es_vulnerable else "ok"
                signo = "❌ X" if es_vulnerable else "✓ OK"
                html += f"                    <td><span class=\"{clase}\">{signo}</span></td>\n"
            
            html += "                </tr>\n"
        
        html += """            </tbody>
        </table>
"""
        
        total_ips = len(datos)
        total_vuln = sum(1 for e in datos for v in e.vulnerabilidades.values() if v)
        total_proto_vuln = sum(1 for e in datos for v in e.protocolos.values() if v)
        
        html += f"""
        <div class="summary">
            <strong>📊 Resumen del Análisis:</strong><br>
            Total de hosts analizados: <strong>{total_ips}</strong><br>
            Vulnerabilidades detectadas: <strong>{total_vuln}</strong><br>
            Protocolos vulnerables/deprecados: <strong>{total_proto_vuln}</strong>
        </div>
"""
        
        html += f"""
        <div class="footer">
            <p>Reporte generado automáticamente | testssl.sh analysis</p>
            <p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Versión:</strong> testssl-analyzer v2.1 Final</p>
            <p>Lógica Confirmada:</p>
            <ul style="text-align: left; display: inline-block;">
                <li>SSLv2, SSLv3, TLSv1, TLSv1.1: ❌ X ROJO si offered / ✓ OK VERDE si not offered</li>
                <li>TLSv1.2, TLSv1.3: ✓ OK VERDE si offered / ❌ X ROJO si not offered</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\n✓ Reporte HTML generado: {output_file}")
    
    @staticmethod
    def _sort_by_ip_port(datos: List[SecurityScan]) -> List[SecurityScan]:
        """Ordena los datos por IP y puerto"""
        def sort_key(escan):
            try:
                partes_ip = [int(x) for x in escan.ip.split('.')]
                puerto = int(escan.puerto)
                return (partes_ip, puerto)
            except:
                return ([], 0)
        
        return sorted(datos, key=sort_key)


class CSVReportGenerator:
    """Genera reportes en formato CSV"""
    
    @staticmethod
    def generate(datos: List[SecurityScan], output_file: str = "reporte_ssl_vulnerabilidades.csv"):
        """Genera un reporte CSV"""
        
        import csv
        
        todos_protocolos = set()
        todas_vulns = set()
        
        for escan in datos:
            todos_protocolos.update(escan.protocolos.keys())
            todas_vulns.update(escan.vulnerabilidades.keys())
        
        todos_protocolos = sorted(list(todos_protocolos))
        todas_vulns = sorted(list(todas_vulns))
        
        datos_ordenados = HTMLReportGenerator._sort_by_ip_port(datos)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            campos = ['IP', 'Puerto'] + todos_protocolos + todas_vulns
            writer = csv.DictWriter(f, fieldnames=campos)
            
            writer.writeheader()
            
            for escan in datos_ordenados:
                fila = {
                    'IP': escan.ip,
                    'Puerto': escan.puerto
                }
                
                for proto in todos_protocolos:
                    fila[proto] = 'VULNERABLE' if escan.protocolos.get(proto, False) else 'OK'
                
                for vuln in todas_vulns:
                    fila[vuln] = 'VULNERABLE' if escan.vulnerabilidades.get(vuln, False) else 'OK'
                
                writer.writerow(fila)
        
        print(f"✓ Reporte CSV generado: {output_file}")


class JSONReportGenerator:
    """Genera reportes en formato JSON"""
    
    @staticmethod
    def generate(datos: List[SecurityScan], output_file: str = "resultados_testssl.json"):
        """Genera un reporte JSON"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump([d.to_dict() for d in datos], f, indent=2, ensure_ascii=False)
        
        print(f"✓ Reporte JSON generado: {output_file}")


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main():
    """Función principal del programa"""
    
    parser = argparse.ArgumentParser(
        description='Analizador avanzado de reportes HTML de testssl.sh v2.1 Final',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 testssl_analyzer.py .
  python3 testssl_analyzer.py /path/to/html/files
  python3 testssl_analyzer.py --output reporte_personalizado.html
  python3 testssl_analyzer.py . --csv --json -v
        """
    )
    
    parser.add_argument(
        'directorio',
        nargs='?',
        default='.',
        help='Directorio con archivos HTML de testssl.sh (default: .)'
    )
    parser.add_argument(
        '-o', '--output',
        default='reporte_ssl_vulnerabilidades.html',
        help='Archivo de salida HTML (default: reporte_ssl_vulnerabilidades.html)'
    )
    parser.add_argument(
        '--csv',
        action='store_true',
        help='Generar también reporte en CSV'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Generar también reporte en JSON'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verbose (más detalles)'
    )
    
    args = parser.parse_args()
    
    # Banner
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║           testssl.sh HTML Report Analyzer v2.1 - Final                    ║
║         Procesador de vulnerabilidades SSL/TLS con lógica comprobada      ║
║                   Colores ROJO y VERDE explícitos confirmados            ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Buscar archivos HTML
    directorio = Path(args.directorio)
    
    if not directorio.exists():
        print(f"❌ Error: El directorio {directorio} no existe")
        sys.exit(1)
    
    archivos_html = list(directorio.glob('*.html'))
    
    if not archivos_html:
        print(f"❌ No se encontraron archivos .html en {directorio}")
        sys.exit(1)
    
    print(f"📂 Directorio: {directorio}")
    print(f"📄 Archivos encontrados: {len(archivos_html)}\n")
    
    # Procesar archivos
    resultados = []
    for archivo in sorted(archivos_html):
        print(f"⏳ Procesando: {archivo.name}...")
        
        try:
            parser = TestSSLParser(str(archivo))
            resultado = parser.get_result()
            resultados.append(resultado)
            
            vulns = sum(1 for v in resultado.vulnerabilidades.values() if v)
            proto_vulns = sum(1 for v in resultado.protocolos.values() if v)
            
            print(f"  ✓ IP: {resultado.ip}:{resultado.puerto}")
            
            if args.verbose:
                print(f"    - Vulnerabilidades: {vulns}")
                print(f"    - Protocolos vulnerables: {proto_vulns}")
        
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
    
    if not resultados:
        print("❌ No se pudieron procesar archivos")
        sys.exit(1)
    
    print(f"\n✓ Se procesaron {len(resultados)} archivo(s)\n")
    
    # Generar reportes
    print("📊 Generando reportes...")
    HTMLReportGenerator.generate(resultados, args.output)
    
    if args.csv:
        CSVReportGenerator.generate(resultados)
    
    if args.json:
        JSONReportGenerator.generate(resultados)
    
    # Resumen final
    print("\n" + "="*70)
    print("RESUMEN DEL ANÁLISIS - v2.1 FINAL")
    print("="*70)
    
    total_hosts = len(resultados)
    total_vulns = sum(1 for r in resultados for v in r.vulnerabilidades.values() if v)
    total_proto_vulns = sum(1 for r in resultados for v in r.protocolos.values() if v)
    
    print(f"\nTotal de hosts analizados: {total_hosts}")
    print(f"Total de vulnerabilidades: {total_vulns}")
    print(f"Total de protocolos vulnerables: {total_proto_vulns}")
    
    print(f"\n✓ Reporte disponible en: {args.output}")
    print("""
LÓGICA APLICADA (v2.1 CONFIRMADA):
├─ SSLv2: offered → ❌ X ROJO | not offered → ✓ OK VERDE
├─ SSLv3: offered → ❌ X ROJO | not offered → ✓ OK VERDE
├─ TLSv1: offered → ❌ X ROJO | not offered → ✓ OK VERDE
├─ TLSv1.1: offered → ❌ X ROJO | not offered → ✓ OK VERDE
├─ TLSv1.2: offered → ✓ OK VERDE | not offered → ❌ X ROJO
└─ TLSv1.3: offered → ✓ OK VERDE | not offered → ❌ X ROJO
""")
    print("\n¡Análisis completado exitosamente!\n")


if __name__ == '__main__':
    main()
