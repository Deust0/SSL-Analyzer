#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
testssl.sh HTML Report Analyzer v2.2 - Final Optimizado
Análisis de vulnerabilidades SSL/TLS desde reportes HTML
Detección de protocolos vulnerables, TLS_FALLBACK y tabla responsive
"""

import os
import json
import csv
import sys
import re
from pathlib import Path
from html import escape
from datetime import datetime

class TestSSLAnalyzer:
    """Analizador de reportes HTML de testssl.sh con detección de vulnerabilidades"""
    
    def __init__(self):
        self.results = []
        self.vulnerable_protocols = ['SSLv2', 'SSLv3', 'TLS 1', 'TLS 1.1']
        self.secure_protocols = ['TLS 1.2', 'TLS 1.3']
        
    def extract_ip_port(self, filename):
        """Extrae IP y puerto del nombre del archivo"""
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)_p(\d+)', filename)
        if match:
            return f"{match.group(1)}:{match.group(2)}"
        return "Unknown"
    
    def extract_protocols(self, content):
        """Extrae información de protocolos del contenido HTML"""
        protocols = {}
        
        protocol_patterns = {
            'SSLv2': r'SSLv2\s*</span>.*?<span[^>]*>(.*?)</span>',
            'SSLv3': r'SSLv3\s*</span>.*?<span[^>]*>(.*?)</span>',
            'TLS 1.0': r'TLS 1\s*</span>.*?<span[^>]*>(.*?)</span>',
            'TLS 1.1': r'TLS 1\.1\s*</span>.*?<span[^>]*>(.*?)</span>',
            'TLS 1.2': r'TLS 1\.2\s*</span>.*?<span[^>]*>(.*?)</span>',
            'TLS 1.3': r'TLS 1\.3\s*</span>.*?<span[^>]*>(.*?)</span>',
        }
        
        for protocol, pattern in protocol_patterns.items():
            match = re.search(pattern, content)
            if match:
                status = match.group(1).strip().lower()
                protocols[protocol] = status
        
        return protocols
    
    def extract_tls_fallback(self, content):
        """Extrae información de TLS_FALLBACK SCSV"""
        patterns = [
            r'TLS FALLBACK.*?SCSV.*?</span>.*?<span[^>]*>(.*?)</span>',
            r'TLS FALLBACK SCSV.*?<span[^>]*>(.*?)</span>',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match:
                status = match.group(1).strip().lower()
                
                # Normalizar los posibles valores
                if 'downgrade attack prevention' in status or 'supported' in status:
                    return 'supported'  # ✓ OK VERDE
                elif 'no fallback' in status:
                    return 'safe'  # ✓ OK VERDE (no fallback posible)
                elif 'not supported' in status or 'vulnerable' in status:
                    return 'vulnerable'  # ❌ X ROJO
        
        return None
    
    def evaluate_protocol(self, protocol, status):
        """Evalúa un protocolo y retorna (símbolo, color)"""
        if not status:
            return ('?', 'gray')
        
        status = status.lower()
        
        # Protocolos vulnerables
        if protocol in self.vulnerable_protocols:
            if 'offered' in status:
                return ('❌', 'red')  # X ROJO - vulnerable y habilitado
            elif 'not offered' in status:
                return ('✓', 'green')  # OK VERDE - vulnerable pero deshabilitado
        
        # Protocolos seguros
        elif protocol in self.secure_protocols:
            if 'offered' in status:
                return ('✓', 'green')  # OK VERDE - seguro y habilitado
            elif 'not offered' in status:
                return ('❌', 'red')  # X ROJO - seguro pero no disponible
        
        return ('?', 'gray')
    
    def evaluate_tls_fallback(self, status):
        """Evalúa TLS_FALLBACK SCSV"""
        if not status:
            return ('?', 'gray', 'N/A')
        
        status = status.lower()
        if 'supported' in status or 'safe' in status:
            return ('✓', 'green', 'Supported')
        elif 'vulnerable' in status or 'not supported' in status:
            return ('❌', 'red', 'Vulnerable')
        
        return ('?', 'gray', 'Unknown')
    
    def process_file(self, filepath):
        """Procesa un archivo HTML de testssl.sh"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error leyendo {filepath}: {e}")
            return None
        
        ip_port = self.extract_ip_port(filepath)
        protocols = self.extract_protocols(content)
        tls_fallback = self.extract_tls_fallback(content)
        
        result = {
            'ip_port': ip_port,
            'protocols': {},
            'tls_fallback': tls_fallback,
            'filename': os.path.basename(filepath)
        }
        
        for protocol, status in protocols.items():
            symbol, color = self.evaluate_protocol(protocol, status)
            result['protocols'][protocol] = {
                'status': status,
                'symbol': symbol,
                'color': color
            }
        
        return result
    
    def analyze_directory(self, directory):
        """Analiza todos los archivos HTML en un directorio"""
        html_files = list(Path(directory).glob('*.html'))
        
        if not html_files:
            print(f"⚠️  No se encontraron archivos HTML en {directory}")
            return []
        
        print(f"📂 Directorio: {directory}")
        print(f"📄 Archivos encontrados: {len(html_files)}\n")
        
        for html_file in sorted(html_files):
            print(f"⏳ Procesando: {html_file.name}...")
            result = self.process_file(str(html_file))
            if result:
                self.results.append(result)
                print(f"  ✓ IP: {result['ip_port']}")
        
        print(f"\n✓ Se procesaron {len(self.results)} archivo(s)\n")
        return self.results
    
    def generate_html_report(self, output_file='reporte_ssl_vulnerabilidades.html'):
        """Genera un reporte HTML profesional con tablas divididas"""
        
        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte SSL/TLS - Análisis de Vulnerabilidades v2.2</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Ubuntu', sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #333;
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 32px;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header p {{
            font-size: 16px;
            opacity: 0.95;
            margin-bottom: 5px;
        }}
        
        .header .version {{
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 13px;
            margin-top: 15px;
            font-weight: 500;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .summary-card h3 {{
            font-size: 13px;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 10px;
            font-weight: 600;
            letter-spacing: 1px;
        }}
        
        .summary-card .value {{
            font-size: 32px;
            font-weight: 700;
            color: #333;
        }}
        
        .legend {{
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border: 1px solid #e0e0e0;
        }}
        
        .legend h3 {{
            margin-bottom: 15px;
            font-size: 16px;
            color: #333;
        }}
        
        .legend-items {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .legend-box {{
            width: 60px;
            height: 40px;
            border-radius: 6px;
            border: 2px solid;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            flex-shrink: 0;
        }}
        
        .legend-box.green {{
            background: #d4edda;
            border-color: #28a745;
            color: #155724;
        }}
        
        .legend-box.red {{
            background: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }}
        
        .legend-text {{
            font-size: 13px;
            color: #555;
        }}
        
        .section-title {{
            font-size: 18px;
            font-weight: 700;
            color: #333;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        
        .tables-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .table-wrapper {{
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border: 1px solid #e0e0e0;
        }}
        
        .table-title {{
            background: #f5f7fa;
            padding: 15px;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #e0e0e0;
            font-size: 14px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        
        thead {{
            background: #f9f9f9;
        }}
        
        th {{
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #555;
            border-bottom: 2px solid #e0e0e0;
            font-size: 13px;
        }}
        
        td {{
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        tr:hover {{
            background: #f5f5f5;
        }}
        
        .ip-cell {{
            font-weight: 600;
            color: #667eea;
            font-family: 'Courier New', monospace;
        }}
        
        .status-cell {{
            text-align: center;
            font-weight: 600;
        }}
        
        .status-green {{
            background: #d4edda;
            border: 1px solid #28a745;
            color: #155724;
            padding: 8px 12px;
            border-radius: 6px;
            display: inline-block;
            min-width: 70px;
        }}
        
        .status-red {{
            background: #f8d7da;
            border: 1px solid #dc3545;
            color: #721c24;
            padding: 8px 12px;
            border-radius: 6px;
            display: inline-block;
            min-width: 70px;
        }}
        
        .status-gray {{
            background: #e9ecef;
            border: 1px solid #adb5bd;
            color: #495057;
            padding: 8px 12px;
            border-radius: 6px;
            display: inline-block;
            min-width: 70px;
        }}
        
        .footer {{
            background: #f9f9f9;
            padding: 20px;
            border-top: 2px solid #e0e0e0;
            text-align: center;
            color: #666;
            font-size: 12px;
        }}
        
        .timestamp {{
            color: #999;
            margin-top: 10px;
        }}
        
        @media (max-width: 768px) {{
            .tables-grid {{
                grid-template-columns: 1fr;
            }}
            
            .header {{
                padding: 20px;
            }}
            
            .header h1 {{
                font-size: 24px;
            }}
            
            .content {{
                padding: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Análisis de Vulnerabilidades SSL/TLS</h1>
            <p>testssl.sh Report Analyzer v2.2</p>
            <p>Detección de protocolos inseguros y vulnerabilidades</p>
            <span class="version">VERSIÓN 2.2 - MEJORADA</span>
        </div>
        
        <div class="content">
            <!-- RESUMEN -->
            <div class="summary">
                <div class="summary-card">
                    <h3>Hosts Analizados</h3>
                    <div class="value">{len(self.results)}</div>
                </div>
                <div class="summary-card">
                    <h3>Vulnerabilidades Detectadas</h3>
                    <div class="value">{self._count_vulnerabilities()}</div>
                </div>
                <div class="summary-card">
                    <h3>TLS FALLBACK Inseguro</h3>
                    <div class="value">{self._count_fallback_vulnerable()}</div>
                </div>
                <div class="summary-card">
                    <h3>Servidores Seguros</h3>
                    <div class="value">{self._count_secure_servers()}</div>
                </div>
            </div>
            
            <!-- LEYENDA -->
            <div class="legend">
                <h3>📌 Leyenda de Colores</h3>
                <div class="legend-items">
                    <div class="legend-item">
                        <div class="legend-box green">✓</div>
                        <div class="legend-text">
                            <strong>VERDE (✓ OK)</strong><br>
                            Configuración segura - Sin acción requerida
                        </div>
                    </div>
                    <div class="legend-item">
                        <div class="legend-box red">❌</div>
                        <div class="legend-text">
                            <strong>ROJO (❌ X)</strong><br>
                            Vulnerable - Requiere atención inmediata
                        </div>
                    </div>
                </div>
            </div>
            
            {self._generate_tables_html()}
            
        </div>
        
        <div class="footer">
            <strong>Reporte Generado:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            <div class="timestamp">
                Análisis realizado con testssl.sh Report Analyzer v2.2
            </div>
        </div>
    </div>
</body>
</html>"""
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"✓ Reporte HTML generado: {output_file}")
            return True
        except Exception as e:
            print(f"Error generando reporte HTML: {e}")
            return False
    
    def _count_vulnerabilities(self):
        """Cuenta el total de vulnerabilidades detectadas"""
        count = 0
        for result in self.results:
            for protocol, data in result['protocols'].items():
                if data['color'] == 'red':
                    count += 1
        return count
    
    def _count_fallback_vulnerable(self):
        """Cuenta servidores con TLS_FALLBACK vulnerable"""
        count = 0
        for result in self.results:
            symbol, color, status = self.evaluate_tls_fallback(result['tls_fallback'])
            if color == 'red':
                count += 1
        return count
    
    def _count_secure_servers(self):
        """Cuenta servidores completamente seguros"""
        secure = 0
        for result in self.results:
            if all(data['color'] != 'red' for data in result['protocols'].values()):
                symbol, color, _ = self.evaluate_tls_fallback(result['tls_fallback'])
                if color != 'red':
                    secure += 1
        return secure
    
    def _generate_tables_html(self):
        """Genera las tablas HTML divididas en 3 secciones"""
        if not self.results:
            return ""
        
        html = '<div class="section-title">📊 Análisis de Protocolos</div>'
        html += '<div class="tables-grid">'
        
        # Tabla 1: Protocolos Vulnerables
        html += self._generate_protocol_table(
            'Protocolos Vulnerables (SSLv2, SSLv3, TLSv1, TLSv1.1)',
            ['SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1']
        )
        
        # Tabla 2: Protocolos Seguros
        html += self._generate_protocol_table(
            'Protocolos Seguros (TLSv1.2, TLSv1.3)',
            ['TLS 1.2', 'TLS 1.3']
        )
        
        html += '</div>'  # Cierra tables-grid
        
        # Tabla 3: TLS FALLBACK SCSV
        html += '<div class="section-title">🛡️ Mitigaciones y Protecciones</div>'
        html += self._generate_tls_fallback_table()
        
        return html
    
    def _generate_protocol_table(self, title, protocols):
        """Genera tabla HTML para un grupo de protocolos"""
        html = f'<div class="table-wrapper"><div class="table-title">{title}</div>'
        html += '<table><thead><tr><th>IP:PUERTO</th>'
        
        for proto in protocols:
            html += f'<th>{proto}</th>'
        
        html += '</tr></thead><tbody>'
        
        for result in self.results:
            html += f'<tr><td class="ip-cell">{escape(result["ip_port"])}</td>'
            
            for proto in protocols:
                if proto in result['protocols']:
                    data = result['protocols'][proto]
                    symbol = data['symbol']
                    color = data['color']
                    
                    if color == 'green':
                        css_class = 'status-green'
                    elif color == 'red':
                        css_class = 'status-red'
                    else:
                        css_class = 'status-gray'
                    
                    html += f'<td class="status-cell"><div class="{css_class}">{symbol}</div></td>'
                else:
                    html += '<td class="status-cell"><div class="status-gray">?</div></td>'
            
            html += '</tr>'
        
        html += '</tbody></table></div>'
        return html
    
    def _generate_tls_fallback_table(self):
        """Genera tabla HTML para TLS FALLBACK SCSV"""
        html = '<div class="table-wrapper"><div class="table-title">TLS FALLBACK SCSV Prevention (RFC 7507)</div>'
        html += '<table><thead><tr><th>IP:PUERTO</th><th>Estado</th><th>Descripción</th></tr></thead><tbody>'
        
        for result in self.results:
            symbol, color, status = self.evaluate_tls_fallback(result['tls_fallback'])
            
            if color == 'green':
                css_class = 'status-green'
                description = '✓ Protegido contra downgrade attacks'
            elif color == 'red':
                css_class = 'status-red'
                description = '❌ Vulnerable a downgrade attacks'
            else:
                css_class = 'status-gray'
                description = '? Estado desconocido'
            
            html += f'<tr>'
            html += f'<td class="ip-cell">{escape(result["ip_port"])}</td>'
            html += f'<td class="status-cell"><div class="{css_class}">{symbol}</div></td>'
            html += f'<td>{description}</td>'
            html += f'</tr>'
        
        html += '</tbody></table></div>'
        return html
    
    def export_csv(self, output_file='resultados_testssl.csv'):
        """Exporta resultados a CSV"""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                protocols = self.vulnerable_protocols + self.secure_protocols
                header = ['IP:PUERTO', 'TLS_FALLBACK'] + protocols
                writer.writerow(header)
                
                for result in self.results:
                    row = [result['ip_port']]
                    
                    symbol, color, _ = self.evaluate_tls_fallback(result['tls_fallback'])
                    row.append(symbol)
                    
                    for protocol in protocols:
                        if protocol in result['protocols']:
                            row.append(result['protocols'][protocol]['symbol'])
                        else:
                            row.append('?')
                    
                    writer.writerow(row)
            
            print(f"✓ Reporte CSV generado: {output_file}")
            return True
        except Exception as e:
            print(f"Error exportando CSV: {e}")
            return False
    
    def export_json(self, output_file='resultados_testssl.json'):
        """Exporta resultados a JSON"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"✓ Reporte JSON generado: {output_file}")
            return True
        except Exception as e:
            print(f"Error exportando JSON: {e}")
            return False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='testssl.sh HTML Report Analyzer v2.2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos de uso:
  python3 testssl_v22.py .
  python3 testssl_v22.py . --csv --json
  python3 testssl_v22.py /datos -o reporte.html
  python3 testssl_v22.py . -v
        '''
    )
    
    parser.add_argument('directory', nargs='?', default='.',
                        help='Directorio con archivos HTML (default: .)')
    parser.add_argument('-o', '--output', default='reporte_ssl_vulnerabilidades.html',
                        help='Archivo de salida HTML')
    parser.add_argument('--csv', action='store_true',
                        help='Exportar también a CSV')
    parser.add_argument('--json', action='store_true',
                        help='Exportar también a JSON')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Modo verbose (más detalles)')
    
    args = parser.parse_args()
    
    print("""
╔════════════════════════════════════════════════════════════════╗
║     testssl.sh HTML Report Analyzer v2.2 - MEJORADO           ║
║  Detección de protocolos vulnerables y TLS FALLBACK SCSV     ║
║         Tabla responsive dividida en 3 secciones              ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    analyzer = TestSSLAnalyzer()
    analyzer.analyze_directory(args.directory)
    
    if analyzer.results:
        analyzer.generate_html_report(args.output)
        
        if args.csv:
            analyzer.export_csv()
        
        if args.json:
            analyzer.export_json()
        
        print("\n" + "="*60)
        print("RESUMEN DEL ANÁLISIS - v2.2")
        print("="*60)
        print(f"Total de hosts analizados: {len(analyzer.results)}")
        print(f"Total de vulnerabilidades: {analyzer._count_vulnerabilities()}")
        print(f"TLS FALLBACK inseguro: {analyzer._count_fallback_vulnerable()}")
        print(f"Servidores seguros: {analyzer._count_secure_servers()}")
        print("\n✓ Reporte disponible en:", args.output)
        print("\n" + "="*60)
    else:
        print("⚠️  No se encontraron archivos para analizar")
        sys.exit(1)


if __name__ == '__main__':
    main()
