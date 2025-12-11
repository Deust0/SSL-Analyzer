#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
testssl.sh HTML Report Analyzer v2.1+ - Interface Mejorada
Análisis de vulnerabilidades SSL/TLS desde reportes HTML
Con interfaz gráfica profesional y responsive
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
            'TLS 1': r'TLS 1\s*</span>.*?<span[^>]*>(.*?)</span>',
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
        
        result = {
            'ip_port': ip_port,
            'protocols': {},
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
        """Genera un reporte HTML profesional con interfaz mejorada"""
        
        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte SSL/TLS - Análisis de Vulnerabilidades</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 50px 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 36px;
            margin-bottom: 10px;
            font-weight: 700;
            letter-spacing: -1px;
        }}
        
        .header p {{
            font-size: 16px;
            opacity: 0.95;
            margin-bottom: 5px;
        }}
        
        .header .badge {{
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 50px;
            font-size: 13px;
            margin-top: 15px;
            font-weight: 600;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.3);
        }}
        
        .content {{
            padding: 50px 40px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 50px;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px;
            border-radius: 12px;
            border-left: 5px solid #667eea;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.1);
            transition: transform 0.3s ease;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
        }}
        
        .summary-card h3 {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 12px;
            font-weight: 700;
            letter-spacing: 1.5px;
        }}
        
        .summary-card .value {{
            font-size: 38px;
            font-weight: 800;
            color: #667eea;
        }}
        
        .legend {{
            background: linear-gradient(135deg, #f9f9f9 0%, #f0f0f0 100%);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 40px;
            border: 1px solid #e0e0e0;
        }}
        
        .legend h3 {{
            margin-bottom: 20px;
            font-size: 18px;
            color: #333;
            font-weight: 700;
        }}
        
        .legend-items {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .legend-box {{
            width: 70px;
            height: 50px;
            border-radius: 8px;
            border: 2.5px solid;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 20px;
            flex-shrink: 0;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
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
            font-size: 14px;
            color: #555;
            line-height: 1.5;
        }}
        
        .legend-text strong {{
            color: #333;
            display: block;
            margin-bottom: 3px;
        }}
        
        .section-title {{
            font-size: 20px;
            font-weight: 700;
            color: #333;
            margin-top: 50px;
            margin-bottom: 25px;
            padding-bottom: 12px;
            border-bottom: 3px solid #667eea;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-title::before {{
            content: '';
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #667eea;
            border-radius: 50%;
        }}
        
        .table-container {{
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            border: 1px solid #e0e0e0;
            margin-bottom: 30px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        
        thead {{
            background: linear-gradient(135deg, #f5f7fa 0%, #e9ecef 100%);
        }}
        
        th {{
            padding: 18px;
            text-align: center;
            font-weight: 700;
            color: #555;
            border-bottom: 2px solid #e0e0e0;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        th:first-child {{
            text-align: left;
        }}
        
        td {{
            padding: 16px 18px;
            border-bottom: 1px solid #f0f0f0;
            text-align: center;
        }}
        
        td:first-child {{
            text-align: left;
            font-weight: 600;
            color: #667eea;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }}
        
        tbody tr {{
            transition: background-color 0.2s ease;
        }}
        
        tbody tr:hover {{
            background: #f9f9f9;
        }}
        
        tbody tr:nth-child(even) {{
            background: #f5f7fa;
        }}
        
        tbody tr:nth-child(even):hover {{
            background: #f0f2f5;
        }}
        
        .status-cell {{
            text-align: center;
        }}
        
        .status-green {{
            background: #d4edda;
            border: 2px solid #28a745;
            color: #155724;
            padding: 10px 14px;
            border-radius: 8px;
            display: inline-block;
            min-width: 60px;
            font-weight: 600;
            font-size: 16px;
            box-shadow: 0 2px 8px rgba(40, 167, 69, 0.15);
        }}
        
        .status-red {{
            background: #f8d7da;
            border: 2px solid #dc3545;
            color: #721c24;
            padding: 10px 14px;
            border-radius: 8px;
            display: inline-block;
            min-width: 60px;
            font-weight: 600;
            font-size: 16px;
            box-shadow: 0 2px 8px rgba(220, 53, 69, 0.15);
        }}
        
        .status-gray {{
            background: #e9ecef;
            border: 2px solid #adb5bd;
            color: #495057;
            padding: 10px 14px;
            border-radius: 8px;
            display: inline-block;
            min-width: 60px;
            font-weight: 600;
            font-size: 16px;
        }}
        
        .footer {{
            background: linear-gradient(135deg, #f5f7fa 0%, #e9ecef 100%);
            padding: 30px;
            border-top: 2px solid #e0e0e0;
            text-align: center;
            color: #666;
            font-size: 13px;
        }}
        
        .timestamp {{
            color: #999;
            margin-top: 10px;
            font-size: 12px;
        }}
        
        @media (max-width: 768px) {{
            .header {{
                padding: 30px 20px;
            }}
            
            .header h1 {{
                font-size: 26px;
            }}
            
            .content {{
                padding: 30px 20px;
            }}
            
            .summary {{
                grid-template-columns: 1fr;
            }}
            
            th, td {{
                padding: 12px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 SSL/TLS Security Analysis</h1>
            <p>testssl.sh Report Analyzer</p>
            <p>Detección de protocolos inseguros y vulnerabilidades</p>
            <span class="badge">✓ v2.1 INTERFACE MEJORADA</span>
        </div>
        
        <div class="content">
            <!-- RESUMEN EJECUTIVO -->
            <div class="summary">
                <div class="summary-card">
                    <h3>📊 Hosts Analizados</h3>
                    <div class="value">{len(self.results)}</div>
                </div>
                <div class="summary-card">
                    <h3>⚠️ Vulnerabilidades</h3>
                    <div class="value">{self._count_vulnerabilities()}</div>
                </div>
                <div class="summary-card">
                    <h3>✅ Servidores Seguros</h3>
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
                            Configuración segura
                        </div>
                    </div>
                    <div class="legend-item">
                        <div class="legend-box red">❌</div>
                        <div class="legend-text">
                            <strong>ROJO (❌ X)</strong><br>
                            Vulnerable - Acción requerida
                        </div>
                    </div>
                </div>
            </div>
            
            {self._generate_tables_html()}
            
        </div>
        
        <div class="footer">
            <strong>Reporte Generado:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            <div class="timestamp">
                Análisis realizado con testssl.sh Report Analyzer v2.1
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
    
    def _count_secure_servers(self):
        """Cuenta servidores completamente seguros"""
        secure = 0
        for result in self.results:
            if all(data['color'] != 'red' for data in result['protocols'].values()):
                secure += 1
        return secure
    
    def _generate_tables_html(self):
        """Genera las tablas HTML"""
        if not self.results:
            return ""
        
        html = '<div class="section-title">Protocolos Vulnerables (SSLv2, SSLv3, TLSv1, TLSv1.1)</div>'
        html += self._generate_protocol_table(
            ['SSLv2', 'SSLv3', 'TLS 1', 'TLS 1.1']
        )
        
        html += '<div class="section-title">Protocolos Seguros (TLSv1.2, TLSv1.3)</div>'
        html += self._generate_protocol_table(
            ['TLS 1.2', 'TLS 1.3']
        )
        
        return html
    
    def _generate_protocol_table(self, protocols):
        """Genera tabla HTML para un grupo de protocolos"""
        html = '<div class="table-container"><table><thead><tr><th>IP:PUERTO</th>'
        
        for proto in protocols:
            html += f'<th>{proto}</th>'
        
        html += '</tr></thead><tbody>'
        
        for result in self.results:
            html += f'<tr><td>{escape(result["ip_port"])}</td>'
            
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
    
    def export_csv(self, output_file='resultados_testssl.csv'):
        """Exporta resultados a CSV"""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                protocols = self.vulnerable_protocols + self.secure_protocols
                header = ['IP:PUERTO'] + protocols
                writer.writerow(header)
                
                for result in self.results:
                    row = [result['ip_port']]
                    
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
        description='testssl.sh HTML Report Analyzer v2.1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos de uso:
  python3 testssl_v21_mejorado.py .
  python3 testssl_v21_mejorado.py . --csv --json
  python3 testssl_v21_mejorado.py /datos -o reporte.html
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
    
    args = parser.parse_args()
    
    print("""
╔════════════════════════════════════════════════════════════════╗
║     testssl.sh HTML Report Analyzer v2.1 - INTERFACE MEJORADA  ║
║         Detección de protocolos vulnerables                   ║
║              Interfaz gráfica profesional y responsive         ║
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
        print("RESUMEN DEL ANÁLISIS - v2.1")
        print("="*60)
        print(f"Total de hosts analizados: {len(analyzer.results)}")
        print(f"Total de vulnerabilidades: {analyzer._count_vulnerabilities()}")
        print(f"Servidores seguros: {analyzer._count_secure_servers()}")
        print("\n✓ Reporte disponible en:", args.output)
        print("="*60)
    else:
        print("⚠️  No se encontraron archivos para analizar")
        sys.exit(1)


if __name__ == '__main__':
    main()
