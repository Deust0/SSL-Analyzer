#!/bin/bash

outfile="reporte_protocolos.html"

echo "<html><head><meta charset='UTF-8'><style>
td { padding: 6px; font-family: Arial; }
.ok { background-color: #b6ffb6; font-weight: bold; }
.bad { background-color: #ffb6b6; font-weight: bold; }
</style></head><body>" > "$outfile"

echo "<h2>Reporte de Protocolos</h2>" >> "$outfile"

for f in *.html; do
    ip=$(grep -oP '->>\s+\K[\d.]+' "$f")

    echo "<h3>IP: $ip</h3>" >> "$outfile"
    echo "<table border='1' cellspacing='0'><tr><th>Protocolo</th><th>Estado</th><th>Resultado</th></tr>" >> "$outfile"

    sed -n '/Testing protocols/,/ALPN\/HTTP2/p' "$f" \
        | grep -E 'SSL|TLS|NPN|ALPN' \
        | sed -E 's/<[^>]+>//g' \
        | sed -E 's/^[[:space:]]+//; s/[[:space:]]+/ /g' | while read -r line; do

            proto=$(echo "$line" | cut -d' ' -f1,2 | sed 's/ $//')
            status=$(echo "$line" | sed -E 's/^[^ ]+ //')

            normproto=$(echo "$proto" | tr '[:upper:]' '[:lower:]')
            normstatus=$(echo "$status" | tr '[:upper:]' '[:lower:]')

            result=""
            css=""

            if [[ "$normproto" =~ sslv[1-3] ]]; then
                if [[ "$normstatus" =~ offered ]]; then
                    result="X"; css="bad"
                else
                    result="OK"; css="ok"
                fi
            elif [[ "$normproto" =~ tls\ 1$ || "$normproto" =~ tls\ 1\.1$ ]]; then
                if [[ "$normstatus" =~ offered ]]; then
                    result="X"; css="bad"
                else
                    result="OK"; css="ok"
                fi
            elif [[ "$normproto" =~ tls\ 1\.2$ || "$normproto" =~ tls\ 1\.3$ ]]; then
                if [[ "$normstatus" =~ offered ]]; then
                    result="OK"; css="ok"
                else
                    result=""; css=""
                fi
            fi

            echo "<tr><td>$proto</td><td>$status</td><td class='$css'>$result</td></tr>" >> "$outfile"

    done

    echo "</table><br>" >> "$outfile"
done

echo "</body></html>" >> "$outfile"

echo "Reporte generado: $outfile"
