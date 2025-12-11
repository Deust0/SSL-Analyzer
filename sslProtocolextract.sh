for f in *.html; do
    echo "Archivo: $f"

    # Extraer IP del encabezado
    ip=$(grep -oP '->>\s+\K[\d.]+' "$f")
    echo "IP: $ip"

    # Extraer protocolos y limpiar HTML
    sed -n '/Testing protocols/,/ALPN\/HTTP2/p' "$f" \
        | grep -E 'SSL|TLS|NPN|ALPN' \
        | sed -E 's/<[^>]+>//g' \
        | sed -E 's/^[[:space:]]+//; s/[[:space:]]+/ /g'

    echo
done
