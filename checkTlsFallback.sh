#!/bin/sh
# busca en todos los .html/.htm del directorio y muestra las IPs que tienen TLS_FALLBACK downgrade NOT supported

for f in *.html *.htm; do
  [ -e "$f" ] || continue

  # búsqueda insensible a mayúsculas de la cadena relevante
  if grep -qi 'downgrade attack prevention not supported' "$f"; then
    # extraer primera IP encontrada en el archivo
    ip="$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$f" | head -n1)"
    # si no se encontró IP con la línea anterior, intentar extraer la IP dentro de paréntesis después del puerto
    if [ -z "$ip" ]; then
      ip="$(grep -oE '\([[:space:]]*([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]*\)' "$f" | tr -d '()' | head -n1)"
    fi
    # Fallback si aún no hay IP (usar nombre de archivo)
    if [ -z "$ip" ]; then
      ip="$f"
    fi

    echo "$ip - TLS_FALLBACK_SCSV: Downgrade attack prevention NOT supported"
  fi
done
