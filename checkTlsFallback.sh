for f in *.html; do
    ip=$(grep -oP '->>\s+\K[\d.]+' "$f")
    if grep -qi "Downgrade attack prevention NOT supported" "$f"; then
        echo "$ip - TLS_FALLBACK downgrade prevention NOT supported"
    fi
done
for f in *.html; do
    ip=$(grep -oP '->>\s+\K[\d.]+' "$f")
    if grep -qi "Downgrade attack prevention NOT supported" "$f"; then
        echo "$ip - TLS_FALLBACK downgrade prevention NOT supported"
    fi
done
