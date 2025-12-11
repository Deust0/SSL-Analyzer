for f in *.html; do
    echo "Archivo: $f"
    ip=$(grep -oP '->>\s+\K[\d.]+(?=: )' "$f")
    echo "IP: $ip"
    awk '/Testing_protocols/{flag=1; next} /^[[:space:]]*$/{flag=0} flag' "$f" \
        | sed -E 's/(offered|not offered).*/\1/' \
        | sed -E 's/^[[:space:]]*//' \
        | grep -E 'offered|not offered'
    echo
done
