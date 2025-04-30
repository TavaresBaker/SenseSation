#!/bin/sh

# Directories to search
SEARCH_DIR="/usr/local /etc /root /cf/conf /usr/local/www"

# Pattern to match
PATTERN="webhook"

# Temp match file
MATCHES="/tmp/webhook_matches.$$"
> "$MATCHES"

# Find all regular files
ALL_FILES=$(find $SEARCH_DIR -type f)
TOTAL=$(echo "$ALL_FILES" | wc -l)
[ "$TOTAL" -eq 0 ] && TOTAL=1

START=$(date +%s)
SCANNED=0

trap 'echo "\nAborted. Cleaning up."; rm -f "$MATCHES"; exit 1' INT

echo "🔍 Scanning $TOTAL files for anything like 'webhook'..."

echo "$ALL_FILES" | while read -r file; do
  SCANNED=$((SCANNED + 1))

  # Only scan text files
  if file "$file" | grep -qi 'text'; then
    # Get first match line number, if any
    MATCH_LINE=$(grep -inm1 "$PATTERN" "$file" 2>/dev/null | cut -d: -f1)
    if [ -n "$MATCH_LINE" ]; then
      echo "webhook found at $file on line $MATCH_LINE" >> "$MATCHES"
    fi
  fi

  # Timer + progress
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  MINS=$((ELAPSED / 60))
  SECS=$((ELAPSED % 60))
  PERCENT=$((SCANNED * 100 / TOTAL))

  printf "\rChecked: %d/%d files | %d%% | Elapsed: %02d:%02d" "$SCANNED" "$TOTAL" "$PERCENT" "$MINS" "$SECS"
done

# Output final results
echo "\n\n🎯 Webhook matches:\n"
if [ -s "$MATCHES" ]; then
  sort -u "$MATCHES"
else
  echo "No matches found."
fi

rm -f "$MATCHES"
