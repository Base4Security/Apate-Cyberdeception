#!/bin/bash
set -e

# Configuration
KIBANA_HOST="http://kibana:5601"
MAX_RETRIES=30
RETRY_INTERVAL=10

echo "=========================================="
echo "Kibana Data View Setup"
echo "=========================================="

# Wait for Kibana to be ready with better error handling
echo "Waiting for Kibana to be ready..."
for i in $(seq 1 $MAX_RETRIES); do
  if curl -s -f "$KIBANA_HOST/api/status" > /dev/null 2>&1; then
    echo "Kibana is ready!"
    break
  fi
  
  if [ $i -eq $MAX_RETRIES ]; then
    echo "ERROR: Kibana failed to start after $((MAX_RETRIES * RETRY_INTERVAL)) seconds"
    exit 1
  fi
  
  echo "Attempt $i/$MAX_RETRIES: Kibana not ready yet, waiting ${RETRY_INTERVAL}s..."
  sleep $RETRY_INTERVAL
done

# Additional wait for Kibana to be fully operational
echo "Waiting for Kibana to be fully operational..."
sleep 10

# Define the data view configuration
DATAVIEW_TITLE="playground-logs-*"
DATAVIEW_ID="playground-logs-star"
DATAVIEW_PATTERN="playground-logs-*"

echo "Setting up data view: $DATAVIEW_TITLE"

# Check if the data view already exists
echo "Checking if data view already exists..."
STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "$KIBANA_HOST/api/data_views/id/${DATAVIEW_ID}" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' 2>/dev/null || echo "000")

if [ "$STATUS_CODE" -eq 200 ]; then
  echo "Data view '${DATAVIEW_TITLE}' already exists. Skipping creation."
else
  echo "Data view '${DATAVIEW_TITLE}' not found. Creating..."
  
  # Create the data view
  RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST "$KIBANA_HOST/api/data_views/data_view" \
    -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    -d '{
      "data_view": {
        "title": "'"${DATAVIEW_TITLE}"'",
        "name": "'"${DATAVIEW_TITLE}"'",
        "id": "'"${DATAVIEW_ID}"'",
        "timeFieldName": "@timestamp"
      }
    }' 2>/dev/null)
  
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  RESPONSE_BODY=$(echo "$RESPONSE" | head -n -1)
  
  if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 201 ]; then
    echo "Successfully created data view '${DATAVIEW_TITLE}'."
  else
    echo "WARNING: Failed to create data view. HTTP Code: $HTTP_CODE"
    echo "Response: $RESPONSE_BODY"
  fi
fi

# Set as default data view
echo "Setting '${DATAVIEW_TITLE}' as the default data view..."
RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST "$KIBANA_HOST/api/kibana/settings" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d '{
    "changes": {
      "defaultIndex": "'"${DATAVIEW_ID}"'"
    }
  }' 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
if [ "$HTTP_CODE" -eq 200 ]; then
  echo "Successfully set '${DATAVIEW_TITLE}' as default data view."
else
  echo "WARNING: Failed to set default data view. HTTP Code: $HTTP_CODE"
fi

# Import saved objects (dashboards, visualizations) from ndjson files
NDJSON_DIR="$(dirname "$0")/ndjson"
if [ -d "$NDJSON_DIR" ]; then
  for ndjson_file in "$NDJSON_DIR"/*.ndjson; do
    [ -f "$ndjson_file" ] || continue
    filename=$(basename "$ndjson_file")
    echo "Importing saved objects from $filename..."
    RESPONSE=$(curl -s -w "\n%{http_code}" \
      -X POST "$KIBANA_HOST/api/saved_objects/_import?overwrite=true" \
      -H 'kbn-xsrf: true' \
      --form file=@"$ndjson_file" 2>/dev/null)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    if [ "$HTTP_CODE" -eq 200 ]; then
      echo "Successfully imported $filename."
    else
      echo "WARNING: Failed to import $filename. HTTP Code: $HTTP_CODE"
    fi
  done
else
  echo "No ndjson/ directory found — skipping dashboard import."
fi

echo "=========================================="
echo "Kibana setup complete!"
echo "=========================================="
echo "Data view: $DATAVIEW_TITLE"
echo "To add dashboards: place .ndjson exports in dashboards/ndjson/"
echo "=========================================="