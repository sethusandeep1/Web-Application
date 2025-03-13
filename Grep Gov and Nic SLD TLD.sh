#!/bin/bash

# URL of the gzipped index paths file
URL="https://data.commoncrawl.org/crawl-data/CC-MAIN-2024-22/cc-index.paths.gz"

# Output file names (adjusted for WSL path)
GZ_FILE="/mnt/c/Users/aryan/OneDrive/Documents/CCrawl/cc-index.paths.gz"
CSV_FILE="/mnt/c/Users/aryan/OneDrive/Documents/CCrawl/in_domains.csv"

# Temporary directory for downloaded files
TEMP_DIR="/mnt/c/Users/aryan/OneDrive/Documents/CCrawl/tmp"

# Download the gzipped file
echo "Downloading the gzipped file..."
wget -q -O "$GZ_FILE" "$URL"

# Check if the file was downloaded successfully
if [ ! -f "$GZ_FILE" ]; then
    echo "Download failed!"
    exit 1
fi

# Ensure the temporary directory exists
mkdir -p "$TEMP_DIR"

# Unzip the gzipped file and process each line to download the referenced index files
echo "Unzipping and processing the index paths file..."
gunzip -c "$GZ_FILE" | while IFS= read -r line; do
    INDEX_URL="https://data.commoncrawl.org/$line"
    echo "Downloading index file: $INDEX_URL"
    wget -nc -P "$TEMP_DIR" "$INDEX_URL"
done

# Wait for all downloads to complete
wait

# Extract .in domains from the downloaded index files and save to CSV
echo "Extracting .in domains from downloaded files..."
for INDEX_FILE in "$TEMP_DIR"/*.gz; do
    echo "Processing $INDEX_FILE"
    # Check if the file is a valid gzip file
    if file "$INDEX_FILE" | grep -q 'gzip compressed data'; then
        # Unzip and extract URLs using the Python script
        zcat "$INDEX_FILE" | python3 extract_urls.py >> "$CSV_FILE"
    else
        echo "Skipping invalid file: $INDEX_FILE"
    fi
done

# Check if the CSV file is created and contains data
echo "Checking CSV file..."
if [ -s "$CSV_FILE" ]; then
    echo "Extraction completed. Results saved in $CSV_FILE"
else
    echo "No .in domains found or CSV creation failed."
fi

# Clean up temporary directory
rm -rf "$TEMP_DIR"
