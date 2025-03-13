#!/bin/bash

input_file="/home/aryan/project/unique_urls.csv"
cms_urls_file="/home/aryan/project/cms_based_urls.csv"
cms_urls_with_type_file="/home/aryan/project/cms_based_urls_with_type.csv"
log_file="/home/aryan/project/filter_log.txt"
num_parallel_jobs=8  # Adjust based on your system's CPU cores

# Function to check if a URL is CMS-based using whatweb and return the CMS type
is_cms_based() {
    url=$1
    result=$(whatweb --aggression=3 "$url" 2>/dev/null)
    if echo "$result" | grep -iq "wordpress"; then
        echo "WP"
    elif echo "$result" | grep -iq "joomla"; then
        echo "Joomla"
    elif echo "$result" | grep -iq "drupal"; then
        echo "Drupal"
    elif echo "$result" | grep -Eiq "cms|concrete5|squarespace|typo3|magento|wix|bitrix|contao|dnn|e107|grav|umbraco|ze>        echo "Other CMS"
    else
        echo "No CMS detected"
    fi
}

export -f is_cms_based

# Ensure log file exists
touch "$log_file"

# Read processed URLs into an array
processed_urls=($(awk -F ": " '/URL: /{print $2}' "$log_file"))

# Function to check if URL has been processed
is_processed() {
    local url=$1
    for processed_url in "${processed_urls[@]}"; do
        if [[ "$processed_url" == "$url" ]]; then
            return 0
        fi
    done
    return 1
}

export -f is_processed

# Initialize counters
total_urls=0
cms_urls=0

# Function to log progress
log_progress() {
    total_urls_processed=$1
    if (( total_urls_processed % 10 == 0 )); then
        echo "Processed $total_urls_processed URLs so far..."
        echo "Processed $total_urls_processed URLs so far..." >> "$log_file"
    fi
}

# Process URLs in parallel and write to output files
tail -n +6634 "$input_file" | tr -d '\r' | parallel -j "$num_parallel_jobs" --bar '
    url={};
    is_processed() {
        local url=$1;
        for processed_url in "${processed_urls[@]}"; do
            if [[ "$processed_url" == "$url" ]]; then
                return 0;
            fi
        done;
        return 1;
    };
    if ! is_processed "$url"; then
        cms_type=$(is_cms_based "$url");
        echo "$url,$cms_type";
    fi
' | while IFS=, read -r url cms_type; do
   if [ -z "$url" ]; then
        continue
    fi
    if [ "$cms_type" != "No CMS detected" ]; then
        echo "$url" >> "$cms_urls_file"
        echo "$url,$cms_type" >> "$cms_urls_with_type_file"
        cms_urls=$((cms_urls + 1))
        echo "Detected CMS: $cms_type for URL: $url" >> "$log_file"
    else
        echo "No CMS detected for URL: $url" >> "$log_file"
    fi
    total_urls=$((total_urls + 1))
    log_progress "$total_urls"
done

# Count the number of processed URLs and CMS-based URLs
total_urls=$(wc -l < "$input_file")
cms_urls=$(wc -l < "$cms_urls_file")

# Log the summary
echo "Total URLs processed: $total_urls" >> "$log_file"
echo "Total CMS-based URLs found: $cms_urls" >> "$log_file"

# Display the summary
echo "Total URLs processed: $total_urls"
echo "Total CMS-based URLs found: $cms_urls"
echo "Processing complete. Check the log file for details: $log_file"
