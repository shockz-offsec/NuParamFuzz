#!/bin/bash

# -------------------------
# ANSI color codes
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
RESET='\033[0m'

# -------------------------
# ASCII art
echo -e "${RED}"
cat << "EOF"
        _   _       _____                          ______             
       | \ | |     |  __ \                        |  ____|            
       |  \| |_   _| |__) |_ _ _ __ __ _ _ __ ___ | |__ _   _ ________
       | . ` | | | |  ___/ _` | '__/ _` | '_ ` _ \|  __| | | |_  /_  /
       | |\  | |_| | |  | (_| | | | (_| | | | | | | |  | |_| |/ / / / 
       |_| \_|\__,_|_|   \__,_|_|  \__,_|_| |_| |_|_|   \__,_/___/___|
                                                               v1.0

                                     Made by Shockz-Offsec
                                            Inspired from NucleiFuzzer by Prakash (0xKayala)
EOF
echo -e "${RESET}"

# -------------------------
# Default settings
OUTPUT_FOLDER="./output"
HOME_DIR=$(eval echo ~"$USER")
EXCLUDED_EXTENSIONS="png,jpg,gif,jpeg,swf,woff,svg,pdf,json,css,js,webp,woff2,eot,ttf,otf,mp4,txt"
LOG_FILE="$OUTPUT_FOLDER/nuparamfuzz.log"
VERBOSE=false
KEEP_TEMP=false
RATE_LIMIT=50
RESULT_FILE=""
SHOW_ALL=false 

# -------------------------
# Help menu
display_help() {
    echo -e "NuParamFuzz: Advanced URL & Parameter Fuzzing Tool\n"
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help              Display this help menu"
    echo "  -d, --domain <domain>   Scan a single domain"
    echo "  -f, --file <filename>   Scan multiple domains/URLs from a file"
    echo "  -o, --output <folder>   Output folder (default: ./output)"
    echo "  -t, --templates <path>  Custom Nuclei templates directory"
    echo "  -v, --verbose           Enable verbose output (logs to terminal)"
    echo "  -k, --keep-temp         Keep temporary files after execution"
    echo "  -r, --rate <limit>      Set rate limit for Nuclei (default: 50)"
    exit 0
}

# -------------------------
# Log function
log() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    if [ "$VERBOSE" = true ] || [ "$level" = "ERROR" ]; then
        echo -e "${YELLOW}[$level]${RESET} $message"
    fi
}

# -------------------------
# Check prerequisites
check_prerequisite() {
    local tool="$1"
    local install_command="$2"
    if ! command -v "$tool" &> /dev/null; then
        log "INFO" "Installing $tool..."
        if ! eval "$install_command"; then
            log "ERROR" "Failed to install $tool. Exiting."
            exit 1
        fi
        if [ "$tool" = "uro" ] && [ -f "$HOME/.local/bin/uro" ]; then
            export PATH="$HOME/.local/bin:$PATH"
            log "INFO" "Added $HOME/.local/bin to PATH."
        fi
    fi
}

# -------------------------
# Check Python module
check_python_module() {
    local module="$1"
    if ! python3 -c "import $module" &>/dev/null; then
        log "INFO" "Installing Python module: $module"
        pip3 install --break-system-packages "$module" || log "ERROR" "Failed to install $module"
    fi
}

# -------------------------
# Clone repositories
clone_repo() {
    local repo_url="$1"
    local target_dir="$2"
    if [ ! -d "$target_dir" ]; then
        log "INFO" "Cloning $repo_url to $target_dir..."
        if ! git clone "$repo_url" "$target_dir"; then
            log "ERROR" "Failed to clone $repo_url. Exiting."
            exit 1
        fi
    fi
}

# -------------------------
# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) display_help ;;
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -f|--file) FILENAME="$2"; shift 2 ;;
        -o|--output) OUTPUT_FOLDER="$2"; shift 2 ;;
        -t|--templates) TEMPLATE_DIR="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -k|--keep-temp) KEEP_TEMP=true; shift ;;
        -r|--rate) RATE_LIMIT="$2"; shift 2 ;;
        -all) SHOW_ALL=true; shift ;;  # New flag
        *) log "ERROR" "Unknown option: $1"; display_help ;;
    esac
done

# -------------------------
# Validate input presence
if [ -z "$DOMAIN" ] && [ -z "$FILENAME" ]; then
    log "ERROR" "Please provide a domain (-d) or file (-f)."
    display_help
fi

# -------------------------
# Setup
mkdir -p "$OUTPUT_FOLDER"
echo "" > "$LOG_FILE"
TEMPLATE_DIR=${TEMPLATE_DIR:-"$HOME_DIR/nuclei-templates"}

# -------------------------
# Warn if not using virtualenv
if [[ "$VIRTUAL_ENV" == "" ]]; then
    log "WARNING" "You are not using a Python virtual environment. It is recommended."
fi

# -------------------------
# Ensure Go bin path is in PATH
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    export PATH="$HOME/go/bin:$PATH"
    log "INFO" "Added $HOME/go/bin to PATH."
fi

# -------------------------
# Dependency installation
check_prerequisite "python3" "sudo apt install -y python3"
check_prerequisite "go" "sudo apt install -y golang"
check_prerequisite "pip3" "sudo apt install -y python3-pip"
check_python_module "requests"
check_python_module "urllib3"
check_prerequisite "nuclei" "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
check_prerequisite "httpx" "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_prerequisite "uro" "pip3 install --break-system-packages uro"
check_prerequisite "katana" "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
check_prerequisite "waybackurls" "go install github.com/tomnomnom/waybackurls@latest"
check_prerequisite "gauplus" "go install github.com/bp0lr/gauplus@latest"
check_prerequisite "hakrawler" "go install github.com/hakluke/hakrawler@latest"
check_prerequisite "paramx" "go install github.com/cyinnove/paramx/cmd/paramx@latest"
check_prerequisite "gospider" "go install github.com/jaeles-project/gospider@latest"
check_prerequisite "cariddi" "go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest"
clone_repo "https://github.com/0xKayala/ParamSpider" "$HOME_DIR/ParamSpider"
clone_repo "https://github.com/projectdiscovery/nuclei-templates.git" "$HOME_DIR/nuclei-templates"

# -------------------------
# Validate input URLs and check ports
validate_input() {
    local input="$1"
    local subdomain_urls

    # Get live URLs (http + https)
    subdomain_urls=$(echo "$input" | httpx -silent -ports 80,443,8080,8443,8000,8008 2>/dev/null)

    if [ -z "$subdomain_urls" ]; then
        log "ERROR" "No live URLs found for $input"
        return 1
    fi

    # Keep only https URLs if both http and https exist
    # First, get unique hosts
    declare -A hosts_map
    local filtered_urls=""
    while IFS= read -r url; do
        # Extract host without protocol
        host="${url#*://}"
        host="${host%%/*}"

        if [[ "$url" == https://* ]]; then
            hosts_map["$host"]="$url"
        elif [[ -z "${hosts_map[$host]}" ]]; then
            hosts_map["$host"]="$url"
        fi
    done <<< "$subdomain_urls"

    # Reconstruct filtered URLs
    for u in "${hosts_map[@]}"; do
        filtered_urls+="$u"$'\n'
    done

    echo -e "${GREEN}Detected live URLs for $input:${RESET}" >&2
    while IFS= read -r url; do
        echo -e "${YELLOW}$url${RESET}" >&2
    done <<< "$filtered_urls"

    echo "$filtered_urls"
}

# -------------------------
# URL collection
collect_urls() {
    local target="$1"
    local output_file="$2"
    local TIMEOUT_DURATION=10s  # General timeout for each tool

    log "INFO" "Starting URL collection for $target..."

    #-------------------------
    #ParamSpider
    echo -e "${GREEN}Collecting URLs for $target...${RESET} using ParamSpider"
    timeout "$TIMEOUT_DURATION" python3 "$HOME_DIR/ParamSpider/paramspider.py" -d "$target" \
        --exclude "$EXCLUDED_EXTENSIONS" --level high --quiet -o "$output_file.tmp" >/dev/null 2>&1
    if [ -f "$output_file.tmp" ]; then
        cat "$output_file.tmp" >> "$output_file"
        rm -f "$output_file.tmp"
    else
        log "INFO" "ParamSpider returned no results for $target or timed out."
    fi

    # -------------------------
    # Waybackurls
    echo -e "${GREEN}Collecting URLs for $target...${RESET} using Waybackurls"
    urls=$(timeout "$TIMEOUT_DURATION" waybackurls <<< "$target")
    if [ -n "$urls" ]; then
        echo "$urls" >> "$output_file"
    else
        log "INFO" "Waybackurls returned no URLs for $target or timed out."
    fi

    # -------------------------
    # Gauplus
    echo -e "${GREEN}Collecting URLs for $target...${RESET} using Gauplus"
    urls=$(timeout "$TIMEOUT_DURATION" gauplus -subs -b "$EXCLUDED_EXTENSIONS" <<< "$target")
    if [ -n "$urls" ]; then
        echo "$urls" >> "$output_file"
    else
        log "INFO" "Gauplus returned no URLs for $target or timed out."
    fi

    # -------------------------
    # Hakrawler
    echo -e "${GREEN}Collecting URLs for $target...${RESET} using Hakrawler"
    urls=$(timeout "$TIMEOUT_DURATION" hakrawler -d 3 -subs -insecure -u <<< "$target")
    if [ -n "$urls" ]; then
        echo "$urls" >> "$output_file"
    else
        log "INFO" "Hakrawler returned no URLs for $target or timed out."
    fi

    # -------------------------
    # Katana
    echo -e "${GREEN}Collecting URLs for $target...${RESET} using Katana"
    urls=$(timeout "$TIMEOUT_DURATION" katana -d 3 -silent -rl 10 <<< "$target")
    if [ -n "$urls" ]; then
        echo "$urls" >> "$output_file"
    else
        log "INFO" "Katana returned no URLs for $target or timed out."
    fi
    
    # -------------------------
    # GoSpider
    echo -e "${GREEN}Collecting URLs for $target...${RESET} using Gospider"
    if ! timeout "$TIMEOUT_DURATION" gospider -s "$target" --js -t 10 -d 3 --sitemap --robots -w -q -r | grep -Eo 'https?://[^[:space:]]+' >> "$output_file" 2>/dev/null; then
        log "INFO" "Gospider returned no results for $target or timed out."
    fi

    # -------------------------
    # Cariddi
    echo -e "${GREEN}Collecting URLs for $target...${RESET} using Cariddi"
    if ! timeout "$TIMEOUT_DURATION" bash -c "echo \"$target\" | cariddi -c 20 -t 5 -rua -s" >> "$output_file" 2>/dev/null; then
        log "INFO" "Cariddi returned no results for $target or timed out."
    fi

}



# -------------------------
# Filter URLs by target host and subdomains
filter_by_target() {
    local input_file="$1"
    local output_file="$2"
    local target="$3"

    if [ ! -f "$input_file" ]; then
        log "WARNING" "$input_file not found. Skipping filter."
        return 0
    fi

    # remove leading "*." only if present
    local clean_target="$target"
    if [[ "$clean_target" == \*.* ]]; then
        clean_target="${clean_target#*.}"
    fi

    awk -v th="$clean_target" '
    /^https?:\/\// {
        url=$0
        sub(/^https?:\/\//, "", url)
        slash=index(url, "/")
        host = (slash ? substr(url,1,slash-1) : url)

        if (host == th) { print; next }
        if (host ~ ("\\." th "$")) { print }
    }' "$input_file" > "$output_file.tmp" && mv "$output_file.tmp" "$output_file"

    log "INFO" "Filtering done for $target (effective: $clean_target), results in $output_file."
}



# -------------------------
# Validate & deduplicate URLs
validate_urls() {
    local input_file="$1"
    local validated_file="$2"
    local filtered_file="$3"

    if [ ! -s "$input_file" ]; then
        log "FAILED" "No URLs found in $input_file."
        return 1
    fi

    echo -e "${GREEN}Deduplicating URLs from $input_file...${RESET}"

    # Deduplicate with uro
    if ! sort -u "$input_file" | uro > "$validated_file"; then
        log "ERROR" "Failed to deduplicate URLs with uro."
        return 1
    fi

    if [ ! -s "$validated_file" ]; then
        log "FAILED" "No URLs left after deduplication. Exiting."
        return 1
    fi

    # Apply paramx according to -all flag
    if [ "$SHOW_ALL" = true ]; then
        paramx -ap -o "$filtered_file" < "$validated_file" >/dev/null 2>&1 || { log "ERROR" "paramx -ap failed."; return 1; }
    else
        paramx -at -o "$filtered_file" < "$validated_file" >/dev/null 2>&1 || { log "ERROR" "paramx -at failed."; return 1; }
    fi

    log "INFO" "Validated URLs saved to $validated_file and filtered URLs to $filtered_file for Nuclei."
}


# -------------------------
# Run nuclei scan
run_nuclei() {
    local url_file="$1"
    echo -e "${GREEN}Running Nuclei on URLs from $url_file...${RESET}"
    httpx -silent -mc 200,204,301,302,401,403,405,500,502,503,504 -l "$url_file" |
        nuclei -t "$TEMPLATE_DIR" -dast -rl "$RATE_LIMIT" -o "$RESULT_FILE"
}


# Unified processing function for DOMAIN or FILE
process_targets() {
    local targets=("$@")   # Array of domains or URLs

    for target in "${targets[@]}"; do
        log "INFO" "Processing target: $target"

        # Create a sanitized folder for this target inside OUTPUT_FOLDER
        local safe_target="${target//[^a-zA-Z0-9.-]/_}"
        local target_folder="$OUTPUT_FOLDER/$safe_target"
        mkdir -p "$target_folder"

        # Define working files inside the target's folder
        local raw_file="$target_folder/all_raw.txt"
        local validated_file="$target_folder/all_validated.txt"
        local filtered_file="$target_folder/all_filtered.txt"

        # Initialize raw file
        echo "" > "$raw_file"

        # Get live URLs for the target
        local urls
        urls=$(validate_input "$target")
        if [ $? -ne 0 ] || [ -z "$urls" ]; then
            log "WARNING" "No live URLs found for $target. Saving to subdomains_without_urls.txt"
            echo "$target" >> "$target_folder/subdomains_without_urls.txt"
            continue
        fi 

        # Collect URLs from various tools for each live URL
        while IFS= read -r url; do
            collect_urls "$url" "$raw_file"
        done <<< "$urls"

        # Filter URLs by host and subdomains
        local tmp_file="$target_folder/tmp_filtered.txt"
        filter_by_target "$raw_file" "$tmp_file" "$target"
        mv "$tmp_file" "$raw_file"

        # Validate and deduplicate URLs using uro and paramx
        validate_urls "$raw_file" "$validated_file" "$filtered_file" || {
            log "FAILED" "No validated URLs to scan for $target. Skipping."
            continue
        }

        # Set result file path inside target folder
        RESULT_FILE="$target_folder/${safe_target}_nuclei_results.txt"

        # Run Nuclei scan on filtered URLs
        run_nuclei "$filtered_file"
    done
}


# -------------------------
# Main logic
if [ -n "$DOMAIN" ]; then
    process_targets "$DOMAIN"
elif [ -n "$FILENAME" ]; then
    if [ ! -f "$FILENAME" ]; then
        log "ERROR" "File $FILENAME not found."
        exit 1
    fi
    mapfile -t TARGETS < "$FILENAME"
    process_targets "${TARGETS[@]}"
fi

# -------------------------
# Cleanup
if [ "$KEEP_TEMP" = false ]; then
    log "INFO" "Cleaning up temporary files..."
    rm -f "$OUTPUT_FOLDER"/*_raw.txt "$OUTPUT_FOLDER"/*_validated.txt 2>/dev/null
fi

log "INFO" "Scanning completed. Results saved in $RESULT_FILE."
echo -e "${RED}The process is completed! Check $RESULT_FILE for results.${RESET}"