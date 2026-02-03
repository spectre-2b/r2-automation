#!/usr/bin/env bash
#
# r2-processor.sh - Read-only R2 bucket scanner and notification system
#
# This script ONLY lists files in the incoming/ folder and reports what's found.
# It does NOT download, process, move, or modify any files in the bucket.
#
# Usage: ./r2-processor.sh [OPTIONS]
#   -c, --config FILE    Path to config file (default: ~/.config/r2-processor/config)
#   -r, --report-only    Just list files without any processing (default behavior)
#   -v, --verbose        Enable verbose output
#   -j, --json           Output report in JSON format
#   -h, --help           Show this help message
#
# Environment variables (or set in config file):
#   R2_REMOTE_NAME       rclone remote name (required)
#   R2_BUCKET_NAME       R2 bucket name (required)
#   R2_INCOMING_PREFIX   Incoming folder prefix (default: incoming/)
#   MAX_FILE_SIZE_MB     Maximum file size in MB for validation (default: 100)
#   ALLOWED_EXTENSIONS   Comma-separated allowed extensions (default: txt,csv,json,xml,pdf)
#

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# CONSTANTS & DEFAULTS
# =============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_PID=$$

# Default configuration values
DEFAULT_INCOMING_PREFIX="incoming/"
DEFAULT_MAX_FILE_SIZE_MB=100
DEFAULT_ALLOWED_EXTENSIONS="txt,csv,json,xml,pdf,mp3,wav,md,png,jpg,jpeg,gif"
DEFAULT_CONFIG_FILE="${HOME}/.config/r2-processor/config"

# Runtime flags
VERBOSE=false
JSON_OUTPUT=false
REPORT_ONLY=true  # Always true - this is now a read-only scanner
CONFIG_FILE=""

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================

# Log message to stderr (keeps stdout clean for reports)
# Usage: log LEVEL MESSAGE
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local log_line="[${timestamp}] [${level}] ${message}"
    
    # Write to stderr with color coding
    case "${level}" in
        ERROR)   echo -e "\033[31m${log_line}\033[0m" >&2 ;;
        WARN)    echo -e "\033[33m${log_line}\033[0m" >&2 ;;
        INFO)    [[ "${VERBOSE}" == "true" ]] && echo "${log_line}" >&2 ;;
        DEBUG)   [[ "${VERBOSE}" == "true" ]] && echo -e "\033[36m${log_line}\033[0m" >&2 ;;
        *)       echo "${log_line}" >&2 ;;
    esac
}

log_info()  { log "INFO" "$@"; }
log_warn()  { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

# =============================================================================
# SECURITY FUNCTIONS (Read-only validation)
# =============================================================================

# Sanitize filename for display/validation only (no file operations)
# Returns sanitized filename via stdout
sanitize_filename() {
    local filename="$1"
    local sanitized
    
    # Remove path components (prevent path traversal in display)
    sanitized="$(basename "${filename}")"
    
    # Remove null bytes
    sanitized="${sanitized//$'\0'/}"
    
    echo "${sanitized}"
}

# Validate file extension against whitelist
# Returns 0 if valid, 1 if invalid
validate_file_type() {
    local filename="$1"
    local extension
    
    # Extract extension (lowercase)
    extension="${filename##*.}"
    extension="$(echo "${extension}" | tr '[:upper:]' '[:lower:]')"
    
    # Check against whitelist
    local IFS=','
    for allowed_ext in ${ALLOWED_EXTENSIONS}; do
        allowed_ext="$(echo "${allowed_ext}" | tr '[:upper:]' '[:lower:]' | xargs)"
        if [[ "${extension}" == "${allowed_ext}" ]]; then
            return 0
        fi
    done
    
    return 1
}

# Check if a file would pass size validation (based on remote size info)
# Returns 0 if within limit, 1 if too large
validate_remote_file_size() {
    local file_size="$1"
    local max_bytes=$((MAX_FILE_SIZE_MB * 1024 * 1024))
    
    if [[ ${file_size} -gt ${max_bytes} ]]; then
        return 1
    fi
    return 0
}

# =============================================================================
# CONFIGURATION
# =============================================================================

# Load configuration from file
load_config() {
    local config_file="$1"
    
    if [[ -f "${config_file}" ]]; then
        # Validate config file permissions (should not be world-readable)
        local perms
        perms="$(stat -c%a "${config_file}" 2>/dev/null || stat -f%Lp "${config_file}" 2>/dev/null || echo "644")"
        if [[ "${perms: -1}" != "0" ]] && [[ "${perms: -1}" != "4" ]]; then
            log_warn "Config file ${config_file} may be readable by others (permissions: ${perms})"
        fi
        
        # Source config file (only if it contains valid variable assignments)
        if grep -qE '^[A-Z_]+=' "${config_file}" 2>/dev/null; then
            while IFS='=' read -r key value; do
                # Skip comments and empty lines
                [[ "${key}" =~ ^[[:space:]]*# ]] && continue
                [[ -z "${key}" ]] && continue
                # Only allow uppercase variable names with underscores
                if [[ "${key}" =~ ^[A-Z_]+$ ]]; then
                    # Remove surrounding quotes from value
                    value="${value%\"}"
                    value="${value#\"}"
                    value="${value%\'}"
                    value="${value#\'}"
                    export "${key}=${value}"
                fi
            done < "${config_file}"
            log_debug "Loaded configuration from ${config_file}"
        fi
    fi
}

# Initialize configuration with defaults
init_config() {
    # Set defaults for unset variables
    R2_REMOTE_NAME="${R2_REMOTE_NAME:-}"
    R2_BUCKET_NAME="${R2_BUCKET_NAME:-}"
    R2_INCOMING_PREFIX="${R2_INCOMING_PREFIX:-${DEFAULT_INCOMING_PREFIX}}"
    MAX_FILE_SIZE_MB="${MAX_FILE_SIZE_MB:-${DEFAULT_MAX_FILE_SIZE_MB}}"
    ALLOWED_EXTENSIONS="${ALLOWED_EXTENSIONS:-${DEFAULT_ALLOWED_EXTENSIONS}}"
    
    # Validate required variables
    if [[ -z "${R2_REMOTE_NAME}" ]]; then
        log_error "R2_REMOTE_NAME is not set"
        return 1
    fi
    
    if [[ -z "${R2_BUCKET_NAME}" ]]; then
        log_error "R2_BUCKET_NAME is not set"
        return 1
    fi
    
    # Ensure prefix ends with /
    [[ "${R2_INCOMING_PREFIX}" != */ ]] && R2_INCOMING_PREFIX="${R2_INCOMING_PREFIX}/"
    
    return 0
}

# =============================================================================
# RCLONE WRAPPER FUNCTIONS (Read-only)
# =============================================================================

# Build rclone remote path
build_remote_path() {
    local prefix="${1:-}"
    echo "${R2_REMOTE_NAME}:${R2_BUCKET_NAME}/${prefix}"
}

# List files in remote prefix with details
# Returns: filename|size|modtime (one per line)
list_remote_files_detailed() {
    local prefix="$1"
    local remote_path
    remote_path="$(build_remote_path "${prefix}")"
    
    log_debug "Listing files in: ${remote_path}"
    
    # Use lsjson for detailed info, extract what we need
    if ! rclone lsjson "${remote_path}" --files-only 2>/dev/null; then
        log_error "Failed to list files in ${remote_path}"
        return 1
    fi
}

# Simple file list (names only)
list_remote_files_simple() {
    local prefix="$1"
    local remote_path
    remote_path="$(build_remote_path "${prefix}")"
    
    if ! rclone lsf "${remote_path}" --files-only 2>/dev/null; then
        log_error "Failed to list files in ${remote_path}"
        return 1
    fi
}

# =============================================================================
# REPORT GENERATION
# =============================================================================

# Generate a summary report of files found
generate_summary_report() {
    local files_json="$1"
    
    local total_files=0
    local valid_files=0
    local invalid_type_files=0
    local oversized_files=0
    local total_size=0
    local file_list=""
    local invalid_list=""
    local oversized_list=""
    
    # Parse JSON and validate each file
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        
        # Extract fields from JSON line (simple parsing)
        local name size
        name=$(echo "${line}" | grep -oP '"Name"\s*:\s*"\K[^"]+' || echo "")
        size=$(echo "${line}" | grep -oP '"Size"\s*:\s*\K[0-9]+' || echo "0")
        
        [[ -z "${name}" ]] && continue
        
        ((total_files++)) || true
        total_size=$((total_size + size))
        
        local sanitized_name
        sanitized_name="$(sanitize_filename "${name}")"
        
        # Check file type
        if ! validate_file_type "${sanitized_name}"; then
            ((invalid_type_files++)) || true
            invalid_list="${invalid_list}${sanitized_name}, "
            continue
        fi
        
        # Check file size
        if ! validate_remote_file_size "${size}"; then
            ((oversized_files++)) || true
            oversized_list="${oversized_list}${sanitized_name} ($(format_size ${size})), "
            continue
        fi
        
        ((valid_files++)) || true
        file_list="${file_list}${sanitized_name}, "
        
    done < <(echo "${files_json}" | grep -o '{[^}]*}')
    
    # Clean up trailing commas
    file_list="${file_list%, }"
    invalid_list="${invalid_list%, }"
    oversized_list="${oversized_list%, }"
    
    # Output report
    if [[ "${JSON_OUTPUT}" == "true" ]]; then
        output_json_report "${total_files}" "${valid_files}" "${invalid_type_files}" \
            "${oversized_files}" "${total_size}" "${file_list}" "${invalid_list}" "${oversized_list}"
    else
        output_text_report "${total_files}" "${valid_files}" "${invalid_type_files}" \
            "${oversized_files}" "${total_size}" "${file_list}" "${invalid_list}" "${oversized_list}"
    fi
}

# Format bytes to human readable
format_size() {
    local bytes="$1"
    if [[ ${bytes} -ge 1073741824 ]]; then
        echo "$(awk "BEGIN {printf \"%.2f\", ${bytes}/1073741824}")GB"
    elif [[ ${bytes} -ge 1048576 ]]; then
        echo "$(awk "BEGIN {printf \"%.2f\", ${bytes}/1048576}")MB"
    elif [[ ${bytes} -ge 1024 ]]; then
        echo "$(awk "BEGIN {printf \"%.2f\", ${bytes}/1024}")KB"
    else
        echo "${bytes}B"
    fi
}

# Output text report
output_text_report() {
    local total_files="$1"
    local valid_files="$2"
    local invalid_type_files="$3"
    local oversized_files="$4"
    local total_size="$5"
    local file_list="$6"
    local invalid_list="$7"
    local oversized_list="$8"
    
    echo "========================================"
    echo "R2 Incoming Folder Scan Report"
    echo "========================================"
    echo "Bucket: ${R2_REMOTE_NAME}:${R2_BUCKET_NAME}"
    echo "Folder: ${R2_INCOMING_PREFIX}"
    echo "Scan time: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "----------------------------------------"
    
    if [[ ${total_files} -eq 0 ]]; then
        echo "No files found in incoming folder."
    else
        echo "Found ${total_files} file(s) ($(format_size ${total_size}) total)"
        echo ""
        
        if [[ ${valid_files} -gt 0 ]]; then
            echo "✓ Valid files (${valid_files}): ${file_list}"
        fi
        
        if [[ ${invalid_type_files} -gt 0 ]]; then
            echo "⚠ Invalid type (${invalid_type_files}): ${invalid_list}"
        fi
        
        if [[ ${oversized_files} -gt 0 ]]; then
            echo "⚠ Oversized (${oversized_files}): ${oversized_list}"
        fi
    fi
    
    echo "========================================"
    echo "NOTE: This is a read-only scan. No files were modified."
    echo "========================================"
}

# Output JSON report
output_json_report() {
    local total_files="$1"
    local valid_files="$2"
    local invalid_type_files="$3"
    local oversized_files="$4"
    local total_size="$5"
    local file_list="$6"
    local invalid_list="$7"
    local oversized_list="$8"
    
    # Convert comma-separated lists to JSON arrays
    local valid_json="[]"
    local invalid_json="[]"
    local oversized_json="[]"
    
    if [[ -n "${file_list}" ]]; then
        valid_json="[$(echo "${file_list}" | sed 's/, /", "/g; s/^/"/; s/$/"/')]"
    fi
    if [[ -n "${invalid_list}" ]]; then
        invalid_json="[$(echo "${invalid_list}" | sed 's/, /", "/g; s/^/"/; s/$/"/')]"
    fi
    if [[ -n "${oversized_list}" ]]; then
        oversized_json="[$(echo "${oversized_list}" | sed 's/, /", "/g; s/^/"/; s/$/"/')]"
    fi
    
    cat << EOF
{
  "bucket": "${R2_REMOTE_NAME}:${R2_BUCKET_NAME}",
  "folder": "${R2_INCOMING_PREFIX}",
  "scan_time": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "summary": {
    "total_files": ${total_files},
    "valid_files": ${valid_files},
    "invalid_type": ${invalid_type_files},
    "oversized": ${oversized_files},
    "total_size_bytes": ${total_size},
    "total_size_human": "$(format_size ${total_size})"
  },
  "files": {
    "valid": ${valid_json},
    "invalid_type": ${invalid_json},
    "oversized": ${oversized_json}
  },
  "read_only": true
}
EOF
}

# Quick one-line summary output
output_quick_summary() {
    local files_json="$1"
    
    local count=0
    local names=""
    
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        local name
        name=$(echo "${line}" | grep -oP '"Name"\s*:\s*"\K[^"]+' || echo "")
        [[ -z "${name}" ]] && continue
        
        local sanitized
        sanitized="$(sanitize_filename "${name}")"
        
        ((count++)) || true
        names="${names}${sanitized}, "
    done < <(echo "${files_json}" | grep -o '{[^}]*}')
    
    names="${names%, }"
    
    if [[ ${count} -eq 0 ]]; then
        echo "No new files found in incoming/"
    else
        echo "Found ${count} new file(s): ${names}"
    fi
}

# =============================================================================
# MAIN SCAN FUNCTION
# =============================================================================

# Main scanning function (READ-ONLY)
scan_incoming_files() {
    log_info "Starting read-only scan"
    log_info "Remote: ${R2_REMOTE_NAME}:${R2_BUCKET_NAME}"
    log_info "Scanning: ${R2_INCOMING_PREFIX}"
    
    # Get file list with details
    local files_json
    files_json="$(list_remote_files_detailed "${R2_INCOMING_PREFIX}")" || {
        log_error "Failed to list incoming files"
        return 1
    }
    
    if [[ -z "${files_json}" ]] || [[ "${files_json}" == "[]" ]]; then
        if [[ "${JSON_OUTPUT}" == "true" ]]; then
            output_json_report 0 0 0 0 0 "" "" ""
        else
            echo "No files found in incoming/"
        fi
        return 0
    fi
    
    # Generate and output report
    generate_summary_report "${files_json}"
    
    return 0
}

# =============================================================================
# HELP & USAGE
# =============================================================================

show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} - Read-only R2 bucket scanner

This script scans the incoming/ folder in your R2 bucket and reports what
files are found. It is completely READ-ONLY and never modifies the bucket.

USAGE:
    ${SCRIPT_NAME} [OPTIONS]

OPTIONS:
    -c, --config FILE    Path to config file (default: ${DEFAULT_CONFIG_FILE})
    -r, --report-only    Just list files (this is always the default behavior)
    -j, --json           Output report in JSON format
    -v, --verbose        Enable verbose/debug output
    -h, --help           Show this help message

ENVIRONMENT VARIABLES:
    R2_REMOTE_NAME       rclone remote name (required)
    R2_BUCKET_NAME       R2 bucket name (required)
    R2_INCOMING_PREFIX   Incoming folder prefix (default: ${DEFAULT_INCOMING_PREFIX})
    MAX_FILE_SIZE_MB     Maximum file size for validation (default: ${DEFAULT_MAX_FILE_SIZE_MB})
    ALLOWED_EXTENSIONS   Comma-separated allowed extensions (default: ${DEFAULT_ALLOWED_EXTENSIONS})

EXAMPLES:
    # Basic scan
    ${SCRIPT_NAME}

    # Scan with custom config
    ${SCRIPT_NAME} -c /path/to/config

    # JSON output
    ${SCRIPT_NAME} --json

    # Verbose scan
    ${SCRIPT_NAME} -v

    # Set required vars and run
    R2_REMOTE_NAME=myremote R2_BUCKET_NAME=mybucket ${SCRIPT_NAME}

OUTPUT:
    Reports files found in incoming/ with validation status:
    - ✓ Valid files that pass all checks
    - ⚠ Invalid type (extension not in whitelist)
    - ⚠ Oversized (exceeds MAX_FILE_SIZE_MB)

SECURITY:
    This script is READ-ONLY safe:
    - Never downloads files
    - Never uploads files
    - Never moves or deletes files
    - Never modifies the bucket in any way
    - Only uses rclone list operations

EOF
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -r|--report-only)
                REPORT_ONLY=true  # Always true anyway
                shift
                ;;
            -j|--json)
                JSON_OUTPUT=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# =============================================================================
# PREFLIGHT CHECKS
# =============================================================================

preflight_checks() {
    # Check for rclone
    if ! command -v rclone &> /dev/null; then
        log_error "rclone is not installed or not in PATH"
        return 1
    fi
    
    # Check rclone version
    local rclone_version
    rclone_version="$(rclone version --check 2>&1 | head -1 || rclone version 2>&1 | head -1)"
    log_debug "rclone version: ${rclone_version}"
    
    # Verify remote exists
    if ! rclone listremotes 2>/dev/null | grep -q "^${R2_REMOTE_NAME}:$"; then
        log_error "Remote '${R2_REMOTE_NAME}' not found in rclone config"
        log_error "Available remotes:"
        rclone listremotes 2>/dev/null || true
        return 1
    fi
    
    # Test remote connectivity (read-only operation)
    log_debug "Testing remote connectivity..."
    if ! rclone lsd "${R2_REMOTE_NAME}:${R2_BUCKET_NAME}" --max-depth 1 &>/dev/null; then
        log_error "Cannot access bucket: ${R2_REMOTE_NAME}:${R2_BUCKET_NAME}"
        return 1
    fi
    
    log_debug "Preflight checks passed"
    return 0
}

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Load config file (if specified or default exists)
    if [[ -n "${CONFIG_FILE}" ]]; then
        if [[ ! -f "${CONFIG_FILE}" ]]; then
            echo "ERROR: Config file not found: ${CONFIG_FILE}" >&2
            exit 1
        fi
        load_config "${CONFIG_FILE}"
    elif [[ -f "${DEFAULT_CONFIG_FILE}" ]]; then
        load_config "${DEFAULT_CONFIG_FILE}"
    fi
    
    # Initialize configuration with defaults
    if ! init_config; then
        echo "ERROR: Configuration validation failed" >&2
        exit 1
    fi
    
    log_info "========================================"
    log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} (READ-ONLY SCANNER)"
    log_info "========================================"
    
    # Run preflight checks
    if ! preflight_checks; then
        log_error "Preflight checks failed, exiting"
        exit 1
    fi
    
    # Run scan (always read-only)
    if ! scan_incoming_files; then
        log_error "Scan failed"
        exit 1
    fi
    
    log_info "Scan completed successfully"
    exit 0
}

# Run main function with all arguments
main "$@"
