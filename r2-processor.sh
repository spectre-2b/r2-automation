#!/usr/bin/env bash
#
# r2-processor.sh - Secure automated file processing between Cloudflare R2 buckets
#
# Usage: ./r2-processor.sh [OPTIONS]
#   -c, --config FILE    Path to config file (default: ~/.config/r2-processor/config)
#   -d, --dry-run        Run without making changes
#   -v, --verbose        Enable verbose output
#   -h, --help           Show this help message
#
# Environment variables (or set in config file):
#   R2_REMOTE_NAME       rclone remote name (required)
#   R2_BUCKET_NAME       R2 bucket name (required)
#   R2_INCOMING_PREFIX   Incoming folder prefix (default: incoming/)
#   R2_OUTGOING_PREFIX   Outgoing folder prefix (default: outgoing/)
#   R2_PROCESSED_PREFIX  Processed folder prefix (default: processed/)
#   WORKSPACE_DIR        Local workspace directory (default: /tmp/r2-processor)
#   LOG_FILE             Log file path (default: /var/log/r2-processor.log)
#   LOCK_FILE            Lock file path (default: /tmp/r2-processor.lock)
#   MAX_FILE_SIZE_MB     Maximum file size in MB (default: 100)
#   ALLOWED_EXTENSIONS   Comma-separated allowed extensions (default: txt,csv,json,xml,pdf)
#

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# CONSTANTS & DEFAULTS
# =============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_PID=$$

# Default configuration values
DEFAULT_INCOMING_PREFIX="incoming/"
DEFAULT_OUTGOING_PREFIX="outgoing/"
DEFAULT_PROCESSED_PREFIX="processed/"
DEFAULT_WORKSPACE_DIR="/tmp/r2-processor"
DEFAULT_LOG_FILE="/var/log/r2-processor.log"
DEFAULT_LOCK_FILE="/tmp/r2-processor.lock"
DEFAULT_MAX_FILE_SIZE_MB=100
DEFAULT_ALLOWED_EXTENSIONS="txt,csv,json,xml,pdf"
DEFAULT_CONFIG_FILE="${HOME}/.config/r2-processor/config"

# Runtime flags
DRY_RUN=false
VERBOSE=false
CONFIG_FILE=""

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================

# Initialize logging - creates log file with secure permissions
init_logging() {
    local log_dir
    log_dir="$(dirname "${LOG_FILE}")"
    
    if [[ ! -d "${log_dir}" ]]; then
        mkdir -p "${log_dir}" 2>/dev/null || {
            # Fall back to temp directory if can't create log dir
            LOG_FILE="/tmp/r2-processor-${USER:-unknown}.log"
        }
    fi
    
    # Create log file with restrictive permissions (600)
    touch "${LOG_FILE}" 2>/dev/null || true
    chmod 600 "${LOG_FILE}" 2>/dev/null || true
}

# Log message to both stdout and log file
# Usage: log LEVEL MESSAGE
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local log_line="[${timestamp}] [${level}] [PID:${SCRIPT_PID}] ${message}"
    
    # Write to log file (if writable)
    echo "${log_line}" >> "${LOG_FILE}" 2>/dev/null || true
    
    # Write to stdout with color coding
    case "${level}" in
        ERROR)   echo -e "\033[31m${log_line}\033[0m" >&2 ;;
        WARN)    echo -e "\033[33m${log_line}\033[0m" >&2 ;;
        INFO)    echo "${log_line}" ;;
        DEBUG)   [[ "${VERBOSE}" == "true" ]] && echo -e "\033[36m${log_line}\033[0m" ;;
        *)       echo "${log_line}" ;;
    esac
}

log_info()  { log "INFO" "$@"; }
log_warn()  { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

# =============================================================================
# SECURITY FUNCTIONS
# =============================================================================

# Sanitize filename to prevent path traversal and command injection
# Returns sanitized filename via stdout
sanitize_filename() {
    local filename="$1"
    local sanitized
    
    # Remove path components (prevent path traversal)
    sanitized="$(basename "${filename}")"
    
    # Remove null bytes
    sanitized="${sanitized//$'\0'/}"
    
    # Remove leading dots (prevent hidden files)
    sanitized="${sanitized#.}"
    
    # Replace dangerous characters with underscores
    # Allow only alphanumeric, dots, hyphens, underscores
    sanitized="$(echo "${sanitized}" | sed 's/[^a-zA-Z0-9._-]/_/g')"
    
    # Prevent empty filename
    if [[ -z "${sanitized}" ]]; then
        sanitized="unnamed_file"
    fi
    
    # Truncate if too long (max 255 chars for most filesystems)
    if [[ ${#sanitized} -gt 255 ]]; then
        local ext="${sanitized##*.}"
        local name="${sanitized%.*}"
        local max_name_len=$((250 - ${#ext}))
        sanitized="${name:0:${max_name_len}}.${ext}"
    fi
    
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

# Validate file size
# Returns 0 if within limit, 1 if too large
validate_file_size() {
    local file_path="$1"
    local max_bytes=$((MAX_FILE_SIZE_MB * 1024 * 1024))
    local file_size
    
    if [[ -f "${file_path}" ]]; then
        file_size="$(stat -c%s "${file_path}" 2>/dev/null || stat -f%z "${file_path}" 2>/dev/null || echo 0)"
        if [[ ${file_size} -gt ${max_bytes} ]]; then
            log_warn "File exceeds size limit: ${file_path} (${file_size} bytes > ${max_bytes} bytes)"
            return 1
        fi
    fi
    return 0
}

# Create secure temporary directory
# Returns path via stdout
create_secure_temp_dir() {
    local prefix="${1:-r2proc}"
    local temp_dir
    
    # Create temp directory with restrictive permissions
    temp_dir="$(mktemp -d -t "${prefix}.XXXXXXXXXX")"
    chmod 700 "${temp_dir}"
    
    echo "${temp_dir}"
}

# =============================================================================
# LOCK FILE MANAGEMENT
# =============================================================================

# Acquire lock to prevent concurrent execution
acquire_lock() {
    local lock_dir
    lock_dir="$(dirname "${LOCK_FILE}")"
    
    # Ensure lock directory exists
    mkdir -p "${lock_dir}" 2>/dev/null || true
    
    # Try to acquire lock using atomic operation
    if ! (set -o noclobber; echo "${SCRIPT_PID}" > "${LOCK_FILE}") 2>/dev/null; then
        # Lock file exists - check if process is still running
        local existing_pid
        existing_pid="$(cat "${LOCK_FILE}" 2>/dev/null || echo "")"
        
        if [[ -n "${existing_pid}" ]] && kill -0 "${existing_pid}" 2>/dev/null; then
            log_error "Another instance is already running (PID: ${existing_pid})"
            return 1
        else
            log_warn "Stale lock file found, removing"
            rm -f "${LOCK_FILE}"
            echo "${SCRIPT_PID}" > "${LOCK_FILE}"
        fi
    fi
    
    log_debug "Lock acquired: ${LOCK_FILE}"
    return 0
}

# Release lock
release_lock() {
    if [[ -f "${LOCK_FILE}" ]]; then
        local lock_pid
        lock_pid="$(cat "${LOCK_FILE}" 2>/dev/null || echo "")"
        if [[ "${lock_pid}" == "${SCRIPT_PID}" ]]; then
            rm -f "${LOCK_FILE}"
            log_debug "Lock released: ${LOCK_FILE}"
        fi
    fi
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
        # shellcheck source=/dev/null
        if grep -qE '^[A-Z_]+=' "${config_file}" 2>/dev/null; then
            # Only source lines that look like variable assignments
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
    R2_OUTGOING_PREFIX="${R2_OUTGOING_PREFIX:-${DEFAULT_OUTGOING_PREFIX}}"
    R2_PROCESSED_PREFIX="${R2_PROCESSED_PREFIX:-${DEFAULT_PROCESSED_PREFIX}}"
    WORKSPACE_DIR="${WORKSPACE_DIR:-${DEFAULT_WORKSPACE_DIR}}"
    LOG_FILE="${LOG_FILE:-${DEFAULT_LOG_FILE}}"
    LOCK_FILE="${LOCK_FILE:-${DEFAULT_LOCK_FILE}}"
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
    
    # Ensure prefixes end with /
    [[ "${R2_INCOMING_PREFIX}" != */ ]] && R2_INCOMING_PREFIX="${R2_INCOMING_PREFIX}/"
    [[ "${R2_OUTGOING_PREFIX}" != */ ]] && R2_OUTGOING_PREFIX="${R2_OUTGOING_PREFIX}/"
    [[ "${R2_PROCESSED_PREFIX}" != */ ]] && R2_PROCESSED_PREFIX="${R2_PROCESSED_PREFIX}/"
    
    return 0
}

# =============================================================================
# RCLONE WRAPPER FUNCTIONS
# =============================================================================

# Build rclone remote path
build_remote_path() {
    local prefix="${1:-}"
    echo "${R2_REMOTE_NAME}:${R2_BUCKET_NAME}/${prefix}"
}

# List files in remote prefix
# Returns list of filenames (one per line)
list_remote_files() {
    local prefix="$1"
    local remote_path
    remote_path="$(build_remote_path "${prefix}")"
    
    log_debug "Listing files in: ${remote_path}"
    
    if ! rclone lsf "${remote_path}" --files-only 2>/dev/null; then
        log_error "Failed to list files in ${remote_path}"
        return 1
    fi
}

# Download file from remote
download_file() {
    local remote_file="$1"
    local local_dir="$2"
    local source_path
    local dest_path
    local sanitized_name
    
    # Sanitize the filename
    sanitized_name="$(sanitize_filename "${remote_file}")"
    
    source_path="$(build_remote_path "${R2_INCOMING_PREFIX}${remote_file}")"
    dest_path="${local_dir}/${sanitized_name}"
    
    log_info "Downloading: ${remote_file} -> ${dest_path}"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would download: ${source_path}"
        return 0
    fi
    
    if ! rclone copyto "${source_path}" "${dest_path}" --no-traverse 2>&1; then
        log_error "Failed to download: ${remote_file}"
        return 1
    fi
    
    # Validate downloaded file size
    if ! validate_file_size "${dest_path}"; then
        log_error "Downloaded file exceeds size limit, removing: ${dest_path}"
        rm -f "${dest_path}"
        return 1
    fi
    
    log_debug "Successfully downloaded: ${remote_file}"
    return 0
}

# Upload file to remote
upload_file() {
    local local_file="$1"
    local remote_prefix="$2"
    local filename
    local dest_path
    
    filename="$(basename "${local_file}")"
    dest_path="$(build_remote_path "${remote_prefix}${filename}")"
    
    log_info "Uploading: ${local_file} -> ${dest_path}"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would upload: ${local_file} to ${dest_path}"
        return 0
    fi
    
    if ! rclone copyto "${local_file}" "${dest_path}" --no-traverse 2>&1; then
        log_error "Failed to upload: ${local_file}"
        return 1
    fi
    
    log_debug "Successfully uploaded: ${filename}"
    return 0
}

# Move file within remote (incoming -> processed)
move_remote_file() {
    local filename="$1"
    local source_path
    local dest_path
    
    source_path="$(build_remote_path "${R2_INCOMING_PREFIX}${filename}")"
    dest_path="$(build_remote_path "${R2_PROCESSED_PREFIX}${filename}")"
    
    log_info "Moving remote: ${filename} -> ${R2_PROCESSED_PREFIX}"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would move: ${source_path} to ${dest_path}"
        return 0
    fi
    
    if ! rclone moveto "${source_path}" "${dest_path}" --no-traverse 2>&1; then
        log_error "Failed to move remote file: ${filename}"
        return 1
    fi
    
    log_debug "Successfully moved: ${filename}"
    return 0
}

# =============================================================================
# PROCESSING FUNCTIONS
# =============================================================================

# Process a single file (STUB - implement your logic here)
# This is a placeholder that should be replaced with actual processing logic
# Returns 0 on success, 1 on failure
# Outputs: processed file path (may be same as input or different)
process_file() {
    local input_file="$1"
    local output_dir="$2"
    local filename
    local output_file
    
    filename="$(basename "${input_file}")"
    output_file="${output_dir}/${filename}"
    
    log_info "Processing file: ${filename}"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would process: ${input_file}"
        echo "${input_file}"
        return 0
    fi
    
    # =========================================================================
    # PLACEHOLDER PROCESSING LOGIC
    # Replace this section with your actual processing code
    # =========================================================================
    
    # Example: Simply copy the file (replace with real processing)
    if ! cp "${input_file}" "${output_file}"; then
        log_error "Processing failed for: ${filename}"
        return 1
    fi
    
    # Example: Add a processing marker to text files
    if [[ "${filename}" =~ \.(txt|csv|json)$ ]]; then
        echo "" >> "${output_file}"
        echo "# Processed by ${SCRIPT_NAME} at $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "${output_file}"
    fi
    
    # =========================================================================
    # END PLACEHOLDER
    # =========================================================================
    
    log_debug "Processing complete: ${output_file}"
    echo "${output_file}"
    return 0
}

# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================

# Clean up temporary files and directories
cleanup() {
    local exit_code="${1:-0}"
    
    log_debug "Running cleanup..."
    
    # Release lock
    release_lock
    
    # Remove temporary directories (if they exist and are in /tmp)
    if [[ -n "${TEMP_DOWNLOAD_DIR:-}" ]] && [[ "${TEMP_DOWNLOAD_DIR}" == /tmp/* ]]; then
        log_debug "Removing temp download dir: ${TEMP_DOWNLOAD_DIR}"
        rm -rf "${TEMP_DOWNLOAD_DIR}" 2>/dev/null || true
    fi
    
    if [[ -n "${TEMP_OUTPUT_DIR:-}" ]] && [[ "${TEMP_OUTPUT_DIR}" == /tmp/* ]]; then
        log_debug "Removing temp output dir: ${TEMP_OUTPUT_DIR}"
        rm -rf "${TEMP_OUTPUT_DIR}" 2>/dev/null || true
    fi
    
    log_debug "Cleanup complete"
    exit "${exit_code}"
}

# Trap signals for cleanup
setup_signal_handlers() {
    trap 'cleanup 130' INT
    trap 'cleanup 143' TERM
    trap 'cleanup $?' EXIT
}

# =============================================================================
# MAIN PROCESSING LOOP
# =============================================================================

# Main processing function
process_incoming_files() {
    local files_processed=0
    local files_failed=0
    local files_skipped=0
    
    log_info "Starting file processing run"
    log_info "Remote: ${R2_REMOTE_NAME}:${R2_BUCKET_NAME}"
    log_info "Incoming prefix: ${R2_INCOMING_PREFIX}"
    log_info "Outgoing prefix: ${R2_OUTGOING_PREFIX}"
    log_info "Processed prefix: ${R2_PROCESSED_PREFIX}"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_warn "DRY-RUN MODE: No changes will be made"
    fi
    
    # Create secure temporary directories
    TEMP_DOWNLOAD_DIR="$(create_secure_temp_dir "r2-download")"
    TEMP_OUTPUT_DIR="$(create_secure_temp_dir "r2-output")"
    
    log_debug "Temp download dir: ${TEMP_DOWNLOAD_DIR}"
    log_debug "Temp output dir: ${TEMP_OUTPUT_DIR}"
    
    # List files in incoming folder
    local incoming_files
    incoming_files="$(list_remote_files "${R2_INCOMING_PREFIX}")" || {
        log_error "Failed to list incoming files"
        return 1
    }
    
    if [[ -z "${incoming_files}" ]]; then
        log_info "No files found in incoming folder"
        return 0
    fi
    
    # Process each file
    while IFS= read -r remote_file; do
        [[ -z "${remote_file}" ]] && continue
        
        log_info "----------------------------------------"
        log_info "Processing: ${remote_file}"
        
        # Validate file type
        if ! validate_file_type "${remote_file}"; then
            log_warn "Skipping file with disallowed extension: ${remote_file}"
            ((files_skipped++)) || true
            continue
        fi
        
        # Sanitize filename
        local safe_filename
        safe_filename="$(sanitize_filename "${remote_file}")"
        log_debug "Sanitized filename: ${safe_filename}"
        
        # Download file
        if ! download_file "${remote_file}" "${TEMP_DOWNLOAD_DIR}"; then
            log_error "Failed to download: ${remote_file}"
            ((files_failed++)) || true
            continue
        fi
        
        local local_file="${TEMP_DOWNLOAD_DIR}/${safe_filename}"
        
        # Skip if file doesn't exist (dry-run mode)
        if [[ "${DRY_RUN}" != "true" ]] && [[ ! -f "${local_file}" ]]; then
            log_error "Downloaded file not found: ${local_file}"
            ((files_failed++)) || true
            continue
        fi
        
        # Process file
        local processed_file
        processed_file="$(process_file "${local_file}" "${TEMP_OUTPUT_DIR}")" || {
            log_error "Failed to process: ${remote_file}"
            ((files_failed++)) || true
            continue
        }
        
        # Upload processed file to outgoing
        if [[ "${DRY_RUN}" != "true" ]] && [[ -f "${processed_file}" ]]; then
            if ! upload_file "${processed_file}" "${R2_OUTGOING_PREFIX}"; then
                log_error "Failed to upload processed file: ${processed_file}"
                ((files_failed++)) || true
                continue
            fi
        elif [[ "${DRY_RUN}" == "true" ]]; then
            upload_file "${local_file}" "${R2_OUTGOING_PREFIX}"
        fi
        
        # Move original to processed folder
        if ! move_remote_file "${remote_file}"; then
            log_error "Failed to move original file to processed: ${remote_file}"
            ((files_failed++)) || true
            continue
        fi
        
        # Clean up local files
        if [[ "${DRY_RUN}" != "true" ]]; then
            rm -f "${local_file}" "${processed_file}" 2>/dev/null || true
        fi
        
        ((files_processed++)) || true
        log_info "Successfully processed: ${remote_file}"
        
    done <<< "${incoming_files}"
    
    log_info "========================================"
    log_info "Processing run complete"
    log_info "  Processed: ${files_processed}"
    log_info "  Failed:    ${files_failed}"
    log_info "  Skipped:   ${files_skipped}"
    log_info "========================================"
    
    return 0
}

# =============================================================================
# HELP & USAGE
# =============================================================================

show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} - Secure R2 file processor

USAGE:
    ${SCRIPT_NAME} [OPTIONS]

OPTIONS:
    -c, --config FILE    Path to config file (default: ${DEFAULT_CONFIG_FILE})
    -d, --dry-run        Run without making changes
    -v, --verbose        Enable verbose/debug output
    -h, --help           Show this help message

ENVIRONMENT VARIABLES:
    R2_REMOTE_NAME       rclone remote name (required)
    R2_BUCKET_NAME       R2 bucket name (required)
    R2_INCOMING_PREFIX   Incoming folder prefix (default: ${DEFAULT_INCOMING_PREFIX})
    R2_OUTGOING_PREFIX   Outgoing folder prefix (default: ${DEFAULT_OUTGOING_PREFIX})
    R2_PROCESSED_PREFIX  Processed folder prefix (default: ${DEFAULT_PROCESSED_PREFIX})
    WORKSPACE_DIR        Local workspace directory (default: ${DEFAULT_WORKSPACE_DIR})
    LOG_FILE             Log file path (default: ${DEFAULT_LOG_FILE})
    LOCK_FILE            Lock file path (default: ${DEFAULT_LOCK_FILE})
    MAX_FILE_SIZE_MB     Maximum file size in MB (default: ${DEFAULT_MAX_FILE_SIZE_MB})
    ALLOWED_EXTENSIONS   Comma-separated allowed extensions (default: ${DEFAULT_ALLOWED_EXTENSIONS})

EXAMPLES:
    # Run with default config
    ${SCRIPT_NAME}

    # Run with custom config
    ${SCRIPT_NAME} -c /path/to/config

    # Dry run with verbose output
    ${SCRIPT_NAME} -d -v

    # Set required vars and run
    R2_REMOTE_NAME=myremote R2_BUCKET_NAME=mybucket ${SCRIPT_NAME}

CONFIG FILE FORMAT:
    R2_REMOTE_NAME=myremote
    R2_BUCKET_NAME=mybucket
    ALLOWED_EXTENSIONS=txt,csv,json,pdf

SECURITY NOTES:
    - Config file should have permissions 600 (owner read/write only)
    - Never commit credentials to version control
    - Use rclone's built-in config encryption for sensitive data

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
            -d|--dry-run)
                DRY_RUN=true
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
    
    # Test remote connectivity
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
    
    # Initialize logging
    init_logging
    
    # Setup signal handlers for cleanup
    setup_signal_handlers
    
    log_info "========================================"
    log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting"
    log_info "========================================"
    
    # Acquire lock
    if ! acquire_lock; then
        log_error "Failed to acquire lock, exiting"
        exit 1
    fi
    
    # Run preflight checks
    if ! preflight_checks; then
        log_error "Preflight checks failed, exiting"
        exit 1
    fi
    
    # Run main processing
    if ! process_incoming_files; then
        log_error "Processing failed"
        exit 1
    fi
    
    log_info "${SCRIPT_NAME} completed successfully"
    exit 0
}

# Run main function with all arguments
main "$@"
