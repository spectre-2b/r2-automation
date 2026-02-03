# R2 Automation Processor

Secure file processing pipeline for Cloudflare R2 buckets. This script automates downloading files from an R2 bucket, processing them locally, and uploading results back.

## Features

- **Secure by design**: No hardcoded credentials, input validation, sanitized filenames
- **Atomic operations**: Files are moved to "processing" folder before download
- **Lock file mechanism**: Prevents concurrent runs
- **File validation**: Whitelist extensions, size limits, path traversal protection
- **Comprehensive logging**: Both stdout and file logging
- **Dry-run mode**: Test configuration without executing
- **Error handling**: Proper cleanup on exit, graceful error recovery

## Installation

1. Clone this repository:
```bash
git clone https://github.com/YOUR_USERNAME/r2-automation.git
cd r2-automation
```

2. Install rclone if not already installed:
```bash
# macOS
brew install rclone

# Linux
curl https://rclone.org/install.sh | sudo bash
```

3. Configure rclone with your R2 credentials:
```bash
rclone config
# Create a new remote named "r2" (or your preferred name)
# Select "S3" storage
# Select "Cloudflare" provider
# Enter your Account ID, Access Key, Secret Key
```

## Usage

### Basic Usage

```bash
export R2_BUCKET="my-bucket"
./r2-processor.sh
```

### With Options

```bash
# Dry run (test without executing)
./r2-processor.sh --dry-run

# Debug mode (verbose logging)
./r2-processor.sh --debug

# Combined
DEBUG=true ./r2-processor.sh --dry-run
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `R2_REMOTE` | `r2` | rclone remote name |
| `R2_BUCKET` | (required) | R2 bucket name |
| `WORKSPACE_DIR` | `~/r2-workspace` | Local working directory |
| `MAX_FILE_SIZE` | `500M` | Maximum file size limit |
| `DEBUG` | `false` | Enable debug logging |
| `DRY_RUN` | `false` | Dry run mode |

## Bucket Structure

The script expects this folder structure in your R2 bucket:

```
bucket/
├── incoming/       # Drop files here to process
├── processing/     # Files moved here during processing
├── processed/      # Completed files archived here
└── outgoing/       # Results uploaded here
```

## Customizing Processing Logic

Edit the `process_file()` function in `r2-processor.sh`:

```bash
process_file() {
    local input_file="$1"
    local output_dir="$2"
    local basename=$(basename "${input_file}")
    
    # Add your custom processing here
    # Example: transcribe audio, convert video, etc.
    
    local result_file="${output_dir}/${basename}.result"
    
    # Your processing logic...
    whisper "${input_file}" --output_format txt --output_dir "${output_dir}"
    
    echo "${result_file}"
}
```

## Automation

### Cron (Linux/macOS)

Run every 30 minutes:

```bash
# Edit crontab
crontab -e

# Add line:
*/30 * * * * R2_BUCKET=my-bucket /path/to/r2-processor.sh >> /var/log/r2-cron.log 2>&1
```

### Systemd Timer (Linux)

Create `/etc/systemd/system/r2-processor.service`:

```ini
[Unit]
Description=R2 Automation Processor
After=network.target

[Service]
Type=oneshot
User=ubuntu
Environment=R2_BUCKET=my-bucket
Environment=R2_REMOTE=r2
ExecStart=/path/to/r2-processor.sh
```

Create `/etc/systemd/system/r2-processor.timer`:

```ini
[Unit]
Description=Run R2 processor every 30 minutes

[Timer]
OnCalendar=*:0/30
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable r2-processor.timer
sudo systemctl start r2-processor.timer
```

## Security Considerations

- Never commit credentials to the repository
- Use environment variables or secure secret management
- The script validates file extensions and sanitizes filenames
- File size limits prevent resource exhaustion
- Lock file prevents race conditions

## License

MIT
