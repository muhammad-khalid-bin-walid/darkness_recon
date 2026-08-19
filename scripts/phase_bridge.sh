#!/bin/bash
# Enhanced Phase Bridge Wrapper Script
# This script wraps existing shell phases with Python lib layer integration

# Set up error handling and logging
error_exit() {
    echo "ERROR: $1" >&2
    exit 1
}

# Source the Python bridge module
source_python_bridge() {
    local python_script="$(dirname "${BASH_SOURCE[0]}")/lib/phase_bridge.py"
    
    if [ ! -f "$python_script" ]; then
        error_exit "Python bridge script not found: $python_script"
    fi
    
    echo "Sourcing Python bridge from: $python_script"
}

# Initialize logging for shell phase integration
init_shell_logging() {
    local phase_name="$1"
    local log_dir="logs/phases"
    
    mkdir -p "$log_dir"
    touch "$log_dir/${phase_name}_bridge.log"
    touch "$log_dir/phase_bridge.log"
}

# Smart logging that converts to Python structured logs
smart_log() {
    local level="$1"
    local message="$2"
    local phase="$3"
    local target="$4"
    local event="${5:-INFO}"
    local metadata="${6:-}"
    
    # Validate inputs
    if [ -z "$phase" ] || [ -z "$target" ]; then
        echo "ERROR: phase and target are required" >&2
        return 1
    fi
    
    # Create Python command for structured logging
    python3 -c "
import json
import sys
from datetime import datetime

level='$level'
message='$message'
phase='$phase'
target='$target'
event='$event'
metadata='$metadata'

# Parse shell message
if 'Found subdomain:' in message:
    clean_msg = message.split('Found subdomain: ')[1].strip()
    finding_type = 'DISCOVERY'
    priority = 'high'
elif 'Starting phase:' in message:
    clean_msg = message
    finding_type = 'PHASE_START'
    priority = 'medium'
elif 'completed successfully' in message:
    clean_msg = 'Phase completed successfully'
    finding_type = 'PHASE_COMPLETE'
    priority = 'low'
elif 'ERROR:' in message or 'ERROR ' in message:
    clean_msg = message
    finding_type = 'ERROR'
    priority = 'critical'
else:
    clean_msg = message
    finding_type = 'INFO'
    priority = 'normal'

# Create structured log entry
log_entry = {
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'level': level,
    'phase': phase,
    'target': target,
    'message': clean_msg,
    'event': event,
    'metadata': {
        'shell_original': message,
        'finding_type': finding_type,
        'priority': priority,
        'integration': True,
        'source': 'shell_bridge'
    }
}

# Write to integration log
with open('logs/integration.log', 'a') as f:
    json.dump(log_entry, f)
    f.write('\n')

# Write to phase-specific log
with open(f'logs/phases/${phase}_bridge.log', 'a') as f:
    json.dump(log_entry, f)
    f.write('\n')

print(json.dumps(log_entry))
" 2>/dev/null || {
        echo "WARNING: Python logging failed, using shell fallback" >&2
        echo "[$level] [$phase] [$target] $message" >> "logs/phases/${phase}_bridge.log"
    }
}

# Smart finding writer with Python validation
smart_write_finding() {
    local finding_json="$1"
    local phase="$2"
    local target="$3"
    local output_dir="$4"
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Use Python to validate and write finding
    python3 -c "
import json
import sys
from datetime import datetime
import os

finding_json='$finding_json'
phase='$phase'
target='$target'
output_dir='$output_dir'

# Parse finding
try:
    finding = json.loads(finding_json)
except json.JSONDecodeError as e:
    print(f'ERROR: Invalid JSON in finding: {e}')
    sys.exit(1)

# Validate finding schema
required_fields = ['type', 'value', 'target']
for field in required_fields:
    if field not in finding:
        print(f'ERROR: Missing required field: {field}')
        sys.exit(1)

# Add metadata
finding.update({
    'phase': phase,
    'target': target,
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'integration_source': 'shell_bridge',
    'python_validated': True
})

# Write to finding file
os.makedirs(output_dir, exist_ok=True)
finding_file = os.path.join(output_dir, f'{phase}_findings.jsonl')

with open(finding_file, 'a') as f:
    json.dump(finding, f)
    f.write('\n')

print(f'SUCCESS: Finding written to {finding_file}')
" 2>&1 | {
        if [[ $? -eq 0 ]]; then
            echo "SUCCESS: Finding written successfully"
        else
            echo "ERROR: Failed to write finding"
            return 1
        fi
    }
}

# Smart validation and write with Python integration
smart_validate_and_write() {
    local phase_name="$1"
    local target="$2"
    local data="$3"
    local output_file="$4"
    
    # Use Python to validate and write
    python3 -c "
import json
import sys
from datetime import datetime
import os

phase_name='$phase_name'
target='$target'
data=json.loads('$data')
output_file='$output_file'

# Validate data
if not isinstance(data, dict):
    print('ERROR: Invalid data format')
    sys.exit(1)

# Add metadata
data.update({
    'phase': phase_name,
    'target': target,
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'integration_source': 'shell_bridge',
    'python_validated': True
})

# Write to file
os.makedirs(os.path.dirname(output_file), exist_ok=True)

with open(output_file, 'w') as f:
    json.dump(data, f, indent=2)

print(f'SUCCESS: Data written to {output_file}')
" 2>&1 | {
        if [[ $? -eq 0 ]]; then
            echo "SUCCESS: Data validated and written successfully"
        else
            echo "ERROR: Failed to validate and write data"
            return 1
        fi
    }
}

# Phase bridge execution wrapper
phase_bridge() {
    "Usage: phase_bridge <phase_name> <target> [<args>]"
    "Bridge shell phases to Python lib layer"
    
    local phase_name="$1"
    local target="$2"
    shift 2
    
    # Source Python bridge
    source_python_bridge
    
    # Initialize logging
    init_shell_logging "$phase_name"
    
    # Validate phase name
    if [ -z "$phase_name" ] || [ -z "$target" ]; then
        echo "ERROR: phase_name and target are required" >&2
        exit 1
    fi
    
    # Log phase start
    smart_log "INFO" "Starting phase: $phase_name for target: $target" "$phase_name" "$target" "PHASE_START"
    
    # Execute phase with Python integration
    echo "Executing phase: $phase_name for target: $target"
    
    # Call the original phase but with Python integration
    # Note: This is a conceptual wrapper - actual implementation would need
    # to replace the phase's internal calls with smart_log, smart_write_finding, etc.
    
    echo "Phase bridge executed (conceptual)"
}

# Main execution logic
if [[ "$1" == "bridge" ]]; then
    phase_bridge "$2" "$3" "$@"
elif [[ "$1" == "log" ]]; then
    smart_log "$2" "$3" "$4" "$5" "$6"
elif [[ "$1" == "write_finding" ]]; then
    smart_write_finding "$2" "$3" "$4" "$5"
elif [[ "$1" == "validate_write" ]]; then
    smart_validate_and_write "$2" "$3" "$4" "$5"
else
    echo "Usage: $0 {bridge|log|write_finding|validate_write} [args]"
    exit 1
fi
