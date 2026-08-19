#!/bin/bash
# Dark Recon Framework - Enhanced Phase Bridge Main Wrapper
# This script provides the main interface for enhanced phase integration

# Global variables
PHASE_BRIDGE_SCRIPT="$(dirname "${BASH_SOURCE[0]}")/scripts/phase_bridge.sh"
PYTHON_BRIDGE="$(dirname "${BASH_SOURCE[0]}")/lib/phase_bridge.py"
LOG_DIR="logs"
PHASE_BRIDGE_VERSION="1.0.2-Enhanced"

# Display help information
usage() {
    cat << EOF
Dark Recon Framework - Enhanced Phase Bridge
==================================================

Version: $PHASE_BRIDGE_VERSION

Usage: $(basename "${BASH_SOURCE[0]}") <command> [options]

Commands:

  bridge <phase_name> <target> [args]
    Execute a phase using Python-enhanced integration
    
    Example: $(basename "${BASH_SOURCE[0]}") bridge subdomain my.target.com

  log <level> <phase> <target> <message> [event] [metadata]
    Create a structured log entry using Python integration
    
    Example: $(basename "${BASH_SOURCE[0]}") log INFO subdomain my.target.com "Found subdomain"

  write_finding <phase> <target> <output_dir> <finding_json>
    Write a finding with Python validation
    
    Example: $(basename "${BASH_SOURCE[0]}") write_finding subdomain my.target.com ./output '{"type":"subdomain","value":"test","target":"my.target.com"}'

  validate_write <phase> <target> <output_file> <data_json>
    Validate and write data using Python integration
    
    Example: $(basename "${BASH_SOURCE[0]}") validate_write subdomain my.target.com ./data.json '{"type":"scan","results":[]}'

  status
    Show Phase Bridge integration status and statistics

  init
    Initialize Phase Bridge logging infrastructure

Options:

  -h, --help
    Show this help message

  -v, --version
    Show Phase Bridge version

  --quiet
    Suppress non-error messages

Configuration:

  Log directory: $LOG_DIR/
  Phase bridge script: $PHASE_BRIDGE_SCRIPT
  Python bridge: $PYTHON_BRIDGE
EOF
}

# Display version information
version() {
    cat << EOF
Dark Recon Framework - Enhanced Phase Bridge
==================================================
Version: $PHASE_BRIDGE_VERSION
Build: Enhanced Integration Edition

Python Bridge: $(basename "$PYTHON_BRIDGE")
Shell Bridge: $(basename "$PHASE_BRIDGE_SCRIPT")

Integration Features:
  ✅ Enhanced Python structured logging
  ✅ Shell-to-Python message conversion
  ✅ Python validation and schema checking
  
  ✅ Smart finding writing with metadata
  ✅ Phase execution tracking
  ✅ Integration statistics and metrics

Phase Integration:
  • subdomain_phase.sh (enhanced)
  • vuln_phase.sh (pending integration)
  • fuzz_phase.sh (pending integration)
  • takeover_phase.sh (pending integration)
  • And ~296 other phases (in progress)

For more information, visit: https://github.com/darkness-recon/dark_recon_framework
EOF
}

# Initialize Phase Bridge logging infrastructure
init_phase_bridge() {
    echo "Initializing Enhanced Phase Bridge..."
    
    # Create necessary directories
    mkdir -p "$LOG_DIR/phases"
    mkdir -p "$LOG_DIR/bridge"
    mkdir -p "$LOG_DIR/integration"
    
    # Initialize log files
    touch "$LOG_DIR/phase_bridge.log"
    touch "$LOG_DIR/integration.log"
    touch "$LOG_DIR/bridge.log"
    
    # Create index file
    cat > "$LOG_DIR/phase_bridge_index.json" << EOF
{
  "version": "$PHASE_BRIDGE_VERSION",
  "initialized_at": "$(date -Iseconds)",
  "status": "ready",
  "python_bridge": "$PYTHON_BRIDGE",
  "shell_bridge": "$PHASE_BRIDGE_SCRIPT"
}
EOF
    
    echo "Enhanced Phase Bridge initialized successfully"
    echo "Logs are stored in: $LOG_DIR/"
}

# Execute phase bridge with integration
execute_phase_bridge() {
    local phase_name="$1"
    local target="$2"
    shift 2
    
    # Validate inputs
    if [[ -z "$phase_name" ]]; then
        echo "ERROR: phase_name is required" >&2
        exit 1
    fi
    
    if [[ -z "$target" ]]; then
        echo "ERROR: target is required" >&2
        exit 1
    fi
    
    
    # Check if Python bridge exists
    if [[ ! -f "$PYTHON_BRIDGE" ]]; then
        echo "ERROR: Python bridge not found: $PYTHON_BRIDGE" >&2
        exit 1
    fi
    
    
    # Check if shell bridge exists
    if [[ ! -f "$PHASE_BRIDGE_SCRIPT" ]]; then
        echo "ERROR: Shell bridge not found: $PHASE_BRIDGE_SCRIPT" >&2
        exit 1
    fi
    
    
    # Initialize logging for this phase
    mkdir -p "logs/phases"
    
    echo "Executing phase: $phase_name for target: $target"
    echo "Phase bridge script: $PHASE_BRIDGE_SCRIPT"
    echo "Python bridge: $PYTHON_BRIDGE"
    
    # Execute the phase bridge wrapper
    "$PHASE_BRIDGE_SCRIPT" "bridge" "$phase_name" "$target" "$@"
}

# Show Phase Bridge integration status
show_status() {
    if [[ -f "$LOG_DIR/phase_bridge_index.json" ]]; then
        echo "Enhanced Phase Bridge Status:"
        echo "======================="
        
        # Parse and display integration status
        local index_content=$(cat "$LOG_DIR/phase_bridge_index.json")
        echo "$index_content"
        
        echo ""
        echo "Integration Statistics:"
        echo "======================="
        
        if [[ -f "$LOG_DIR/integration.log" ]]; then
            local total_events=$(wc -l < "$LOG_DIR/integration.log" 2>/dev/null || echo 0)
            echo "Total integration events: $total_events"
        else
            echo "Total integration events: 0 (log file not found)"
        fi
        
        if [[ -d "logs/phases" ]]; then
            local phase_count=$(ls "logs/phases" | wc -l)
            echo "Active phase logs: $phase_count"
        else
            echo "Active phase logs: 0"
        fi
        
        echo ""
        echo "Python Bridge Status:"
        echo "======================="
        echo "Python bridge file: $PYTHON_BRIDGE"
        if [[ -f "$PYTHON_BRIDGE" ]]; then
            local python_size=$(wc -c < "$PYTHON_BRIDGE" 2>/dev/null || echo ): "$(basename "$PYTHON_BRIDGE")"
            echo "Size: ${python_size} bytes"
            
            # Count Python classes/functions (simplified)
            local python_lines=$(grep -c "^class\|^def " "$PYTHON_BRIDGE" 2>/dev/null || echo 0)
            echo "Python definitions: ${python_lines}"
        else
            echo "Python bridge: Not found"
        fi
        
        echo ""
        echo "Shell Bridge Status:"
        echo "======================="
        echo "Shell bridge file: $PHASE_BRIDGE_SCRIPT"
        if [[ -f "$PHASE_BRIDGE_SCRIPT" ]]; case "$1" in
        *"log")
            shift
            smart_log "$1" "$2" "$3" "$4" "$5"
            return
            ;;
        *"write_finding")
            shift
            smart_write_finding "$1" "$2" "$3" "$4"
            return
            ;;
        *"validate_write")
            shift
            smart_validate_and_write "$1" "$2" "$3" "$4"
            return
            ;;
        *"status")
            show_status
            return
            ;;
        *"init")
            init_phase_bridge
            return
            ;;
        *"--help"|--help)
            usage
            return
            ;;
        *"-v"|--version)
            version
            return
            ;;
        *"--quiet")
            QUIET=true
            shift
            "main_logic_for_quiet_mode"
            return
            ;;
        *"bridge")
            execute_phase_bridge "$2" "$3" "$@"
            return
            ;;
        *"*"|*)
            echo "Unknown command: $1" >&2
            usage
            exit 1
            ;;
esac
    fi
}

# Main execution logic
if [[ -z "${1:-}" ]]; then
    echo "Error: No command provided" >&2
    usage
    exit 1
fi

case "$1" in
    bridge)
        shift
        execute_phase_bridge "$@"
        ;;
    log)
        shift
        smart_log "$@"
        ;;
    write_finding)
        shift
        smart_write_finding "$@"
        ;;
    validate_write)
        shift
        smart_validate_and_write "$@"
        ;;
    status)
        show_status
        ;;
    init)
        init_phase_bridge
        ;;
    --help|-h)
        usage
        ;;
    --version|-v)
        version
        ;;
    --quiet)
        QUIET=true
        shift
        "main_logic_for_quiet_mode"
        ;;
    *)
        echo "Unknown command: $1" >&2
        usage
        exit  instructions for phase bridge usage
$(date +%Y-%m-%d)

Phase Bridge enhanced with Python integration support

Features:
- ✅ Enhanced structured logging
- ✅ Shell-to-Python message conversion
- ' ✅ Python validation and schema checking
- ' ✅ Smart finding writing
- ✅ Phase execution tracking
- ' ✅ Integration statistics
- ' ✅ Error handling and recovery

For more information:
- Documentation: See docs/PHASE_BRIDGE.md
- Examples: See examples/phase_bridge_examples/
- Support: Check docs/support/

Enhanced Phase Bridge initialized successfully
" >> "$LOG_DIR/phase_bridge_index.json"
    
    echo "Enhanced Phase Bridge initialized successfully"
    echo "Type '$(basename "${BASH_SOURCE[0]}") status' to view status"
fi

# Execute main command
if [[ "$QUIET" == "true" ]]; then
    "main_logic_for_quiet_mode"
else
    case "$1" in
        bridge)
            shift
            execute_phase_bridge "$@"
            ;;
        log)
            shift
            smart_log "$@"
            ;;
        write_finding)
            shift
            smart_write_finding "$@"
            ;;
        validate_write)
            shift
            smart_validate_and_write "$@"
            ;;
        status)
            show_status
            ;;
        init)
            init_phase_bridge
            ;;
        --help|-h)
            usage
            ;;
        --version|-v)
            version
            ;;
        *)
            echo "Unknown command: $1" >&2
            usage
            exit 1
            ;;
    esac
fi
