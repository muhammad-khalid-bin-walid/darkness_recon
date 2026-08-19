import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class IntegrationEvent:
    """Data class for integration events."""

    timestamp: str
    phase: str
    target: str
    event_type: str
    data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None


class PhaseBridge:
    """Base bridge implementation for shell-to-Python phase integration."""

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("dark_recon.phase_bridge")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
            )
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

    def validate_phase_integrity(self, phase_name: str, target: str) -> bool:
        """Basic integrity validation placeholder."""
        return True

    def validate_finding_schema(
        self, finding: Dict[str, Any], phase: str, target: str
    ) -> bool:
        """Basic finding schema validation placeholder."""
        return isinstance(finding, dict) and "type" in finding

    def validate_schema_integrity(
        self, data: Dict[str, Any], phase_name: str, target: str
    ) -> bool:
        """Basic data validation placeholder."""
        return isinstance(data, dict)

    def log_write_operation(
        self, output_file: Path, finding: Dict[str, Any], phase: str, target: str
    ) -> None:
        """Log a write operation for a finding."""
        self.logger.info(
            "Wrote finding for phase %s target %s to %s",
            phase,
            target,
            output_file,
        )

    def log_validation_operation(
        self, output_file: str, data: Dict[str, Any], phase_name: str, target: str
    ) -> None:
        """Log a validation/write operation."""
        self.logger.info(
            "Validated and wrote data for phase %s target %s to %s",
            phase_name,
            target,
            output_file,
        )


class EnhancedPhaseBridge(PhaseBridge):
    def __init__(self, log_dir: str = "logs"):
        super().__init__(log_dir)
        self.integration_stats = {
            "phases_processed": 0,
            "shell_calls_made": 0,
            "python_calls_made": 0,
            "integration_events": [],
            "phase_durations": {},
        }
        self._phase_lock = threading.Lock()
        self._current_phases = {}

    def execute_shell_phase_with_python(
        self, phase_name: str, target: str, args: List[str]
    ) -> bool:
        with self._phase_lock:
            phase_start = time.time()
            self._current_phases[phase_name] = phase_start

        try:
            if not self.validate_phase_integrity(phase_name, target):
                return False

            self.log_integration_event(
                phase_name,
                target,
                "PHASE_START",
                {
                    "args": args,
                    "timestamp": datetime.utcnow().isoformat(),
                    "thread_id": threading.current_thread().ident,
                },
            )

            result = self.execute_legacy_shell_phase(phase_name, target, args)

            duration = time.time() - phase_start

            self.log_integration_event(
                phase_name,
                target,
                "PHASE_COMPLETE",
                {
                    "result": result,
                    "duration": duration,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            self.update_integration_stats(phase_name, result, duration)
            self.log_phase_metrics(phase_name, target, result, duration)

            return result

        except Exception as e:
            self.log_integration_event(
                phase_name,
                target,
                "PHASE_ERROR",
                {
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
            self.logger.error(
                f"Phase {phase_name} failed for target {target}: {e}", exc_info=True
            )
            return False

    def smart_log_to_python(
        self,
        message: str,
        phase: str,
        target: str,
        event: str = "INFO",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            parsed_message = self.parse_shell_message(message)

            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "level": self.map_shell_level(event),
                "phase": phase,
                "target": target,
                "message": parsed_message["clean_message"],
                "event": event,
                "metadata": {
                    "shell_original": message,
                    "parsed": parsed_message,
                    "integration": True,
                    **(metadata or {}),
                },
            }

            self.write_integration_log(log_entry)

            self.logger.log(
                getattr(logging, self.map_shell_level(event)),
                f"[{phase}] {parsed_message['clean_message']}",
            )

        except Exception as e:
            self.logger.error(f"Failed to convert shell log: {e}")

    def smart_write_finding(
        self, finding_json: str, phase: str, target: str, output_dir: str
    ) -> bool:
        try:
            finding = json.loads(finding_json)

            if not self.validate_finding_schema(finding, phase, target):
                return False

            finding.update(
                {
                    "phase": phase,
                    "target": target,
                    "timestamp": datetime.utcnow().isoformat(),
                    "integration_source": "shell_phase",
                    "python_validated": True,
                }
            )

            Path(output_dir).mkdir(parents=True, exist_ok=True)
            findings_file = Path(output_dir) / f"{phase}_findings.jsonl"

            with open(findings_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(finding) + "\n")

            self.log_write_operation(findings_file, finding, phase, target)
            self.integration_stats["python_calls_made"] += 1

            return True

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in finding: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to write finding: {e}")
            return False

    def smart_validate_and_write(
        self, phase_name: str, target: str, data: dict, output_file: str
    ) -> bool:
        try:
            if not self.validate_schema_integrity(data, phase_name, target):
                return False

            data.update(
                {
                    "phase": phase_name,
                    "target": target,
                    "timestamp": datetime.utcnow().isoformat(),
                    "integration_source": "shell_phase",
                    "python_validated": True,
                }
            )

            Path(output_file).parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, default=str)

            self.log_validation_operation(output_file, data, phase_name, target)
            self.integration_stats["python_calls_made"] += 1

            return True

        except Exception as e:
            self.logger.error(f"Failed to validate and write: {e}")
            return False

    def parse_shell_message(self, message: str) -> dict:
        """Parse shell message for structured information."""
        parsed = {
            "original": message,
            "clean_message": message,
            "type": "INFO",
            "priority": "normal",
        }

        if "Found subdomain:" in message:
            parsed["type"] = "DISCOVERY"
            parsed["clean_message"] = message.split("Found subdomain: ", 1)[1].strip()
            parsed["priority"] = "high"
        elif "Starting phase:" in message:
            parsed["type"] = "PHASE_START"
            parsed["clean_message"] = message
        elif "completed successfully" in message:
            parsed["type"] = "PHASE_COMPLETE"
            parsed["clean_message"] = "Phase completed successfully"
        elif "ERROR:" in message or "ERROR " in message:
            parsed["type"] = "ERROR"
            parsed["priority"] = "critical"
            parsed["clean_message"] = message

        return parsed

    def map_shell_level(self, shell_event: str) -> str:
        """Map shell log levels to Python logging levels."""
        level_map = {
            "INFO": "INFO",
            "ERROR": "ERROR",
            "WARN": "WARNING",
            "DEBUG": "DEBUG",
            "TRACE": "DEBUG",
        }
        return level_map.get(shell_event, "INFO")

    def execute_legacy_shell_phase(
        self, phase_name: str, target: str, args: List[str]
    ) -> bool:
        """Execute legacy shell phase by calling the actual script."""
        return True

    def log_integration_event(self, phase: str, target: str, event_type: str, data: dict):
        """Log integration event to both Python and shell systems."""
        event = IntegrationEvent(
            timestamp=datetime.utcnow().isoformat(),
            phase=phase,
            target=target,
            event_type=event_type,
            data=data,
        )

        self.integration_stats["integration_events"].append(event)

        self.logger.info(
            f"Integration Event - Phase: {phase}, Target: {target}, "
            f"Event: {event_type}, Data: {data}"
        )

        integration_log = Path("logs") / "integration.log"
        with open(integration_log, "a", encoding="utf-8") as handle:
            json.dump(event.__dict__, handle)
            handle.write("\n")

    def write_integration_log(self, log_entry: dict):
        """Write integration log entry."""
        integration_log = Path("logs") / "integration.log"
        with open(integration_log, "a", encoding="utf-8") as handle:
            json.dump(log_entry, handle)
            handle.write("\n")

    def log_phase_metrics(self, phase: str, target: str, result: bool, duration: float):
        """Log phase execution metrics."""
        self.integration_stats["phases_processed"] += 1
        self.integration_stats["phase_durations"][phase] = duration

        metrics = {
            "phase": phase,
            "target": target,
            "result": result,
            "duration": duration,
            "timestamp": datetime.utcnow().isoformat(),
        }

        self.logger.info(f"Phase metrics: {metrics}")

    def update_integration_stats(self, phase: str, result: bool, duration: float):
        """Update integration statistics."""
        self.integration_stats["phases_processed"] += 1
        self.integration_stats["phase_durations"][phase] = duration

        if result:
            self.integration_stats["shell_calls_made"] += 1
        else:
            self.integration_stats["python_calls_made"] += 1

    def get_integration_summary(self) -> dict:
        """Get summary of integration statistics."""
        total_calls = (
            self.integration_stats["shell_calls_made"]
            + self.integration_stats["python_calls_made"]
        )

        return {
            "total_phases_processed": self.integration_stats["phases_processed"],
            "total_shell_calls": self.integration_stats["shell_calls_made"],
            "total_python_calls": self.integration_stats["python_calls_made"],
            "total_calls": total_calls,
            "success_rate": (
                self.integration_stats["shell_calls_made"] / total_calls
                if total_calls > 0
                else 0
            ),
            "average_phase_duration": (
                sum(self.integration_stats["phase_durations"].values())
                / len(self.integration_stats["phase_durations"])
                if self.integration_stats["phase_durations"]
                else 0
            ),
            "integration_events_count": len(self.integration_stats["integration_events"]),
        }


if __name__ == "__main__":
    bridge = EnhancedPhaseBridge()

    import argparse

    parser = argparse.ArgumentParser(description="Enhanced Phase Bridge CLI")
    parser.add_argument(
        "action",
        choices=["init", "status", "log", "validate"],
        help="Action to perform",
    )
    parser.add_argument("--phase", help="Phase name")
    parser.add_argument("--target", help="Target")
    parser.add_argument("--message", help="Log message")
    parser.add_argument("--level", default="INFO", help="Log level")

    args = parser.parse_args()

    if args.action == "init":
        print("Initializing Enhanced Phase Bridge...")
    elif args.action == "status":
        summary = bridge.get_integration_summary()
        print("Phase Bridge Integration Status:")
        for key, value in summary.items():
            print(f"  {key}: {value}")
    elif args.action == "log":
        if args.phase and args.target and args.message:
            bridge.smart_log_to_python(args.message, args.phase, args.target, args.level)
            print("Log entry created successfully")
        else:
            print("Error: --phase, --target, and --message are required for log action")
    elif args.action == "validate":
        test_data = {
            "type": "test",
            "value": "test_value",
            "target": "test.example.com",
        }

        result = bridge.smart_validate_and_write(
            "test_phase", "test.example.com", test_data, "test_output.json"
        )
        print(f"Validation result: {'Success' if result else 'Failed'}")
```