#!/usr/bin/env python3
"""Read-only BIG-IP tenant/partition inventory collector."""

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import logging
import re
import shlex
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import paramiko

SCRIPT_NAME = "bigip_tenant_info"
TIMESTAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

PARTITION_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

SECTION_COMMANDS = {
    "system_version": ("show sys version", False),
    "hostname": ("list sys global-settings hostname", False),
    "routes": ("list net route all-properties", True),
    "route_domains": ("list net route-domain all-properties", True),
    "vlans": ("list net vlan all-properties", True),
    "self_ips": ("list net self all-properties", True),
    "arp": ("show net arp", True),
    "interfaces": ("show net interface", True),
    "virtual_servers": ("list ltm virtual all-properties", True),
    "pools": ("list ltm pool all-properties", True),
    "snat": ("list ltm snat all-properties", True),
}

@dataclass
class CommandResult:
    section: str
    status: str
    exit_status: int
    command: str
    lines: int
    object_count: int
    output: str
    error: str = ""

class AuditLogger:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def command(self, section: str, command: str) -> None:
        self.logger.info("[%s] %s", section, command)

    def result(self, result: CommandResult) -> None:
        self.logger.info(
            "[%s] status=%s exit=%s lines=%s objects=%s",
            result.section,
            result.status,
            result.exit_status,
            result.lines,
            result.object_count,
        )

        if result.error:
            self.logger.warning(
                "[%s] %s",
                result.section,
                result.error,
            )

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect read-only routing and tenant information from BIG-IP."
    )

    parser.add_argument(
        "--host",
        required=True,
        help="BIG-IP management hostname or IP",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port; default: 22",
    )

    parser.add_argument(
        "--username",
        help="SSH username; prompted if omitted",
    )

    parser.add_argument(
        "--password",
        help="SSH password; prompted if omitted",
    )

    parser.add_argument(
        "--partition",
        default="Common",
        help="BIG-IP partition/tenant; default: Common",
    )

    parser.add_argument(
        "--route-domain",
        type=int,
        help="Optional route-domain ID",
    )

    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Target IP for route and ping checks; repeatable",
    )

    parser.add_argument(
        "--skip-ltm",
        action="store_true",
        help="Skip virtual server, pool, and SNAT collection",
    )

    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory",
    )

    parser.add_argument(
        "--command-timeout",
        type=int,
        default=120,
        help="Per-command timeout in seconds",
    )

    parser.add_argument(
        "--strict-host-key",
        action="store_true",
        help="Reject unknown SSH host keys",
    )

    return parser.parse_args()

def validate_partition(partition: str) -> str:
    partition = partition.strip().strip("/")

    if not partition or not PARTITION_RE.fullmatch(partition):
        raise ValueError(
            "Partition must contain only letters, numbers, "
            "underscore, dot, or hyphen"
        )

    return partition

def validate_route_domain(route_domain: Optional[int]) -> None:
    if route_domain is not None and not 0 <= route_domain <= 65535:
        raise ValueError(
            "Route-domain ID must be between 0 and 65535"
        )

def validate_targets(targets: Iterable[str]) -> List[str]:
    validated = []

    for target in targets:
        target = target.strip()

        try:
            ipaddress.ip_address(target)
        except ValueError as exc:
            raise ValueError(
                f"Target must be an IPv4 or IPv6 address: {target}"
            ) from exc

        validated.append(target)

    return validated

def setup_logging(log_path: Path) -> logging.Logger:
    logger = logging.getLogger(SCRIPT_NAME)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s"
    )

    file_handler = logging.FileHandler(
        log_path,
        encoding="utf-8",
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger

def object_count(output: str) -> int:
    count = 0

    for line in output.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith("{"):
            count += 1

    return count

def clean_error(
    stderr: str,
    output: str,
    exit_status: int,
) -> str:
    message = stderr.strip() or output.strip()

    if not message and exit_status:
        message = f"remote command exited with status {exit_status}"

    return message.replace("\n", " | ")[:2000]

def tmsh_command(
    operation: str,
    partition: Optional[str] = None,
) -> str:
    if partition:
        tmsh_expression = f"cd /{partition}; {operation}"
    else:
        tmsh_expression = operation

    return f"tmsh -q -c {shlex.quote(tmsh_expression)}"

def context_target(
    target: str,
    route_domain: Optional[int],
) -> str:
    if route_domain is None:
        return target

    return f"{target}%{route_domain}"

def connect(
    args: argparse.Namespace,
    username: str,
    password: str,
    logger: logging.Logger,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()

    if args.strict_host_key:
        client.load_system_host_keys()
        client.set_missing_host_key_policy(
            paramiko.RejectPolicy()
        )
    else:
        logger.warning(
            "SSH host-key verification is disabled; "
            "use --strict-host-key in production"
        )

        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

    logger.info(
        "Connecting to %s:%s",
        args.host,
        args.port,
    )

    client.connect(
        hostname=args.host,
        port=args.port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=30,
        banner_timeout=60,
        auth_timeout=60,
    )

    logger.info(
        "Connected to %s",
        args.host,
    )

    return client

def execute(
    client: paramiko.SSHClient,
    section: str,
    command: str,
    timeout: int,
    audit_logger: AuditLogger,
) -> CommandResult:
    audit_logger.command(section, command)

    stdout_text = ""
    stderr_text = ""
    exit_status = -1

    try:
        _, stdout, stderr = client.exec_command(
            command,
            timeout=timeout,
        )

        stdout_text = stdout.read().decode(
            "utf-8",
            errors="replace",
        )

        stderr_text = stderr.read().decode(
            "utf-8",
            errors="replace",
        )

        exit_status = stdout.channel.recv_exit_status()

        error = clean_error(
            stderr_text,
            stdout_text,
            exit_status,
        )

        status = (
            "OK"
            if exit_status == 0 and not stderr_text.strip()
            else "ERROR"
        )

    except Exception as exc:
        error = str(exc)
        status = "ERROR"

    result = CommandResult(
        section=section,
        status=status,
        exit_status=exit_status,
        command=command,
        lines=len(stdout_text.splitlines()),
        object_count=object_count(stdout_text),
        output=stdout_text,
        error=error if status == "ERROR" else "",
    )

    audit_logger.result(result)

    return result

def collect_sections(
    client: paramiko.SSHClient,
    partition: str,
    skip_ltm: bool,
    timeout: int,
    audit_logger: AuditLogger,
) -> Dict[str, CommandResult]:
    collected = {}

    for section, (
        operation,
        partition_scoped,
    ) in SECTION_COMMANDS.items():

        if skip_ltm and section in {
            "virtual_servers",
            "pools",
            "snat",
        }:
            continue

        context = partition if partition_scoped else None

        command = tmsh_command(
            operation,
            context,
        )

        collected[section] = execute(
            client,
            section,
            command,
            timeout,
            audit_logger,
        )

    return collected

def collect_target_checks(
    client: paramiko.SSHClient,
    partition: str,
    route_domain: Optional[int],
    targets: List[str],
    timeout: int,
    audit_logger: AuditLogger,
) -> Dict[str, List[CommandResult]]:
    route_results = []
    ping_results = []

    for target in targets:
        scoped_target = context_target(
            target,
            route_domain,
        )

        route_operation = f"show net route {scoped_target}"
        ping_operation = f"run util ping -c 3 {scoped_target}"

        route_results.append(
            execute(
                client,
                f"target_route:{target}",
                tmsh_command(
                    route_operation,
                    partition,
                ),
                timeout,
                audit_logger,
            )
        )

        ping_results.append(
            execute(
                client,
                f"target_ping:{target}",
                tmsh_command(
                    ping_operation,
                    partition,
                ),
                timeout,
                audit_logger,
            )
        )

    return {
        "target_routes": route_results,
        "target_pings": ping_results,
    }

def write_reports(
    output_dir: Path,
    args: argparse.Namespace,
    partition: str,
    route_domain: Optional[int],
    sections: Dict[str, CommandResult],
    target_checks: Dict[str, List[CommandResult]],
) -> Tuple[Path, Path, Path]:
    stem = f"{SCRIPT_NAME}_{partition}_{TIMESTAMP}"

    summary_csv = output_dir / f"{stem}.csv"
    detail_json = output_dir / f"{stem}.json"
    detail_txt = output_dir / f"{stem}.txt"

    all_results = list(sections.values())
    all_results.extend(
        target_checks.get("target_routes", [])
    )
    all_results.extend(
        target_checks.get("target_pings", [])
    )

    with summary_csv.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "Partition",
                "Route Domain",
                "Section",
                "Status",
                "Exit Status",
                "Command",
                "Lines",
                "Object Count",
                "Error",
            ],
        )

        writer.writeheader()

        for result in all_results:
            writer.writerow(
                {
                    "Partition": partition,
                    "Route Domain": (
                        ""
                        if route_domain is None
                        else route_domain
                    ),
                    "Section": result.section,
                    "Status": result.status,
                    "Exit Status": result.exit_status,
                    "Command": result.command,
                    "Lines": result.lines,
                    "Object Count": result.object_count,
                    "Error": result.error,
                }
            )

    json_payload = {
        "metadata": {
            "generated_utc": TIMESTAMP,
            "host": args.host,
            "partition": partition,
            "route_domain": route_domain,
            "targets": args.target,
            "read_only": True,
        },
        "sections": {
            key: asdict(value)
            for key, value in sections.items()
        },
        "target_checks": {
            key: [
                asdict(value)
                for value in values
            ]
            for key, values in target_checks.items()
        },
    }

    with detail_json.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            json_payload,
            handle,
            indent=2,
        )

    with detail_txt.open(
        "w",
        encoding="utf-8",
    ) as handle:
        handle.write(
            "BIG-IP Tenant Information Report\n"
        )
        handle.write("=" * 80 + "\n")
        handle.write(f"Host: {args.host}\n")
        handle.write(f"Partition: {partition}\n")
        handle.write(
            "Route Domain: "
            f"{route_domain if route_domain is not None else 'N/A'}\n"
        )
        handle.write(
            f"Generated UTC: {TIMESTAMP}\n"
        )
        handle.write(
            "Read-only collection: YES\n\n"
        )

        for result in all_results:
            handle.write(
                f"SECTION: {result.section}\n"
            )
            handle.write(
                f"STATUS: {result.status}\n"
            )
            handle.write(
                f"COMMAND: {result.command}\n"
            )

            if result.error:
                handle.write(
                    f"ERROR: {result.error}\n"
                )

            handle.write("-" * 80 + "\n")
            handle.write(result.output)

            if not result.output.endswith("\n"):
                handle.write("\n")

            handle.write("\n")

    return summary_csv, detail_json, detail_txt

def main() -> int:
    args = parse_args()

    partition = validate_partition(
        args.partition
    )

    validate_route_domain(
        args.route_domain
    )

    args.target = validate_targets(
        args.target
    )

    output_dir = Path(
        args.output_dir
    ).expanduser().resolve()

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_path = output_dir / (
        f"{SCRIPT_NAME}_{partition}_{TIMESTAMP}.log"
    )

    logger = setup_logging(log_path)
    audit_logger = AuditLogger(logger)

    username = (
        args.username
        or input("Username: ").strip()
    )

    password = (
        args.password
        or getpass.getpass("Password: ")
    )

    logger.info(
        "Starting read-only BIG-IP collection: "
        "host=%s partition=%s route_domain=%s",
        args.host,
        partition,
        (
            args.route_domain
            if args.route_domain is not None
            else "N/A"
        ),
    )

    client = None

    try:
        client = connect(
            args,
            username,
            password,
            logger,
        )

        sections = collect_sections(
            client,
            partition,
            args.skip_ltm,
            args.command_timeout,
            audit_logger,
        )

        target_checks = collect_target_checks(
            client,
            partition,
            args.route_domain,
            args.target,
            args.command_timeout,
            audit_logger,
        )

        summary_csv, detail_json, detail_txt = write_reports(
            output_dir,
            args,
            partition,
            args.route_domain,
            sections,
            target_checks,
        )

    except Exception:
        logger.exception(
            "Collection failed"
        )
        return 1

    finally:
        if client is not None:
            client.close()
            logger.info(
                "Disconnected from %s",
                args.host,
            )

    logger.info(
        "CSV report: %s",
        summary_csv,
    )

    logger.info(
        "JSON detail report: %s",
        detail_json,
    )

    logger.info(
        "TXT detail report: %s",
        detail_txt,
    )

    logger.info(
        "Log file: %s",
        log_path,
    )

    return 0

if __name__ == "__main__":
    sys.exit(main())
