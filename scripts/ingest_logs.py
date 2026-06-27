"""
Log Ingestion Script
Entry point for batch or streaming log ingestion into the detection pipeline.

Usage:
  python scripts/ingest_logs.py --source cloudtrail --input logs/trail.jsonl
  python scripts/ingest_logs.py --source syslog --input /var/log/auth.log
  python scripts/ingest_logs.py --source windows --input logs/security.jsonl
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from detectors.sigma_engine import SigmaEngine
from parsers.evtx_parser import EvtxParser
from parsers.syslog_parser import SyslogParser
from parsers.cloudtrail_parser import CloudTrailParser

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Threat Detection SIEM — Log Ingestion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/ingest_logs.py --source windows  --input logs/security.jsonl
  python scripts/ingest_logs.py --source syslog   --input /var/log/auth.log
  python scripts/ingest_logs.py --source cloudtrail --input logs/trail.jsonl
        """
    )
    p.add_argument("--source",  required=True,
                   choices=["windows", "syslog", "cloudtrail"],
                   help="Log source type")
    p.add_argument("--input",   required=True, help="Input log file path")
    p.add_argument("--rules",   default="rules/sigma", help="Sigma rules directory")
    p.add_argument("--output",  help="Output alerts JSONL file")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    out_fh = open(args.output, "w") if args.output else None

    def on_alert(alert):
        line = json.dumps(alert.to_dict(), default=str)
        print(line)
        if out_fh:
            out_fh.write(line + "\n")

    engine = SigmaEngine(rules_dir=args.rules, alert_callback=on_alert)
    n = engine.load_rules()
    logger.info("Loaded %d Sigma rules", n)

    total = 0
    with open(args.input) as fh:
        for raw_line in fh:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                if args.source == "windows":
                    event = json.loads(raw_line)
                elif args.source == "syslog":
                    parsed = SyslogParser().parse_line(raw_line)
                    event = parsed.ecs if parsed else None
                elif args.source == "cloudtrail":
                    record = json.loads(raw_line)
                    parsed = CloudTrailParser().parse(record)
                    event = parsed.ecs if parsed else None
                else:
                    event = None

                if event:
                    engine.process_event(event)
                    total += 1
            except Exception as e:
                logger.warning("Skipping line: %s", e)

    stats = engine.stats
    logger.info("Done. Lines: %d | Alerts: %d", total, stats["alerts"])
    if out_fh:
        out_fh.close()


if __name__ == "__main__":
    main()
