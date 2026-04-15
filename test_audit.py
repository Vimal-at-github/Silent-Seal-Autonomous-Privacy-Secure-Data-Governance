from core.audit import get_audit_logger
import json

logger = get_audit_logger()
logs = logger.get_all_logs(limit=10)
print(f"Total logs found: {len(logs)}")
print(json.dumps(logs, indent=2, default=str))
