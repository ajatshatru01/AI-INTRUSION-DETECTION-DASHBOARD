from collections import defaultdict, deque
from threading import Lock
import time

lock = Lock()

metrics = {
    "total_flows": 0,
    "attacks": 0,
    "attack_types": defaultdict(int),
    "recent_alerts": deque(maxlen=100),
}

def update_metrics(result, raw):
    with lock:
        metrics["total_flows"] += 1

        if result["is_attack"]:
            metrics["attacks"] += 1
            atk = result["attack_class"]
            metrics["attack_types"][atk] += 1

            metrics["recent_alerts"].appendleft({
                "timestamp": time.time(),
                "attack": atk,
                "confidence": result["multiclass_confidence"],
                "src_ip": raw.get("Src IP", "NA"),
                "dst_ip": raw.get("Dst IP", "NA")
            })

def get_metrics():
    with lock:
        return {
            "total_flows": metrics["total_flows"],
            "attacks": metrics["attacks"],
            "attack_types": dict(metrics["attack_types"]),
            "recent_alerts": list(metrics["recent_alerts"])
        }
