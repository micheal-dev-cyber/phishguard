"""SIEM Webhook Integration — push alerts to Splunk, Elastic, QRadar."""

import json
import logging
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("siem")


class SIEMClient:
    def __init__(self):
        from src.env import ENV
        self.splunk_url = getattr(ENV, "SIEM_SPLUNK_HEC_URL", "") or ""
        self.splunk_token = getattr(ENV, "SIEM_SPLUNK_HEC_TOKEN", "") or ""
        self.elastic_cloud_id = getattr(ENV, "SIEM_ELASTIC_CLOUD_ID", "") or ""
        self.elastic_api_key = getattr(ENV, "SIEM_ELASTIC_API_KEY", "") or ""
        self.qradar_url = getattr(ENV, "SIEM_QRAZAR_URL", "") or ""
        self.qradar_key = getattr(ENV, "SIEM_QRAZAR_API_KEY", "") or ""

    @property
    def any_enabled(self) -> bool:
        return bool(self.splunk_url or self.elastic_cloud_id or self.qradar_url)

    def dispatch(self, event: dict) -> list:
        """Send a threat event to all configured SIEM targets."""
        results = []
        if self.splunk_url:
            results.append(self._send_splunk(event))
        if self.elastic_cloud_id:
            results.append(self._send_elastic(event))
        if self.qradar_url:
            results.append(self._send_qradar(event))
        return results

    def _send_splunk(self, event: dict) -> dict:
        payload = json.dumps({
            "event": event,
            "sourcetype": "phishguard:threat",
            "host": "phishguard",
        }).encode()
        req = Request(
            self.splunk_url.rstrip("/") + "/services/collector",
            data=payload,
            headers={"Authorization": f"Splunk {self.splunk_token}"},
        )
        return self._post(req, "Splunk")

    def _send_elastic(self, event: dict) -> dict:
        payload = json.dumps({
            "@timestamp": event.get("timestamp", ""),
            "message": json.dumps(event),
            "service": "phishguard",
            "severity": event.get("severity", "LOW"),
            "risk_score": event.get("risk_score", 0),
        }).encode()
        req = Request(
            f"https://{self.elastic_cloud_id}.elastic-cloud.com/api/v1/logs",
            data=payload,
            headers={
                "Authorization": f"ApiKey {self.elastic_api_key}",
                "Content-Type": "application/json",
            },
        )
        return self._post(req, "Elastic")

    def _send_qradar(self, event: dict) -> dict:
        payload = json.dumps({
            "events": [{
                "eventName": "PhishGuard Threat Alert",
                "severity": event.get("severity", "Low"),
                "riskScore": event.get("risk_score", 0),
                "sourceIp": event.get("source_ip", ""),
                "destinationIp": event.get("destination_ip", ""),
                "domain": event.get("domain", ""),
                "username": event.get("username", ""),
                "customPayload": json.dumps(event),
            }],
        }).encode()
        req = Request(
            self.qradar_url.rstrip("/") + "/api/ariel/events",
            data=payload,
            headers={
                "SEC": self.qradar_key,
                "Content-Type": "application/json",
            },
        )
        return self._post(req, "QRadar")

    def _post(self, req: Request, name: str) -> dict:
        try:
            resp = urlopen(req, timeout=10)
            resp.read().decode()
            logger.info("SIEM %s: %d", name, resp.status)
            return {"siem": name, "status": resp.status, "success": True}
        except URLError as e:
            logger.error("SIEM %s failed: %s", name, e)
            return {"siem": name, "status": 0, "success": False, "error": str(e)}
        except Exception as e:
            logger.error("SIEM %s error: %s", name, e)
            return {"siem": name, "status": 0, "success": False, "error": str(e)}
