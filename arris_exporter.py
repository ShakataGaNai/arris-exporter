#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "httpx>=0.28",
#     "prometheus-client>=0.21",
# ]
# ///
"""Prometheus exporter for Arris S33 cable modem."""

import argparse
import hashlib
import hmac
import os
import time
from dataclasses import dataclass

import httpx
from prometheus_client import REGISTRY, Gauge, Info, start_http_server
from prometheus_client.core import GaugeMetricFamily, InfoMetricFamily


def hmac_md5(key: str, message: str) -> str:
    """Compute HMAC-MD5 and return uppercase hex digest."""
    return hmac.new(key.encode(), message.encode(), hashlib.md5).hexdigest().upper()


def hnap_auth(private_key: str, soap_action: str) -> str:
    """Generate the HNAP_AUTH header value."""
    timestamp = str((time.time_ns() // 1_000_000) % 2_000_000_000_000)
    auth_hash = hmac_md5(private_key, timestamp + soap_action)
    return f"{auth_hash} {timestamp}"


@dataclass
class Credential:
    uid: str
    private_key: str


class ArrisS33Client:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.credential: Credential | None = None
        self._client = httpx.Client(verify=verify_ssl, timeout=30.0)

    def _build_cookie(self, uid: str | None = None, private_key: str | None = None) -> str:
        if uid and private_key:
            return f"Secure; Secure; uid={uid}; PrivateKey={private_key}"
        return "Secure; Secure"

    def login(self) -> bool:
        """Perform two-step HNAP login. Returns True on success."""
        soap_action = '"http://purenetworks.com/HNAP1/Login"'
        url = f"{self.base_url}/HNAP1/"

        payload = {
            "Login": {
                "Action": "request",
                "Username": self.username,
                "LoginPassword": "",
                "Captcha": "",
                "PrivateLogin": "LoginPassword",
            }
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "SOAPACTION": soap_action,
            "HNAP_AUTH": "SKIP 0",
            "Cookie": self._build_cookie(),
        }

        try:
            resp = self._client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                return False

            login_resp = resp.json().get("LoginResponse", {})
            public_key = login_resp.get("PublicKey")
            uid = login_resp.get("Cookie")
            challenge = login_resp.get("Challenge")

            if not all([public_key, uid, challenge]):
                return False

            private_key = hmac_md5(public_key + self.password, challenge)
            login_password = hmac_md5(private_key, challenge)

            payload["Login"]["Action"] = "login"
            payload["Login"]["LoginPassword"] = login_password
            headers["Cookie"] = self._build_cookie(uid, private_key)

            resp = self._client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                return False

            login_result = resp.json().get("LoginResponse", {}).get("LoginResult")
            if login_result not in ("OK", "OK_CHANGED"):
                return False

            self.credential = Credential(uid=uid, private_key=private_key)
            return True

        except Exception:
            return False

    def fetch(self, *endpoints: str, retry_auth: bool = True) -> dict | None:
        """Fetch data from HNAP endpoints. Re-authenticates on 404 if retry_auth=True."""
        if not self.credential:
            if not self.login():
                return None

        soap_action = '"http://purenetworks.com/HNAP1/GetMultipleHNAPs"'
        url = f"{self.base_url}/HNAP1/"

        payload = {"GetMultipleHNAPs": {ep: "" for ep in endpoints}}

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "SOAPACTION": soap_action,
            "HNAP_AUTH": hnap_auth(self.credential.private_key, soap_action),
            "Cookie": self._build_cookie(self.credential.uid, self.credential.private_key),
        }

        try:
            resp = self._client.post(url, json=payload, headers=headers)

            # Session expired - re-authenticate and retry once
            if resp.status_code == 404 and retry_auth:
                self.credential = None
                if self.login():
                    return self.fetch(*endpoints, retry_auth=False)
                return None

            if resp.status_code != 200:
                return None

            return resp.json()

        except Exception:
            return None

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def parse_uptime(uptime_str: str) -> int:
    """Parse uptime string like '4 days 21h:04m:41s' to seconds."""
    try:
        parts = uptime_str.split()
        days = int(parts[0]) if "days" in uptime_str or "day" in uptime_str else 0

        time_part = parts[-1] if len(parts) > 1 else parts[0]
        time_part = time_part.replace("h:", ":").replace("m:", ":").replace("s", "")
        h, m, s = map(int, time_part.split(":"))

        return days * 86400 + h * 3600 + m * 60 + s
    except Exception:
        return 0


def parse_downstream_channels(channel_str: str) -> list[dict]:
    """Parse downstream channel string into list of dicts."""
    channels = []
    for entry in channel_str.split("|+|"):
        parts = entry.strip("^").split("^")
        if len(parts) >= 9:
            channels.append({
                "channel_id": parts[3],
                "lock_status": parts[1],
                "modulation": parts[2],
                "frequency_hz": parts[4],
                "power_dbmv": float(parts[5]),
                "snr_db": float(parts[6]),
                "corrected": int(parts[7]),
                "uncorrected": int(parts[8]),
            })
    return channels


def parse_upstream_channels(channel_str: str) -> list[dict]:
    """Parse upstream channel string into list of dicts."""
    channels = []
    for entry in channel_str.split("|+|"):
        parts = entry.strip("^").split("^")
        if len(parts) >= 7:
            channels.append({
                "channel_id": parts[3],
                "lock_status": parts[1],
                "channel_type": parts[2],
                "width_hz": int(parts[4]) if parts[4] != "0" else 0,
                "frequency_hz": parts[5],
                "power_dbmv": float(parts[6]),
            })
    return channels


class ArrisCollector:
    """Custom collector that fetches metrics on-demand when /metrics is scraped."""

    def __init__(self, client: ArrisS33Client):
        self.client = client

    def describe(self):
        # Return empty to indicate this collector doesn't have fixed metrics
        return []

    def collect(self):
        # Modem info
        device = self.client.fetch("GetArrisDeviceStatus", "GetArrisRegisterInfo")
        if device:
            resp = device.get("GetMultipleHNAPsResponse", {})
            dev_status = resp.get("GetArrisDeviceStatusResponse", {})
            reg_info = resp.get("GetArrisRegisterInfoResponse", {})

            info = InfoMetricFamily("arris_modem", "Modem information")
            info.add_metric([], {
                "firmware": dev_status.get("FirmwareVersion", ""),
                "model": reg_info.get("ModelName", ""),
                "mac_address": reg_info.get("MacAddress", ""),
                "serial_number": reg_info.get("SerialNumber", ""),
            })
            yield info

        # Uptime
        status = self.client.fetch("GetCustomerStatusConnectionInfo")
        if status:
            resp = status.get("GetMultipleHNAPsResponse", {})
            conn_info = resp.get("GetCustomerStatusConnectionInfoResponse", {})
            uptime_str = conn_info.get("CustomerConnSystemUpTime", "")

            uptime = GaugeMetricFamily("arris_modem_uptime_seconds", "Modem uptime in seconds")
            uptime.add_metric([], parse_uptime(uptime_str))
            yield uptime

        # Channel info
        channels = self.client.fetch("GetCustomerStatusDownstreamChannelInfo", "GetCustomerStatusUpstreamChannelInfo")
        if channels:
            resp = channels.get("GetMultipleHNAPsResponse", {})

            # Downstream
            ds_labels = ["channel_id", "frequency_hz", "modulation"]
            ds_power = GaugeMetricFamily("arris_downstream_power_dbmv", "Downstream power", labels=ds_labels)
            ds_snr = GaugeMetricFamily("arris_downstream_snr_db", "Downstream SNR/MER", labels=ds_labels)
            ds_corrected = GaugeMetricFamily("arris_downstream_corrected_total", "Downstream corrected codewords", labels=ds_labels)
            ds_uncorrected = GaugeMetricFamily("arris_downstream_uncorrected_total", "Downstream uncorrected codewords", labels=ds_labels)

            ds_resp = resp.get("GetCustomerStatusDownstreamChannelInfoResponse", {})
            ds_str = ds_resp.get("CustomerConnDownstreamChannel", "")
            for ch in parse_downstream_channels(ds_str):
                labels = [ch["channel_id"], ch["frequency_hz"], ch["modulation"]]
                ds_power.add_metric(labels, ch["power_dbmv"])
                ds_snr.add_metric(labels, ch["snr_db"])
                ds_corrected.add_metric(labels, ch["corrected"])
                ds_uncorrected.add_metric(labels, ch["uncorrected"])

            yield ds_power
            yield ds_snr
            yield ds_corrected
            yield ds_uncorrected

            # Upstream
            us_labels = ["channel_id", "frequency_hz", "channel_type"]
            us_power = GaugeMetricFamily("arris_upstream_power_dbmv", "Upstream power", labels=us_labels)
            us_width = GaugeMetricFamily("arris_upstream_width_hz", "Upstream channel width", labels=us_labels)

            us_resp = resp.get("GetCustomerStatusUpstreamChannelInfoResponse", {})
            us_str = us_resp.get("CustomerConnUpstreamChannel", "")
            for ch in parse_upstream_channels(us_str):
                labels = [ch["channel_id"], ch["frequency_hz"], ch["channel_type"]]
                us_power.add_metric(labels, ch["power_dbmv"])
                us_width.add_metric(labels, ch["width_hz"])

            yield us_power
            yield us_width


# Interval-based metrics (initialized lazily when interval > 0)
MODEM_INFO = None
MODEM_UPTIME = None
DS_POWER = None
DS_SNR = None
DS_CORRECTED = None
DS_UNCORRECTED = None
US_POWER = None
US_WIDTH = None


def init_interval_metrics():
    """Initialize global metrics for interval mode."""
    global MODEM_INFO, MODEM_UPTIME, DS_POWER, DS_SNR, DS_CORRECTED, DS_UNCORRECTED, US_POWER, US_WIDTH
    MODEM_INFO = Info("arris_modem", "Modem information")
    MODEM_UPTIME = Gauge("arris_modem_uptime_seconds", "Modem uptime in seconds")
    DS_POWER = Gauge("arris_downstream_power_dbmv", "Downstream power", ["channel_id", "frequency_hz", "modulation"])
    DS_SNR = Gauge("arris_downstream_snr_db", "Downstream SNR/MER", ["channel_id", "frequency_hz", "modulation"])
    DS_CORRECTED = Gauge("arris_downstream_corrected_total", "Downstream corrected codewords", ["channel_id", "frequency_hz", "modulation"])
    DS_UNCORRECTED = Gauge("arris_downstream_uncorrected_total", "Downstream uncorrected codewords", ["channel_id", "frequency_hz", "modulation"])
    US_POWER = Gauge("arris_upstream_power_dbmv", "Upstream power", ["channel_id", "frequency_hz", "channel_type"])
    US_WIDTH = Gauge("arris_upstream_width_hz", "Upstream channel width", ["channel_id", "frequency_hz", "channel_type"])


def collect_metrics_interval(client: ArrisS33Client):
    """Collect metrics for interval-based mode."""
    device = client.fetch("GetArrisDeviceStatus", "GetArrisRegisterInfo")
    if device:
        resp = device.get("GetMultipleHNAPsResponse", {})
        dev_status = resp.get("GetArrisDeviceStatusResponse", {})
        reg_info = resp.get("GetArrisRegisterInfoResponse", {})
        MODEM_INFO.info({
            "firmware": dev_status.get("FirmwareVersion", ""),
            "model": reg_info.get("ModelName", ""),
            "mac_address": reg_info.get("MacAddress", ""),
            "serial_number": reg_info.get("SerialNumber", ""),
        })

    status = client.fetch("GetCustomerStatusConnectionInfo")
    if status:
        resp = status.get("GetMultipleHNAPsResponse", {})
        conn_info = resp.get("GetCustomerStatusConnectionInfoResponse", {})
        uptime_str = conn_info.get("CustomerConnSystemUpTime", "")
        MODEM_UPTIME.set(parse_uptime(uptime_str))

    channels = client.fetch("GetCustomerStatusDownstreamChannelInfo", "GetCustomerStatusUpstreamChannelInfo")
    if channels:
        resp = channels.get("GetMultipleHNAPsResponse", {})

        ds_resp = resp.get("GetCustomerStatusDownstreamChannelInfoResponse", {})
        ds_str = ds_resp.get("CustomerConnDownstreamChannel", "")
        for ch in parse_downstream_channels(ds_str):
            labels = [ch["channel_id"], ch["frequency_hz"], ch["modulation"]]
            DS_POWER.labels(*labels).set(ch["power_dbmv"])
            DS_SNR.labels(*labels).set(ch["snr_db"])
            DS_CORRECTED.labels(*labels).set(ch["corrected"])
            DS_UNCORRECTED.labels(*labels).set(ch["uncorrected"])

        us_resp = resp.get("GetCustomerStatusUpstreamChannelInfoResponse", {})
        us_str = us_resp.get("CustomerConnUpstreamChannel", "")
        for ch in parse_upstream_channels(us_str):
            labels = [ch["channel_id"], ch["frequency_hz"], ch["channel_type"]]
            US_POWER.labels(*labels).set(ch["power_dbmv"])
            US_WIDTH.labels(*labels).set(ch["width_hz"])


def main():
    parser = argparse.ArgumentParser(description="Prometheus exporter for Arris S33")
    parser.add_argument("--url", default=os.getenv("MODEM_URL", "https://192.168.100.1"), help="Modem URL")
    parser.add_argument("--username", default=os.getenv("MODEM_USERNAME", "admin"), help="Username")
    parser.add_argument("--password", default=os.getenv("MODEM_PASSWORD"), help="Password")
    parser.add_argument("--port", type=int, default=int(os.getenv("EXPORTER_PORT", "9393")), help="Exporter port")
    parser.add_argument("--interval", type=int, default=int(os.getenv("SCRAPE_INTERVAL", "30")), help="Scrape interval (0 = on-demand)")
    args = parser.parse_args()

    if not args.password:
        print("Error: --password or MODEM_PASSWORD required")
        return 1

    client = ArrisS33Client(args.url, args.username, args.password)

    if args.interval == 0:
        # On-demand mode: fetch fresh data on each /metrics request
        print(f"Starting Arris S33 exporter on port {args.port} (on-demand mode)")
        REGISTRY.register(ArrisCollector(client))
        start_http_server(args.port)
        # Keep the main thread alive
        while True:
            time.sleep(3600)
    else:
        # Interval mode: poll modem at fixed intervals
        print(f"Starting Arris S33 exporter on port {args.port} (interval: {args.interval}s)")
        init_interval_metrics()
        start_http_server(args.port)
        while True:
            try:
                collect_metrics_interval(client)
            except Exception as e:
                print(f"Error collecting metrics: {e}")
            time.sleep(args.interval)


if __name__ == "__main__":
    exit(main())
