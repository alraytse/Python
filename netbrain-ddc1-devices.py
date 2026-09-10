import csv
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
BASE_URL = "https://netbrain.mckesson.com"
API_PREFIX = f"{BASE_URL}/ServicesAPI/API/V1"

USERNAME = "skk30ws"
PASSWORD = "REPLACE_WITH_YOUR_ROTATED_PASSWORD"

OUTPUT_FILE = (
    "/Users/alex.raytselsky/Downloads/ddc1_network_inventory.csv"
)

DEBUG_LOG_FILE = (
    "/Users/alex.raytselsky/Downloads/ddc1_netbrain_debug.log"
)

MAX_WORKERS = 50
PAGE_LIMIT = 100
MAX_ESTIMATED_PAGES = 100

DEFAULT_VRFS = {
    "default",
    "mgmt",
    "management",
    "global",
    "none",
    "null",
    "",
}

# --- Logging ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(DEBUG_LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)

logger = logging.getLogger(__name__)

def api_get(label, url, params, timeout):
    """Execute a GET request and log status, response keys, and errors."""
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            verify=False,
            timeout=timeout,
        )

        body_preview = response.text[:2000].replace("\n", " ")

        logger.info(
            "[%s] HTTP %s URL=%s PARAMS=%s BODY=%s",
            label,
            response.status_code,
            response.url,
            params,
            body_preview,
        )

        if response.status_code != 200:
            return None, (
                f"HTTP {response.status_code}: "
                f"{body_preview[:500]}"
            )

        try:
            payload = response.json()
        except ValueError as error:
            return None, f"Invalid JSON response: {error}"

        if isinstance(payload, dict):
            logger.debug(
                "[%s] Response keys: %s",
                label,
                list(payload.keys()),
            )

        return payload, None

    except Exception as error:
        logger.exception("[%s] Request failed: %s", label, error)
        return None, str(error)

# --- Authenticate ---
headers = {}

login_url = f"{API_PREFIX}/Session"
login_payload = {
    "username": USERNAME,
    "password": PASSWORD,
}

print("Logging into NetBrain...")
logger.info("Logging into NetBrain using API endpoint: %s", login_url)

try:
    response = requests.post(
        login_url,
        json=login_payload,
        verify=False,
        timeout=30,
    )
except Exception as error:
    logger.exception("Authentication request failed")
    raise Exception(f"Authentication request failed: {error}")

logger.info(
    "Authentication response: HTTP %s BODY=%s",
    response.status_code,
    response.text[:1000].replace("\n", " "),
)

if response.status_code != 200:
    raise Exception(
        f"Authentication failed ({response.status_code}): "
        f"{response.text}"
    )

login_data = response.json()
token = login_data.get("token")

if not token:
    raise Exception("Token not found in login response payload.")

headers = {
    "Token": token,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

if login_data.get("tenantId") and login_data.get("domainId"):
    headers["tenantId"] = login_data["tenantId"]
    headers["domainId"] = login_data["domainId"]

logger.info("Authentication successful.")

def fetch_device_page(skip_value):
    """Retrieve one page of device records."""
    url = f"{API_PREFIX}/CMDB/Devices"
    params = {
        "skip": skip_value,
        "limit": PAGE_LIMIT,
    }

 