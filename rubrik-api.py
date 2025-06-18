import requests
import urllib3

# Disable warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Rubrik CDM API endpoint and credentials
RUBRIK_CLUSTER = "https://<rubrik-cluster-ip-or-hostname>"
USERNAME = "your_username"
PASSWORD = "your_password"

# API login URL
LOGIN_URL = f"{RUBRIK_CLUSTER}/api/v1/session"

# Start a session
session = requests.Session()
session.verify = False  # Only for self-signed certs

def login():
    """Authenticate and store token in session headers."""
    response = session.post(LOGIN_URL, auth=(USERNAME, PASSWORD))
    if response.status_code == 200:
        print("Login successful.")
        session.headers.update({'Authorization': f"Bearer {response.text}"})
    else:
        print(f"Login failed: {response.status_code} - {response.text}")
        exit()

def get_cluster_info():
    """Fetch Rubrik cluster information."""
    url = f"{RUBRIK_CLUSTER}/api/v1/cluster/me"
    response = session.get(url)
    if response.ok:
        return response.json()
    else:
        print(f"Failed to get cluster info: {response.status_code}")
        return None

if __name__ == "__main__":
    login()
    cluster_info = get_cluster_info()
    if cluster_info:
        print("Cluster Info:")
        print(cluster_info)
