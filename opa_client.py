# opa_client.py
import requests
import json

OPA_URL = "http://localhost:8181/v1/data/dac/authz/decision"

def query_opa(input_obj, timeout=2):
    """
    input_obj must be a JSON-serializable object.
    Returns the decoded decision (as OPA returns).
    """
    try:
        resp = requests.post(OPA_URL, json={"input": input_obj}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return data.get("result")
    except Exception as e:
        # Propagate exception to caller to allow fallback
        raise
