import http.client
import os
from typing import Any, Dict, Optional
from urllib.parse import urlparse


def ecs_credentials() -> str:
    uri = os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    token = os.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")

    if not uri:
        raise ValueError(
            "Not running in ECS — AWS_CONTAINER_CREDENTIALS_FULL_URI not set"
        )

    parsed = urlparse(uri)
    host = parsed.hostname
    path = parsed.path

    conn: Optional[http.client.HTTPConnection] = None
    try:
        conn = http.client.HTTPConnection(host, timeout=1)  # type: ignore

        headers: Dict[str, Any] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        conn.request("GET", path, headers=headers)
        response = conn.getresponse()

        if response.status != 200:
            raise Exception(
                f"Failed to get credentials: {response.status} {response.reason}"
            )

        credentials = response.read().decode()
        return credentials

    finally:
        if conn is not None:
            conn.close()
