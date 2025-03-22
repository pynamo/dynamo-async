from typing import Optional


def ec2_credentials() -> str:
    # Syncronous implementation to fetch ec2 credentials.
    import http.client

    conn: Optional[http.client.HTTPConnection] = None

    try:
        conn = http.client.HTTPConnection("169.254.169.254", timeout=1)
        conn.request(
            "PUT",
            "/latest/api/token",
            headers={
                "X-aws-ec2-metadata-token-ttl-seconds": "21600",
            },
        )
        response = conn.getresponse()
        if response.status != 200:
            raise Exception(f"Failed to get token: {response.status}")
        token = response.read().decode()
        conn.request(
            "GET",
            "/latest/meta-data/security-credentials",
            headers={
                "x-aws-ec2-metadata-token": token,
            },
        )
        response = conn.getresponse()
        if response.status != 200:
            raise Exception(f"Failed to get role name: {response.status}")
        role_name = response.read().decode().strip()

        conn.request(
            "GET",
            f"/latest/meta-data/iam/security-credentials/{role_name}",
            headers={"X-aws-ec2-metadata-token": token},
        )
        response = conn.getresponse()
        if response.status != 200:
            raise Exception(f"Failed to get credentials: {response.status}")

        credentials = response.read().decode()

        return credentials

    finally:
        if conn is not None:
            conn.close()
