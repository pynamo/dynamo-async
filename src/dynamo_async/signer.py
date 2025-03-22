import datetime
import hashlib
import hmac
from functools import lru_cache
from typing import Any, Callable, Dict, Optional, Tuple

SERVICE: str = "dynamodb"
ALGORITHM: str = "AWS4-HMAC-SHA256"


def sign(key: bytes, msg: str):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


@lru_cache(maxsize=1)  # Cache one value (per day)
def get_signature_key(secret_key: str, date_stamp: str, region: str) -> bytes:
    k_date = sign(f"AWS4{secret_key}".encode(), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, SERVICE)
    k_signing = sign(k_service, "aws4_request")
    return k_signing


def sign_request(
    method: str,
    region: str,
    amz_target: str,
    payload: Dict[str, Any],
    encoder: Callable[[Dict[str, Any]], bytes],
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None,
) -> Tuple[Dict[str, Any], bytes]:
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
    dt_now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = dt_now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = dt_now.strftime("%Y%m%d")

    canonical_uri = "/"
    canonical_querystring = ""

    encoded_payload = encoder(payload)

    hashed_payload = hashlib.sha256(encoded_payload).hexdigest()

    headers = {
        "host": f"dynamodb.{region}.amazonaws.com",
        "x-amz-date": amz_date,
        "x-amz-content-sha256": hashed_payload,
        "x-amz-target": amz_target,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token

    sorted_header_keys = sorted(headers.keys())

    canonical_headers = (
        "\n".join([f"{k}:{headers[k]}" for k in sorted_header_keys]) + "\n"
    )

    signed_headers = ";".join(sorted_header_keys)

    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            hashed_payload,
        ]
    )

    credential_scope = "/".join(
        [
            date_stamp,
            region,
            SERVICE,
            "aws4_request",
        ]
    )
    string_to_sign = "\n".join(
        [
            ALGORITHM,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    signing_key = get_signature_key(secret_key, date_stamp, region)

    signature = hmac.new(
        signing_key,
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    authorization_header = (
        f"{ALGORITHM} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers["Authorization"] = authorization_header
    headers["Content-Type"] = "application/json"

    return headers, encoded_payload
