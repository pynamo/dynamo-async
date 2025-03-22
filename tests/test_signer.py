from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from dynamo_async.signer import sign_request
from dynamo_async.client import json_encoder

TEST_ACCESS_KEY = "ACCESSKEY"
TEST_SECRET_KEY = "SECRETKEY"
TEST_SESSION_TOKEN = "SESSIONTOKEN"


@patch("dynamo_async.signer.datetime.datetime")
def test_sign_request(mock_datetime: MagicMock):
    payload = {"TableName": "my-table", "Key": {"id": {"S": "123"}}}

    mock_datetime.now.return_value = datetime(
        2025,
        3,
        21,
        12,
        12,
        12,
        tzinfo=timezone.utc,
    )
    headers, serialized_payload = sign_request(
        method="POST",
        region="us-east-1",
        amz_target="DynamoDB_20120810.GetItem",
        payload=payload,
        access_key=TEST_ACCESS_KEY,
        secret_key=TEST_SECRET_KEY,
        session_token=TEST_SESSION_TOKEN,
        encoder=json_encoder.encode,
    )

    assert "Authorization" in headers
    assert "x-amz-date" in headers
    assert "x-amz-target" in headers
    assert "x-amz-security-token" in headers
    assert headers["x-amz-target"] == "DynamoDB_20120810.GetItem"
    assert headers["x-amz-date"] == "20250321T121212Z"

    assert serialized_payload == b'{"TableName":"my-table","Key":{"id":{"S":"123"}}}'
    assert (
        headers["x-amz-content-sha256"]
        == "87705e33d68f731ad4c67a39e0db1c3ef7cfa2f9ff5dc6b3ebcff8ad3ebeb2f8"
    )
    assert headers["x-amz-security-token"] == "SESSIONTOKEN"

    assert (
        "c2e495f29917d262a8e656973baaf050fb7af9d27620ab5e16c1bc5b01919d29"
        in headers["Authorization"]
    )
