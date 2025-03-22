from unittest.mock import patch, MagicMock

import os

from dynamo_async.ecs import ecs_credentials


@patch.dict(
    os.environ,
    {
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://localhost/credentials",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN": "mock-token",
    },
)
@patch("http.client.HTTPConnection")
def test_ecs_credentials(mock_http: MagicMock):
    mock_conn = MagicMock()
    mock_http.return_value = mock_conn

    # Mock successful response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = (
        b'{"AccessKeyId": "AKIA...", "SecretAccessKey": "SECRET..."}'
    )
    mock_conn.getresponse.return_value = mock_response

    credentials = ecs_credentials()

    assert credentials == '{"AccessKeyId": "AKIA...", "SecretAccessKey": "SECRET..."}'
    mock_http.assert_called_once_with("localhost", timeout=1)
    mock_conn.request.assert_called_once_with(
        "GET", "/credentials", headers={"Authorization": "Bearer mock-token"}
    )
