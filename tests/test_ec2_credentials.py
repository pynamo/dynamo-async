from unittest.mock import patch, MagicMock

from dynamo_async.ec2 import ec2_credentials


@patch("http.client.HTTPConnection")
def test_ec2_credentials(mock_http: MagicMock):
    # Mock connection and response
    mock_conn = MagicMock()
    mock_http.return_value = mock_conn

    # Mock token request
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"mock-token"
    mock_conn.getresponse.return_value = mock_response

    # Mock role name request
    mock_response.read.return_value = b"mock-role"
    mock_conn.getresponse.return_value = mock_response

    # Mock credentials request
    mock_response.read.return_value = (
        b'{"AccessKeyId": "AKIA...", "SecretAccessKey": "SECRET..."}'
    )
    mock_conn.getresponse.return_value = mock_response

    credentials = ec2_credentials()

    assert credentials == '{"AccessKeyId": "AKIA...", "SecretAccessKey": "SECRET..."}'
    assert mock_http.called
    assert mock_conn.request.call_count == 3
