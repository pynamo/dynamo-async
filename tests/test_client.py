import pytest
from unittest.mock import AsyncMock, patch, MagicMock, ANY
from dynamo_async import DynamoAsyncClient, DynamoDBError
from dynamo_async.client import json_encoder


@pytest.fixture
def mock_client():
    mock_session = AsyncMock()
    mock_session.post = AsyncMock()
    return mock_session


@pytest.fixture
def client(mock_client: AsyncMock):
    async def client_factory():
        return mock_client

    client = DynamoAsyncClient(
        client_factory=client_factory,
        region="us-east-1",
        access_key="access-key",
        secret_key="secret-key",
        session_token="session-token",
    )
    return client


@pytest.mark.asyncio
async def test_get_item_success(client: DynamoAsyncClient, mock_client: AsyncMock):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={"Item": {"id": {"S": "123"}}})
    mock_client.post.return_value = mock_response

    payload = {"TableName": "test-table", "Key": {"id": {"S": "123"}}}
    result = await client.get_item(payload)

    assert result == {"Item": {"id": {"S": "123"}}}
    mock_client.post.assert_called_once_with(
        "https://dynamodb.us-east-1.amazonaws.com/",
        data=json_encoder.encode(payload),
        headers=ANY,
    )


@pytest.mark.asyncio
async def test_get_item_with_retries(client: DynamoAsyncClient, mock_client: AsyncMock):
    mock_response_1 = MagicMock()
    mock_response_1.status = 500
    mock_response_1.json = AsyncMock(return_value={"__type": "InternalServerError"})

    mock_response_2 = MagicMock()
    mock_response_2.status = 200
    mock_response_2.json = AsyncMock(return_value={"Item": {"id": {"S": "456"}}})

    mock_client.post.side_effect = [mock_response_1, mock_response_2]

    payload = {"TableName": "test-table", "Key": {"id": {"S": "456"}}}
    result = await client.get_item(payload)

    assert result == {"Item": {"id": {"S": "456"}}}
    assert mock_client.post.call_count == 2


@pytest.mark.asyncio
async def test_get_item_max_retries(client: DynamoAsyncClient, mock_client: AsyncMock):
    mock_response = MagicMock()
    mock_response.status = 500

    mock_client.post.side_effect = lambda *args, **kwargs: MagicMock(  # type: ignore
        status=500,
        json=AsyncMock(
            return_value={"__type": "InternalServerError"},
        ),
    )

    payload = {"TableName": "test-table", "Key": {"id": {"S": "123"}}}

    with pytest.raises(DynamoDBError, match="AWS error: InternalServerError"):
        await client.get_item(payload)

    assert mock_client.post.call_count == client.max_retries


@pytest.mark.asyncio
async def test_missing_credentials():
    async def client_factory():
        return AsyncMock()

    with pytest.raises(Exception, match="Could not determine credentials"):
        DynamoAsyncClient(
            client_factory=client_factory,
            region="us-east-1",
        )


@pytest.mark.asyncio
async def test_custom_endpoint():
    client = DynamoAsyncClient(
        endpoint="http://localhost:4566",
        access_key="access-key",
        secret_key="secret-key",
        session_token="session-token",
    )

    payload = {"TableName": "test-table", "Key": {"id": {"S": "123"}}}

    with patch.object(
        client, "_request", return_value={"Item": {"id": {"S": "123"}}}
    ) as mock_request:
        result = await client.get_item(payload)

        assert result == {"Item": {"id": {"S": "123"}}}
        mock_request.assert_called_once_with("DynamoDB_20120810.GetItem", payload)


@pytest.mark.asyncio
async def test_custom_endpoint2(mock_client: AsyncMock):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={"Item": {"id": {"S": "123"}}})
    mock_client.post.return_value = mock_response

    async def client_factory():
        return mock_client

    client = DynamoAsyncClient(
        client_factory=client_factory,
        endpoint="http://localhost:4566",
        region="us-east-1",
        access_key="access-key",
        secret_key="secret-key",
        session_token="session-token",
    )

    payload = {"TableName": "test-table", "Key": {"id": {"S": "123"}}}
    result = await client.get_item(payload)

    assert result == {"Item": {"id": {"S": "123"}}}
    mock_client.post.assert_called_once_with(
        "http://localhost:4566",
        data=json_encoder.encode(payload),
        headers=ANY,
    )


@pytest.mark.asyncio
async def test_client_creation_failure():
    async def client_factory():
        raise Exception("Failed to create session")

    with pytest.raises(Exception, match="Failed to create session"):
        client = DynamoAsyncClient(
            client_factory=client_factory,
            region="us-east-1",
            access_key="access-key",
            secret_key="secret-key",
        )
        await client.get_item({})
