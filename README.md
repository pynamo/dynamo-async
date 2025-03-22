# dynamo-async

Asynchronous Python client for Amazon DynamoDB.

## Features

- **Async-first** — Built on `asyncio` and `aiohttp`
- **AWS Signature v4** — Fully compatible with AWS DynamoDB authentication
- **Automatic Retries** — Handles transient AWS errors gracefully

---

## Example Usage

```python
from dynamo_async import DynamoAsyncClient
dynamodb_client = DynamoAsyncClient(
	region="us-east-1",
	access_key="...",
	secret_key="...",
)

await client.get_item(TableName=...)
```

#### Customize the aiohttp client session

You can supply a custom `aiohttp.ClientSession` for advanced connection pooling:

```python
from dynamo_async import DynamoAsyncClient

async def client_factory():
	# Refer to the aiohttp documention
	conn = aiohttp.TCPConnector(...)
	aiohttp_client = aiohttp.ClientSession(connector=conn)
	return aiohttp_client

dynamodb_client = DynamoAsyncClient(
	client_factory=client_factory,
	...,
)

result = await client.get_item(
	{"TableName": "my-table", "Key": {"id": {"S": "123"}}}
)
```
