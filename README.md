# dynamo-async

Asynchronous Python client for Amazon DynamoDB.

## Example Usage

```python
from dynamo_async import DynamoAsyncClient
dynamodb_client = DynamoAsyncClient(
	region="us-east-1",
	access_key="...",
	secret_key="...",
)

await dynamodb_client.get_item(
	{"TableName": "my-table", "Key": {"id": {"S": "123"}}}
)
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

result = await dynamodb_client.get_item(
	{"TableName": "my-table", "Key": {"id": {"S": "123"}}}
)
```

## Authentication

If deployed on EC2 or ECS, `dynamo-async` will automatically
use the meta-data services for token access, assuming an iam-role with
correct permissions is assigned. In those cases, just specify the region:

```python
from dynamo_async import DynamoAsyncClient
dynamodb_client = DynamoAsyncClient(
	region="us-east-1",
)
```
