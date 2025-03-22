import asyncio
import atexit
import datetime
import logging
import random
import signal
import threading
import weakref
from os import environ
from typing import Any, Awaitable, Callable, Dict, Literal, Optional, Tuple

import aiohttp
import msgspec

from . import ec2, ecs
from .signer import sign_request

logger = logging.getLogger("dynio")
logger.addHandler(logging.NullHandler())


DYNIO_CLIENTS: weakref.WeakValueDictionary[int, "DynamoAsyncClient"] = (
    weakref.WeakValueDictionary()
)


class DynamoDBError(Exception):
    pass


def cleanup():
    for _, client in DYNIO_CLIENTS.items():
        client.stop_refresh_thread()
        try:
            loop = asyncio.get_running_loop()
            loop.run_until_complete(client.client.close())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(client.client.close())


def handle_exit(signum, frame):  # type: ignore
    cleanup()


signal.signal(signal.SIGINT, handle_exit)  # type: ignore
signal.signal(signal.SIGTERM, handle_exit)  # type: ignore
atexit.register(cleanup)

json_encoder = msgspec.json.Encoder()
json_decoder = msgspec.json.Decoder()


class DynamoAsyncClient:
    """
    Async client for AWS DynamoDB using aiohttp.

    Handles signing, retries, and connection management for high-performance
    DynamoDB interaction over HTTP.

    :param client_factory: Factory function to create an aiohttp ClientSession.
    :type client_factory: Callable[[], aiohttp.ClientSession]
    :param region: AWS region (e.g., "us-east-1"). If not set, ``endpoint`` must be provided.
    :type region: Optional[str]
    :param endpoint: Custom DynamoDB endpoint (e.g., "http://localhost:8000").
    :type endpoint: Optional[str]
    :param access_key: AWS access key.
    :type access_key: Optional[str]
    :param secret_key: AWS secret key.
    :type secret_key: Optional[str]
    :param session_token: AWS session token for temporary credentials.
    :type session_token: Optional[str]

    :param user_agent: Custom user-agent string for tracking requests.
    :type user_agent: str
    :param max_retries: Number of retries for transient AWS errors.
    :type max_retries: int
    :param base_backoff: Base time (in seconds) for exponential backoff.
    :type base_backoff: float
    """

    def __init__(
        self,
        client_factory: Optional[Callable[[], Awaitable[aiohttp.ClientSession]]] = None,
        region: Optional[Literal["us-east-1", "us-east-2"]] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
        endpoint: Optional[str] = None,
        user_agent: str = "DynamoAsyncClient/0.1.0",
        max_retries: int = 5,
        base_backoff: float = 0.05,
    ):
        self.region = region

        self.endpoint = endpoint or f"https://dynamodb.{region}.amazonaws.com/"

        if not self.endpoint:
            raise ValueError("Either region or endpoint must be provided")

        self.user_agent = user_agent
        self.max_retries = max_retries
        self.base_backoff = base_backoff

        self.client_factory = client_factory
        self.client: aiohttp.ClientSession

        self.client_factory_lock = asyncio.Lock()

        self.credentials: Optional[Tuple[str, str, Optional[str]]] = None

        self.aws_environment: Optional[Literal["ec2", "ecs"]] = None
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.shutdown_event = threading.Event()
        self.refresh_thread: Optional[threading.Thread] = None

        if self.access_key and self.secret_key:
            logging.debug("Using defined AWS access_key and secret_key")
        else:
            self.credential_search()

    def start_refresh_thread(self, target: Callable[[], None]) -> None:
        if self.refresh_thread and self.refresh_thread.is_alive():
            return

        self.shutdown_event.clear()
        self.refresh_thread = threading.Thread(target=target, daemon=True)
        self.refresh_thread.start()

    def stop_refresh_thread(self):
        if self.refresh_thread and self.refresh_thread.is_alive():
            self.shutdown_event.set()
            self.refresh_thread.join()

    def credential_search(self):
        """
        Attempt to find AWS credentials from the environment or ECS/EC2 metadata.

        This is blocking only during initialization to prevent race conditions.

        :raises Exception: If no valid credentials are found.
        """

        if environ.get("AWS_ACCESS_KEY_ID") and environ.get("AWS_SECRET_ACCESS_KEY"):
            self.access_key = environ["AWS_ACCESS_KEY_ID"]
            self.secret_key = environ["AWS_SECRET_ACCESS_KEY"]
            self.session_token = environ.get("AWS_SESSION_TOKEN")
            logging.debug("Using env AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            return

        if environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI"):
            try:
                credentials = ecs.ecs_credentials()
            except Exception as err:
                logging.debug(f"ECS credential error: {err}")
            else:
                if credentials:
                    logging.debug("Using ecs credentials")
                    credentials = json_decoder.decode(credentials).decode()
                    self.access_key = credentials["AccessKeyId"]
                    self.secret_key = credentials["SecretAccessKey"]
                    self.session_token = credentials["Token"]
                    self.expiration = credentials["Expiration"]
                    self.aws_environment = "ecs"
                    self.start_refresh_thread(self.task_refresh_credentials)

                    return

        try:
            credentials = ec2.ec2_credentials()
        except Exception as err:
            logging.debug(f"EC2 credential error: {err}")
        else:
            if credentials:
                logging.debug("Using ec2 credentials")
                credentials = json_decoder.decode(credentials).decode()
                self.access_key = credentials["AccessKeyId"]
                self.secret_key = credentials["SecretAccessKey"]
                self.session_token = credentials["Token"]
                self.expiration = credentials["Expiration"]
                self.aws_environment = "ec2"
                self.start_refresh_thread(self.task_refresh_credentials)

                return
        raise Exception("Could not determine credentials")

    def task_refresh_credentials(self):
        """
        Background thread for refreshing AWS credentials.

        Credentials are refreshed approximately 5 minutes before expiration.
        This thread exits when the `shutdown_event` is triggered.
        """
        if self.aws_environment == "ec2":
            credential_func = ec2.ec2_credentials
        elif self.aws_environment == "ecs":
            credential_func = ecs.ecs_credentials
        else:
            raise NotImplementedError()

        while not self.shutdown_event.is_set():
            if self.expiration:
                refresh_time = (
                    self.expiration - datetime.timedelta(minutes=5)
                ).timestamp()
                now = datetime.datetime.now(datetime.timezone.utc).timestamp()
                remaining_time = max(refresh_time - now, 5)  # Min sleep 5 sec

                while remaining_time > 0 and not self.shutdown_event.is_set():
                    interval = min(remaining_time, 30)  # Sleep in 30-second increments
                    self.shutdown_event.wait(interval)
                    remaining_time -= interval

            try:
                res_body = credential_func()
                credentials = json_decoder.decode(res_body).decode()
                self.access_key = credentials["AccessKeyId"]
                self.secret_key = credentials["SecretAccessKey"]
                self.session_token = credentials["Token"]
                self.expiration = credentials["Expiration"]
            except Exception as e:
                logger.debug(f"Failed to refresh credentials (ec2): {e}")
                # Retry with exponential backoff
                for i in range(5):
                    if self.shutdown_event.is_set():
                        return

                    wait = min(2**i, 60)
                    logger.debug(f"Retrying in {wait} seconds...")
                    if self.shutdown_event.wait(wait):
                        return
                    try:
                        res_body = credential_func()

                        credentials = json_decoder.decode(res_body).decode()
                        self.access_key = credentials["AccessKeyId"]
                        self.secret_key = credentials["SecretAccessKey"]
                        self.session_token = credentials["Token"]
                        self.expiration = credentials["Expiration"]
                        break

                    except Exception as e:
                        logger.debug(f"Retrying failed: {e}")
                else:
                    logger.debug(
                        "Failed to refresh credentials after multiple attempts"
                    )

    async def _request(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Internal method for sending a signed request to DynamoDB.

        Handles signing, retries, and connection management automatically.

        :param target: DynamoDB operation target (e.g., "DynamoDB_20120810.GetItem").
        :type target: str
        :param payload: JSON-serializable payload to send to DynamoDB.
        :type payload: Dict[str, Any]
        :return: Parsed JSON response from DynamoDB.
        :rtype: Dict[str, Any]
        :raises aiohttp.ClientError: Raised if the request fails after maximum retries.
        :raises DynamoDBError: Raised if DynamoDB returns an error response.
        """

        if not hasattr(self, "client"):
            async with self.client_factory_lock:
                if not hasattr(self, "client"):
                    logging.debug("Setting up client")
                    if self.client_factory:
                        logging.debug("User defined client_factory")
                        self.client = await self.client_factory()

                    else:
                        self.client = aiohttp.ClientSession()

                    DYNIO_CLIENTS[id(self)] = self

        if not self.access_key or not self.secret_key:
            raise ValueError("No credentials")

        headers, encoded_payload = await asyncio.to_thread(
            sign_request,
            "POST",
            self.region,  # type: ignore
            target,
            payload,
            encoder=json_encoder.encode,
            access_key=self.access_key,
            secret_key=self.secret_key,
            session_token=self.session_token,
        )

        headers["User-Agent"] = self.user_agent

        retries = 1

        while True:
            try:
                response = await self.client.post(
                    self.endpoint,
                    data=encoded_payload,
                    headers=headers,
                )
                json_response = await response.json(loads=json_decoder.decode)

                if response.status == 200:
                    return json_response

                error_code = json_response.get("__type", "")
                if error_code in (
                    "ProvisionedThroughputExceededException",
                    "ThrottlingException",
                    "RequestLimitExceeded",
                    "InternalServerError",
                    "TransactionConflictException",
                    "ServiceUnavailable",
                    "NetworkingError",
                    "RequestTimeout",
                ):
                    if retries < self.max_retries:
                        retry_delay = self.base_backoff * (2**retries) + random.uniform(
                            0, 0.1
                        )
                        logger.warning(
                            f"AWS error {error_code} — Retrying in {retry_delay:.2f}s..."
                        )
                        retries += 1
                        await asyncio.sleep(retry_delay)
                        continue
                    raise DynamoDBError(
                        f"AWS error: {error_code} — {json_response.get('message')}"
                    )

                raise DynamoDBError(json_response)

            except aiohttp.ClientError as e:
                if retries < self.max_retries:
                    retry_delay = self.base_backoff * (2**retries) + random.uniform(
                        0, 0.1
                    )
                    logger.warning(
                        f"Request failed — Retrying in {retry_delay:.2f}s... [{e}]"
                    )
                    retries += 1
                    await asyncio.sleep(retry_delay)
                else:
                    logger.error(f"Max retries reached. Failed with error: {e}")
                    raise

    async def get_item(self, payload: Dict[str, Any]):
        """
        Perform a DynamoDB GetItem request.

        :param payload: GetItem request payload.
        :type payload: Dict[str, Any]
        :return: Parsed JSON response from DynamoDB.
        :rtype: Dict[str, Any]
        """
        return await self._request("DynamoDB_20120810.GetItem", payload)

    async def put_item(self, payload: Dict[str, Any]):
        """
        Perform a DynamoDB PutItem request.

        :param payload: PutItem request payload.
        :type payload: Dict[str, Any]
        :return: Parsed JSON response from DynamoDB.
        :rtype: Dict[str, Any]
        """
        return await self._request("DynamoDB_20120810.PutItem", payload)

    async def delete_item(self, payload: Dict[str, Any]):
        """
        Perform a DynamoDB DeleteItem request.

        :param payload: DeleteItem request payload.
        :type payload: Dict[str, Any]
        :return: Parsed JSON response from DynamoDB.
        :rtype: Dict[str, Any]
        """
        return await self._request("DynamoDB_20120810.DeleteItem", payload)
