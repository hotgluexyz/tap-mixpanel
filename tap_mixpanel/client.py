import base64
import io
from typing import Union, Dict, Any, Tuple
import backoff
import jsonlines
import requests
from requests.exceptions import ConnectionError, HTTPError
from singer import metrics
import singer
from enum import Enum
from .utils import get_export_host, get_standard_host

LOGGER = singer.get_logger()

BACKOFF_MAX_TRIES_REQUEST = 7


class API_TYPES(Enum):
    QUERY = "query"
    EXPORT = "export"
    
class ReadTimeoutError(Exception):
    pass


class Server5xxError(Exception):
    pass


class MixpanelError(Exception):
    pass


class MixpanelRateLimitsError(MixpanelError):
    pass


class MixpanelBadRequestError(MixpanelError):
    pass


class MixpanelUnauthorizedError(MixpanelError):
    pass


class MixpanelRequestFailedError(MixpanelError):
    pass


class MixpanelNotFoundError(MixpanelError):
    pass


class MixpanelForbiddenError(MixpanelError):
    pass


class MixpanelInternalServiceError(MixpanelError):
    pass



ERROR_CODE_EXCEPTION_MAPPING = {
    400: MixpanelBadRequestError,
    401: MixpanelUnauthorizedError,
    402: MixpanelRequestFailedError,
    403: MixpanelForbiddenError,
    404: MixpanelNotFoundError,
    429: MixpanelRateLimitsError,
    500: MixpanelInternalServiceError}


def get_exception_for_error_code(error_code):
    return ERROR_CODE_EXCEPTION_MAPPING.get(error_code, MixpanelError)

def raise_for_error(response):
    if response.status_code != 400:
        LOGGER.warn('STATUS {}: {}, REASON: {}'.format(response.status_code,
            response.text, response.reason))

    try:
        response.raise_for_status()
    except (requests.HTTPError, requests.ConnectionError) as error:
        try:
            content_length = len(response.content)
            if content_length == 0:
                # There is nothing we can do here since Mixpanel has neither sent
                # us a 2xx response nor a response content.
                return
            response = response.json()
            if ('error' in response) or ('errorCode' in response):
                message = '%s: %s' % (response.get('error', str(error)),
                                      response.get('message', 'Unknown Error'))
                error_code = response.get('status')
                ex = get_exception_for_error_code(error_code)
                raise ex(message)
            else:
                raise MixpanelError(error)
        except (ValueError, TypeError):
            raise MixpanelError(error)


class MixpanelClient(object):

    def __init__(self,
                 api_secret,
                 username,
                 password,
                 project_id,
                 user_agent=None,
                 service_account_name=None,
                 service_account_secret=None,
                 data_region=None):
        self.__api_secret = api_secret
        self.username = username
        self.password = password
        self.__user_agent = user_agent
        self.__session = requests.Session()
        self.__verified = False
        self.disable_engage_endpoint = False
        self.project_id = project_id
        self.service_account_name = service_account_name
        self.service_account_secret = service_account_secret
        self.data_region = data_region

    def __enter__(self):
        self.__verified = self.check_access()
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.__session.close()

    @property
    def has_basic_auth(self):
        return bool(self.username and self.password)

    @property
    def has_service_account(self):
        return bool(self.service_account_name and self.service_account_secret)

    @property
    def has_secret(self):
        return bool(self.__api_secret)
    
    def _apply_auth_and_project(
        self,
        params: Union[Dict[str, Any], str, None],
        kwargs: Dict[str, Any]
    ) -> Tuple[Union[Dict[str, Any], str], Dict[str, Any]]:
        
        # initialize headers/auth if missing
        kwargs.setdefault('headers', {})

        # 1) Service Account / Basic Auth
        if self.has_service_account or self.has_basic_auth:
            # inject project_id
            if params is None:
                params = {}
            if isinstance(params, dict):
                params['project_id'] = self.project_id
            elif isinstance(params, str):
                # Fix: Ensure we don't add double question marks
                if not params:
                    params = f"project_id={self.project_id}"
                elif '?' in params:
                    params = f"{params}&project_id={self.project_id}"
                else:
                    params = f"{params}&project_id={self.project_id}"

            # set auth tuple - prioritize service account over basic auth
            if self.has_service_account:
                kwargs['auth'] = (self.service_account_name, self.service_account_secret)
            else:
                kwargs['auth'] = (self.username, self.password)

        # 2) API Secret
        else:
            token = base64.urlsafe_b64encode(
                self.__api_secret.encode('utf-8')
            ).decode('utf-8')
            kwargs['headers']['Authorization'] = f"Basic {token}"

        return params, kwargs
    
    @backoff.on_exception(
        backoff.expo,
        (Server5xxError, MixpanelRateLimitsError, ReadTimeoutError, ConnectionError),
        max_tries=5,
        factor=2
    )
    def check_access(self):
        """
        Verify Mixpanel API access using one of:
        - Service account (name/secret) - prioritized if available
        - Basic auth (username/password)
        - API secret (base64)
        Raises if no credentials or on non-200 errors (except 402).
        """
        # Determine auth mode

        if not (self.has_service_account or self.has_basic_auth or self.has_secret):
            raise Exception("Error: Missing credentials (service account, username/password, or api_secret) in tap config.json.")

        # Choose endpoint
        base_url = self._get_base_url(API_TYPES.QUERY)
        url = base_url + "/app/me" if (self.has_service_account or self.has_basic_auth) else base_url + "/2.0/engage"
        LOGGER.info(f"Checking access by calling {url}")

        # Build headers
        headers = {"Accept": "application/json"}
        if self.__user_agent:
            headers["User-Agent"] = self.__user_agent

        # If using API secret (and not service_account/basic), set Authorization header
        auth = None
        if self.has_service_account:
            auth = (self.service_account_name, self.service_account_secret)
        elif self.has_basic_auth:
            auth = (self.username, self.password)
        else:  # using API secret
            token = base64.urlsafe_b64encode(self.__api_secret.encode()).decode()
            headers["Authorization"] = f"Basic {token}"

        # Perform request with timeout to catch slow responses
        try:
            response = self.__session.get(url, headers=headers, auth=auth, timeout=30)
        except TimeoutError as err:
            LOGGER.error(f"TIMEOUT ERROR: {err}")
            raise ReadTimeoutError
        except requests.exceptions.RequestException as err:
            # let backoff decorator handle retries for connection errors, etc.
            LOGGER.error(f"REQUEST ERROR: {err}")
            raise

        # Handle Mixpanel's "Payment Required" special case
        if response.status_code == 402:
            self.disable_engage_endpoint = True
            LOGGER.warning("Mixpanel returned 402 from Engage API; skipping Engage stream.")
            return True

        # Any non-200 (other than 402) is an error
        if response.status_code != 200:
            LOGGER.error(f"Error status_code = {response.status_code}")
            raise_for_error(response)

        return True


    @backoff.on_exception(
        backoff.expo,
        (MixpanelRateLimitsError, Server5xxError, ReadTimeoutError, ConnectionError, HTTPError),
        max_tries=BACKOFF_MAX_TRIES_REQUEST,
        factor=3, 
        logger=LOGGER)
    def perform_request(self,
                        method,
                        url=None,
                        params=None,
                        json=None,
                        stream=False,
                        **kwargs):
        try:
            response = self.__session.request(method=method,
                                          url=url,
                                          params=params,
                                          json=json,
                                          stream=stream,
                                          **kwargs)

            if response.status_code >= 500:
                raise Server5xxError(response.text)

            if response.status_code != 200:
                raise_for_error(response)
            return response
        except requests.exceptions.Timeout as err:
            LOGGER.error('TIMEOUT ERROR: {}'.format(err))
            raise ReadTimeoutError(err)


    def request(self, method, url=None, path=None, params=None, json=None, **kwargs):
        if not self.__verified:
            self.__verified = self.check_access()

        url = '{}/2.0/{}'.format(self._get_base_url(API_TYPES.QUERY), path)

        if 'endpoint' in kwargs:
            endpoint = kwargs['endpoint']
            del kwargs['endpoint']
        else:
            endpoint = None

        if 'headers' not in kwargs:
            kwargs['headers'] = {}

        kwargs['headers']['Accept'] = 'application/json'

        if self.__user_agent:
            kwargs['headers']['User-Agent'] = self.__user_agent

        if method == 'POST':
            kwargs['headers']['Content-Type'] = 'application/json'
            
        # Apply authentication and project ID
        params, kwargs = self._apply_auth_and_project(params, kwargs)

        with metrics.http_request_timer(endpoint) as timer:
            response = self.perform_request(method=method,
                                            url=url,
                                            params=params,
                                            json=json,
                                            **kwargs)

            timer.tags[metrics.Tag.http_status_code] = response.status_code

        response_json = response.json()
        return response_json


    def request_export(self, method, url=None, path=None, params=None, json=None, **kwargs):
        if not self.__verified:
            self.__verified = self.check_access()

        url = '{}/2.0/{}'.format(self._get_base_url(API_TYPES.EXPORT), path)

        if 'endpoint' in kwargs:
            endpoint = kwargs['endpoint']
            del kwargs['endpoint']
        else:
            endpoint = 'export'

        if 'headers' not in kwargs:
            kwargs['headers'] = {}

        kwargs['headers']['Accept'] = 'application/json'

        if self.__user_agent:
            kwargs['headers']['User-Agent'] = self.__user_agent

        if method == 'POST':
            kwargs['headers']['Content-Type'] = 'application/json'

        # Apply authentication and project ID
        params, kwargs = self._apply_auth_and_project(params, kwargs)

        with metrics.http_request_timer(endpoint) as timer:
            response = self.perform_request(method=method,
                                        url=url,
                                        params=params,
                                        json=json,
                                        stream=True,
                                        **kwargs)
            timer.tags[metrics.Tag.http_status_code] = response.status_code

            # export endpoint returns jsonl results;
            #  other endpoints return json with array of results
            #  jsonlines reference: https://jsonlines.readthedocs.io/en/latest/
            reader = jsonlines.Reader(response.iter_lines())
            for record in reader.iter(allow_none=True, skip_empty=True):
                yield record

    def _get_base_url(self, api_type: API_TYPES) -> str:
        region = (self.data_region or 'default').lower()
        
        if api_type == API_TYPES.EXPORT:
            return get_export_host(region)
        return get_standard_host(region)

