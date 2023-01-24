import json
import requests
from typing import Tuple, Union


class RequestError(Exception):
    def __init__(self, message: str):
        req = message

        message = f"The request failed with code {req.status_code} {req.reason}: {req.text}"

        super().__init__(message)
        self.req = req
        self.request_body = req.request.body
        self.base = req.url
        self.error = req.text


class ContentError(Exception):
    def __init__(self, message: str):
        req = message

        message = "The server returned invalid (non-json) data. Maybe not a FreeNAS server?"

        super().__init__(message)
        self.req = req
        self.request_body = req.request.body
        self.base = req.url
        self.error = message


class Request(object):
    def __init__(self, base: str, http_session: requests.Session, authorization: Tuple[str, str], filters: dict = None):
        self.filters = filters
        self.authorization = authorization
        self.url = base
        self.http_session = http_session

    def _make_call(self, verb: str = "get", url_override: str = None, add_params: dict = None, data: dict = None) -> Union[bool, list]:
        if verb in ("post", "put"):
            headers = {"Content-Type": "application/json"}
        else:
            headers = {"Accept": "application/json"}

        params = {}
        if not url_override:
            if self.filters:
                params.update(self.filters)
            if add_params:
                params.update(add_params)

        req = getattr(self.http_session, verb)(
            url_override or self.url, auth=self.authorization, headers=headers, params=params, json=data, verify=False
        )

        if verb == "delete":
            if req.ok:
                return True
            else:
                raise RequestError(req)
        elif req.ok:
            if verb == "put":
                return True
            try:
                j = req.json()
                if isinstance(j, list):
                    return j
                return [j]
            except json.JSONDecodeError:
                if verb == "post":
                    return True

                raise ContentError(req)
        else:
            if req.status_code == 404 and verb == "get":
                return None

            raise RequestError(req)

    def get(self, add_params: dict = None) -> list:
        def req_all():
            url_override = None

            req = self._make_call(url_override=url_override, add_params=add_params)
            return req

        return req_all()

    def put(self, data: dict) -> bool:
        return self._make_call(verb="put", data=data)

    def post(self, data: dict) -> Union[bool, dict]:
        return self._make_call(verb="post", data=data)

    def delete(self) -> bool:
        return self._make_call(verb="delete")
