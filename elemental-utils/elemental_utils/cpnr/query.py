import json
import requests


class RequestError(Exception):
    def __init__(self, message):
        req = message

        message = f"The request failed with code {req.status_code} {req.reason}: {req.text}"

        super().__init__(message)
        self.req = req
        self.request_body = req.request.body
        self.base = req.url
        self.error = req.text


class ContentError(Exception):
    def __init__(self, message):
        req = message

        message = "The server returned invalid (non-json) data. Maybe not a CPNR server?"

        super().__init__(message)
        self.req = req
        self.request_body = req.request.body
        self.base = req.url
        self.error = message


class Request(object):
    def __init__(self, base, http_session, authorization, filters=None):
        self.filters = filters
        self.authorization = authorization
        self.links = None
        self.url = base
        self.http_session = http_session

    def _make_call(self, verb="get", url_override=None, add_params=None, data=None):
        is_action = False

        if verb in ("post", "put"):
            headers = {"Content-Type": "application/json"}
        else:
            headers = {"Accept": "application/json"}

        if verb == "action":
            is_action = True
            verb = "put"

        params = {}
        if not url_override:
            if self.filters:
                params.update(self.filters)
            if add_params:
                params.update(add_params)

        req = getattr(self.http_session, verb)(
            url_override or self.url, auth=self.authorization, headers=headers, params=params, json=data, verify=False
        )
        if "Link" in req.headers:
            self.links = requests.utils.parse_header_links(req.headers["Link"])
        else:
            self.links = None

        if req.status_code == 201 and verb == "post":
            return True
        if verb == "delete":
            if req.ok:
                return True
            else:
                raise RequestError(req)
        if is_action:
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
                raise ContentError(req)
        else:
            raise RequestError(req)

    def get(self, add_params=None):
        def req_all():
            ret = []
            more_pages = True
            url_override = None

            while more_pages:
                req = self._make_call(url_override=url_override, add_params=add_params)
                ret.extend(req)
                found_next = False
                if self.links:
                    for link in self.links:
                        if link["rel"] == "next":
                            url_override = link["url"]
                            found_next = True
                            break

                    if found_next:
                        continue

                    more_pages = False
                else:
                    more_pages = False

            return ret

        return req_all()

    def put(self, data):
        return self._make_call(verb="put", data=data)

    def post(self, data):
        return self._make_call(verb="post", data=data)

    def delete(self):
        return self._make_call(verb="delete")

    def action(self, instance=None, add_params=None):
        if instance:
            self.url += f"/{instance}"

        return self._make_call(verb="action", add_params=add_params)
