from . import Endpoint


class Exception(Endpoint):
    def __init__(self, api):
        self.api = api
        self.url = self.api.base_url + "web-services/rest/resource/DnsException"
        self.key = "name"
        self.required_params = []
