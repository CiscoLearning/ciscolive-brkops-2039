from . import Endpoint


class RZone(Endpoint):
    def __init__(self, api):
        self.api = api
        self.url = self.api.base_url + "web-services/rest/resource/CCMReverseZone"
        self.key = "origin"
        self.required_params = []
