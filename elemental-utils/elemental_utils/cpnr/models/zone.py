from . import Endpoint


class Zone(Endpoint):
    def __init__(self, api):
        self.api = api
        self.url = self.api.base_url + "web-services/rest/resource/CCMZone"
        self.key = "origin"
        self.required_params = []
