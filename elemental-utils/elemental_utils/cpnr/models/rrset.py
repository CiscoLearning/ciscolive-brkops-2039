from . import Endpoint


class RRSet(Endpoint):
    def __init__(self, api):
        self.api = api
        self.url = self.api.base_url + "web-services/rest/resource/CCMRRSet"
        self.key = "name"
        self.required_params = ["zoneOrigin"]
