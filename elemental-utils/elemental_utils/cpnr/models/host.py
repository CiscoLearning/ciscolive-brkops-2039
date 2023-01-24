from . import Endpoint


class Host(Endpoint):
    def __init__(self, api):
        self.api = api
        self.url = self.api.base_url + "web-services/rest/resource/CCMHost"
        self.key = "name"
        self.required_params = ["zoneOrigin"]
