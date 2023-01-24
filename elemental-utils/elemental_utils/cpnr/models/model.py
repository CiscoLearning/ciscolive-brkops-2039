from elemental_utils.cpnr.query import Request, RequestError


def check_required_params(params, kwa):
    if len(params) > 0:
        if not kwa or not all(k in kwa for k in params):
            raise ValueError(f"missing required parameter; must have all of {', '.join(params)}")


def filter_kwargs(params, kwa):
    if len(params) == 0:
        return None

    new_kwa = {}
    for p in params:
        new_kwa[p] = kwa[p]

    return new_kwa


class Endpoint(object):
    def __init__(self, api):
        self.api = None
        self.key = None
        self.url = None
        self.required_params = []

    def get(self, *args, **kwargs):
        check_required_params(self.required_params, kwargs)

        try:
            key = args[0]
        except IndexError:
            key = None

        if not key:
            filter_lookup = self.filter(**kwargs)
            if filter_lookup:
                if len(filter_lookup) > 1:
                    raise ValueError("Query returned more than one result.  Use a tighter filter or use filter() or all()")
                else:
                    return filter_lookup[0]

            return None

        req = Request(
            base=self.url + f"/{key}",
            filters=kwargs,
            authorization=(self.api.username, self.api.password),
            http_session=self.api.http_session,
        )

        try:
            resp = req.get()
        except RequestError as e:
            if e.req.status_code == 404:
                return None
            else:
                raise e

        return Record(resp[0], type(self), self.api, filter_kwargs(self.required_params, kwargs))

    def all(self, **kwargs):
        check_required_params(self.required_params, kwargs)

        req = Request(
            base=self.url, filters=kwargs, authorization=(self.api.username, self.api.password), http_session=self.api.http_session
        )

        return [Record(i, type(self), self.api, filter_kwargs(self.required_params, kwargs)) for i in req.get()]

    def filter(self, *args, **kwargs):
        check_required_params(self.required_params, kwargs)

        if args:
            kwargs.update({self.key: args[0]})

        if not kwargs:
            raise ValueError("filter must be passed kwargs.  Perhaps use all() instead.")

        req = Request(
            filters=kwargs, base=self.url, authorization=(self.api.username, self.api.password), http_session=self.api.http_session
        )

        return [Record(i, type(self), self.api, filter_kwargs(self.required_params, kwargs)) for i in req.get()]

    def add(self, **kwargs):
        check_required_params(self.required_params, kwargs)

        if not kwargs or self.key not in kwargs:
            raise ValueError("a key value must be specified to add a new object")

        req = Request(base=self.url, authorization=(self.api.username, self.api.password), http_session=self.api.http_session)
        req.post(kwargs)

        return self.get(kwargs[self.key], **{k: kwargs[k] for k in self.required_params})

    def update(self, *args, **kwargs):
        check_required_params(self.required_params, kwargs)

        if not args:
            raise ValueError("a key value must be specified to update an object")

        req = Request(
            base=self.url + f"/{args[0]}", authorization=(self.api.username, self.api.password), http_session=self.api.http_session
        )
        req.put(kwargs)

        return self.get(args[0], **{k: kwargs[k] for k in self.required_params})

    def delete(self, *args, **kwargs):
        check_required_params(self.required_params, kwargs)

        if not args:
            raise ValueError("a key value must be specified to delete an object")

        req = Request(
            base=self.url + f"/{args[0]}",
            authorization=(self.api.username, self.api.password),
            http_session=self.api.http_session,
            filters=kwargs,
        )
        resp = req.delete()

        return resp


class Record(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, item, klass, api, params):
        self.update(item)
        self.__ref = klass
        self.__api = api
        if params:
            self.update(params)

    def save(self):
        o = self.__ref(self.__api)
        return o.update(self[o.key], **{k: v for k, v in self.items() if (k != "_Record__ref" and k != "_Record__api")})

    def delete(self):
        o = self.__ref(self.__api)
        return o.delete(self[o.key], **{k: v for k, v in self.items() if (k != "_Record__ref" and k != "_Record__api")})
