# -*- coding: utf-8 -*-
import zerorpc
from .middleware import ClientMiddleware, TracerMiddleware, ResolverMiddleware


class ZeroRPClient:
    location = "tcp://127.0.0.1:4242"

    def __init__(self, location=None, timeout=10):
        if not location:
            location = self.location
        ctx = zerorpc.Context()
        client = ClientMiddleware()
        ctx.register_middleware(client)
        resolver = ResolverMiddleware()
        ctx.register_middleware(resolver)
        tracer = TracerMiddleware('[client]')
        ctx.register_middleware(tracer)
        self.client = zerorpc.Client(timeout=timeout, context=ctx)
        self.client.connect(location)

    def close(self):
        return self.client.close()