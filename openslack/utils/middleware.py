# -*- coding: utf-8 -*-
"""
rpc中间件，可以监控rpc的一些状态或者做一些tracelog记录
"""
import random, hashlib, gevent


class ClientMiddleware:
    def __init__(self):
        self.called = True

    def client_before_request(self, event):
        self.method = event.name

    def client_after_request(self, req_event, rep_event, exception):
        pass
        # assert req_event is not None
        # assert req_event.name == "crash" or req_event.name == "echoes_crash"
        # self.called = True
        # assert isinstance(exception, zerorpc.RemoteError)
        # assert exception.name == 'RuntimeError'
        # assert 'BrokenEchoModule' in exception.msg
        # assert rep_event.name == 'ERR'

    def client_handle_remote_error(self, event):
        pass

    def client_patterns_list(self, patterns):
        pass


class ResolverMiddleware:
    def resolve_endpoint(self, endpoint):
        if endpoint == 'toto':
            return endpoint
        return endpoint


class TracerMiddleware:
    '''Used by test_task_context_* tests'''

    def __init__(self, identity):
        self._identity = identity
        self._locals = gevent.local.local()
        self._log = []

    @property
    def trace_id(self):
        return self._locals.__dict__.get('trace_id', None)

    def load_task_context(self, event_header):
        self._locals.trace_id = event_header.get('trace_id', None)
        print self._identity, 'load_task_context', self.trace_id
        self._log.append(('load', self.trace_id))

    def get_task_context(self):
        if self.trace_id is None:
            # just an ugly code to generate a beautiful little hash.
            self._locals.trace_id = '<{0}>'.format(hashlib.md5(
                str(random.random())[3:]
            ).hexdigest()[0:6].upper())
            print self._identity, 'get_task_context! [make a new one]', self.trace_id
            self._log.append(('new', self.trace_id))
        else:
            print self._identity, 'get_task_context! [reuse]', self.trace_id
            self._log.append(('reuse', self.trace_id))
        return {'trace_id': self.trace_id}

