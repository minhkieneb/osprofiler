# Copyright 2014 Mirantis Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from unittest import mock

from webob import response as webob_response

from osprofiler import _utils as utils
from osprofiler import profiler
from osprofiler.tests import test
from osprofiler import web


def dummy_app(environ, response):
    res = webob_response.Response()
    return res(environ, response)


class WebTestCase(test.TestCase):
    def setUp(self):
        super().setUp()
        profiler.clean()
        self.addCleanup(profiler.clean)

    def test_get_trace_id_headers_no_hmac(self):
        profiler.init(None, base_id="y", parent_id="z")  # type: ignore[arg-type]
        headers = web.get_trace_id_headers()
        self.assertEqual(headers, {})

    def test_get_trace_id_headers(self):
        profiler.init("key", base_id="y", parent_id="z")
        headers = web.get_trace_id_headers()
        self.assertEqual(
            sorted(headers.keys()), sorted(["X-Trace-Info", "X-Trace-HMAC"])
        )

        trace_info = utils.signed_unpack(
            headers["X-Trace-Info"], headers["X-Trace-HMAC"], ["key"]
        )
        assert trace_info is not None  # noqa: S101
        self.assertIn("hmac_key", trace_info)
        self.assertEqual("key", trace_info.pop("hmac_key"))
        self.assertEqual({"parent_id": "z", "base_id": "y"}, trace_info)

    @mock.patch("osprofiler.profiler.get")
    def test_get_trace_id_headers_no_profiler(self, mock_get_profiler):
        mock_get_profiler.return_value = False
        headers = web.get_trace_id_headers()
        self.assertEqual(headers, {})


class WebMiddlewareTestCase(test.TestCase):
    def setUp(self):
        super().setUp()
        profiler.clean()
        # it's default state of _ENABLED param, so let's set it here
        web._ENABLED = None
        web._ALWAYS_TRACE = None
        web._TRACE_SAMPLE_RATE = None
        self.addCleanup(profiler.clean)

    def tearDown(self):
        web.enable()
        super().tearDown()

    def test_factory(self):
        mock_app = mock.MagicMock()
        local_conf = {"enabled": True, "hmac_keys": "123"}

        factory = web.WsgiMiddleware.factory(None, **local_conf)
        wsgi = factory(mock_app)

        self.assertEqual(wsgi.application, mock_app)
        self.assertEqual(wsgi.name, "wsgi")
        self.assertTrue(wsgi.enabled)
        self.assertEqual(wsgi.hmac_keys, [local_conf["hmac_keys"]])

    def _test_wsgi_middleware_with_invalid_trace(
        self, headers, hmac_key, mock_profiler_init, enabled=True
    ):
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.headers = headers

        middleware = web.WsgiMiddleware(mock.ANY, hmac_key, enabled=enabled)
        self.assertEqual("yeah!", middleware(request))
        request.get_response.assert_called_once_with(mock.ANY)
        mock_profiler_init.assert_not_called()

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_disabled(self, mock_profiler_init):
        hmac_key = "secret"
        pack = utils.signed_pack({"base_id": "1", "parent_id": "2"}, hmac_key)
        headers = {
            "a": "1",
            "b": "2",
            "X-Trace-Info": pack[0],
            "X-Trace-HMAC": pack[1],
        }

        self._test_wsgi_middleware_with_invalid_trace(
            headers, hmac_key, mock_profiler_init, enabled=False
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_no_trace(self, mock_profiler_init):
        headers = {"a": "1", "b": "2"}
        self._test_wsgi_middleware_with_invalid_trace(
            headers, "secret", mock_profiler_init
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_invalid_trace_headers(self, mock_profiler_init):
        headers = {
            "a": "1",
            "b": "2",
            "X-Trace-Info": "abbababababa",
            "X-Trace-HMAC": "abbababababa",
        }
        self._test_wsgi_middleware_with_invalid_trace(
            headers, "secret", mock_profiler_init
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_no_trace_hmac(self, mock_profiler_init):
        hmac_key = "secret"
        pack = utils.signed_pack({"base_id": "1", "parent_id": "2"}, hmac_key)
        headers = {"a": "1", "b": "2", "X-Trace-Info": pack[0]}
        self._test_wsgi_middleware_with_invalid_trace(
            headers, hmac_key, mock_profiler_init
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_invalid_hmac(self, mock_profiler_init):
        hmac_key = "secret"
        pack = utils.signed_pack({"base_id": "1", "parent_id": "2"}, hmac_key)
        headers = {
            "a": "1",
            "b": "2",
            "X-Trace-Info": pack[0],
            "X-Trace-HMAC": "not valid hmac",
        }
        self._test_wsgi_middleware_with_invalid_trace(
            headers, hmac_key, mock_profiler_init
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_invalid_trace_info(self, mock_profiler_init):
        hmac_key = "secret"
        pack = utils.signed_pack(
            [{"base_id": "1"}, {"parent_id": "2"}],  # type: ignore[arg-type]
            hmac_key,
        )
        headers = {
            "a": "1",
            "b": "2",
            "X-Trace-Info": pack[0],
            "X-Trace-HMAC": pack[1],
        }
        self._test_wsgi_middleware_with_invalid_trace(
            headers, hmac_key, mock_profiler_init
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_key_passthrough(self, mock_profiler_init):
        hmac_key = "secret2"
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.url = "someurl"
        request.host_url = "someurl"
        request.path = "path"
        request.query_string = "query"
        request.method = "method"
        request.scheme = "scheme"

        pack = utils.signed_pack({"base_id": "1", "parent_id": "2"}, hmac_key)

        request.headers = {
            "a": "1",
            "b": "2",
            "X-Trace-Info": pack[0],
            "X-Trace-HMAC": pack[1],
        }

        middleware = web.WsgiMiddleware(
            mock.ANY, f"secret1,{hmac_key}", enabled=True
        )
        self.assertEqual("yeah!", middleware(request))
        mock_profiler_init.assert_called_once_with(
            hmac_key=hmac_key, base_id="1", parent_id="2"
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_key_passthrough2(self, mock_profiler_init):
        hmac_key = "secret1"
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.url = "someurl"
        request.host_url = "someurl"
        request.path = "path"
        request.query_string = "query"
        request.method = "method"
        request.scheme = "scheme"

        pack = utils.signed_pack({"base_id": "1", "parent_id": "2"}, hmac_key)

        request.headers = {
            "a": "1",
            "b": "2",
            "X-Trace-Info": pack[0],
            "X-Trace-HMAC": pack[1],
        }

        middleware = web.WsgiMiddleware(
            mock.ANY, f"{hmac_key},secret2", enabled=True
        )
        self.assertEqual("yeah!", middleware(request))
        mock_profiler_init.assert_called_once_with(
            hmac_key=hmac_key, base_id="1", parent_id="2"
        )

    @mock.patch("osprofiler.web.profiler.Trace")
    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware(self, mock_profiler_init, mock_profiler_trace):
        hmac_key = "secret"
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.url = "someurl"
        request.host_url = "someurl"
        request.path = "path"
        request.query_string = "query"
        request.method = "method"
        request.scheme = "scheme"

        pack = utils.signed_pack({"base_id": "1", "parent_id": "2"}, hmac_key)

        request.headers = {
            "a": "1",
            "b": "2",
            "X-Trace-Info": pack[0],
            "X-Trace-HMAC": pack[1],
        }

        middleware = web.WsgiMiddleware(mock.ANY, hmac_key, enabled=True)
        self.assertEqual("yeah!", middleware(request))
        mock_profiler_init.assert_called_once_with(
            hmac_key=hmac_key, base_id="1", parent_id="2"
        )
        expected_info = {
            "request": {
                "path": request.path,
                "query": request.query_string,
                "method": request.method,
                "scheme": request.scheme,
            }
        }
        mock_profiler_trace.assert_called_once_with("wsgi", info=expected_info)

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_disable_via_python(self, mock_profiler_init):
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        web.disable()
        middleware = web.WsgiMiddleware(mock.ANY, "hmac_key", enabled=True)
        self.assertEqual("yeah!", middleware(request))
        mock_profiler_init.assert_not_called()

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_enable_via_python(self, mock_profiler_init):
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.url = "someurl"
        request.host_url = "someurl"
        request.path = "path"
        request.query_string = "query"
        request.method = "method"
        request.scheme = "scheme"
        hmac_key = "super_secret_key2"

        pack = utils.signed_pack({"base_id": "1", "parent_id": "2"}, hmac_key)
        request.headers = {
            "a": "1",
            "b": "2",
            "X-Trace-Info": pack[0],
            "X-Trace-HMAC": pack[1],
        }

        web.enable("super_secret_key1,super_secret_key2")
        middleware = web.WsgiMiddleware(mock.ANY, enabled=True)
        self.assertEqual("yeah!", middleware(request))
        mock_profiler_init.assert_called_once_with(
            hmac_key=hmac_key, base_id="1", parent_id="2"
        )

    @mock.patch("osprofiler.web.profiler.Trace")
    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_always_trace_no_headers(
        self, mock_profiler_init, mock_profiler_trace
    ):
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.path = "/v2.1/servers"
        request.query_string = ""
        request.method = "GET"
        request.scheme = "http"
        request.headers = {"a": "1"}

        web.enable("my_secret_key", always_trace=True)
        middleware = web.WsgiMiddleware(mock.ANY, enabled=True)
        self.assertEqual("yeah!", middleware(request))

        mock_profiler_init.assert_called_once()
        call_kwargs = mock_profiler_init.call_args[1]
        self.assertEqual("my_secret_key", call_kwargs["hmac_key"])
        self.assertIsNotNone(call_kwargs["base_id"])
        self.assertIsNone(call_kwargs["parent_id"])

        mock_profiler_trace.assert_called_once_with(
            "wsgi",
            info={
                "request": {
                    "path": "/v2.1/servers",
                    "query": "",
                    "method": "GET",
                    "scheme": "http",
                }
            },
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_always_trace_kube_probe(self, mock_profiler_init):
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.headers = {"User-Agent": "kube-probe/1.28"}

        middleware = web.WsgiMiddleware(
            mock.ANY,
            hmac_keys="key1",
            enabled=True,
            always_trace=True,
        )
        self.assertEqual("yeah!", middleware(request))
        mock_profiler_init.assert_not_called()

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_always_trace_w3c_traceparent(
        self, mock_profiler_init
    ):
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.path = "/v2.1/servers"
        request.query_string = ""
        request.method = "GET"
        request.scheme = "http"
        request.headers = {
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        }

        middleware = web.WsgiMiddleware(
            mock.ANY,
            hmac_keys="key1",
            enabled=True,
            always_trace=True,
        )
        self.assertEqual("yeah!", middleware(request))

        mock_profiler_init.assert_called_once_with(
            hmac_key="key1",
            base_id="4bf92f3577b34da6a3ce929d0e0e4736",
            parent_id="000000000000000000f067aa0ba902b7",
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_always_trace_via_init(self, mock_profiler_init):
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.path = "/v2.1/servers"
        request.query_string = ""
        request.method = "GET"
        request.scheme = "http"
        request.headers = {}

        middleware = web.WsgiMiddleware(
            mock.ANY,
            hmac_keys="key1,key2",
            enabled=True,
            always_trace=True,
        )
        self.assertEqual("yeah!", middleware(request))

        mock_profiler_init.assert_called_once()
        call_kwargs = mock_profiler_init.call_args[1]
        self.assertEqual("key1", call_kwargs["hmac_key"])
        self.assertIsNotNone(call_kwargs["base_id"])
        self.assertIsNone(call_kwargs["parent_id"])

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_always_trace_invalid_headers(
        self, mock_profiler_init
    ):
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.path = "/path"
        request.query_string = ""
        request.method = "GET"
        request.scheme = "http"
        request.headers = {
            "X-Trace-Info": "invalid-info",
            "X-Trace-HMAC": "invalid-hmac",
        }

        middleware = web.WsgiMiddleware(
            mock.ANY,
            hmac_keys="default_key",
            enabled=True,
            always_trace=True,
        )
        self.assertEqual("yeah!", middleware(request))

        mock_profiler_init.assert_called_once()
        call_kwargs = mock_profiler_init.call_args[1]
        self.assertEqual("default_key", call_kwargs["hmac_key"])
        self.assertIsNotNone(call_kwargs["base_id"])
        self.assertIsNone(call_kwargs["parent_id"])

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_always_trace_preserves_valid_trace(
        self, mock_profiler_init
    ):
        hmac_key = "secret_key"
        pack = utils.signed_pack(
            {"base_id": "root-123", "parent_id": "span-456"}, hmac_key
        )
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.path = "/path"
        request.query_string = ""
        request.method = "GET"
        request.scheme = "http"
        request.headers = {
            "X-Trace-Info": pack[0],
            "X-Trace-HMAC": pack[1],
        }

        middleware = web.WsgiMiddleware(
            mock.ANY,
            hmac_keys=hmac_key,
            enabled=True,
            always_trace=True,
        )
        self.assertEqual("yeah!", middleware(request))

        mock_profiler_init.assert_called_once_with(
            hmac_key=hmac_key, base_id="root-123", parent_id="span-456"
        )

    @mock.patch("osprofiler.web.profiler.init")
    def test_wsgi_middleware_always_trace_sampling_zero(
        self, mock_profiler_init
    ):
        request = mock.MagicMock()
        request.get_response.return_value = "yeah!"
        request.headers = {}

        middleware = web.WsgiMiddleware(
            mock.ANY,
            hmac_keys="key1",
            enabled=True,
            always_trace=True,
            trace_sample_rate=0.0,
        )
        self.assertEqual("yeah!", middleware(request))
        mock_profiler_init.assert_not_called()

    def test_disable(self):
        web.enable(always_trace=True, trace_sample_rate=0.5)
        web.disable()
        self.assertFalse(web._ENABLED)
        self.assertFalse(web._ALWAYS_TRACE)
        self.assertEqual(1.0, web._TRACE_SAMPLE_RATE)

    def test_enabled(self):
        web.disable()
        web.enable()
        self.assertTrue(web._ENABLED)
