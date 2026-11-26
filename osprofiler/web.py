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

from __future__ import annotations

import random
import re
from typing import Any, TypeGuard, TYPE_CHECKING

from oslo_utils import strutils
from oslo_utils import uuidutils
import webob.dec

from osprofiler import _utils as utils
from osprofiler import profiler

if TYPE_CHECKING:
    from _typeshed.wsgi import WSGIApplication


# Trace keys that are required or optional, any other
# keys that are present will cause the trace to be rejected...
_REQUIRED_KEYS = ("base_id", "hmac_key")
_OPTIONAL_KEYS = ("parent_id",)

#: Http header that will contain the needed traces data.
X_TRACE_INFO = "X-Trace-Info"

#: Http header that will contain the traces data hmac (that will be validated).
X_TRACE_HMAC = "X-Trace-HMAC"

#: W3C Trace Context traceparent header.
W3C_TRACEPARENT = "traceparent"
_W3C_TRACEPARENT_RE = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$"
)


def extract_w3c_context(headers: Any) -> tuple[str | None, str | None]:
    """Extract trace_id and parent_id from W3C traceparent header.

    :param headers: Request headers mapping
    :returns: Tuple of (trace_id, parent_id) or (None, None)
    """
    traceparent = headers.get(W3C_TRACEPARENT) or headers.get("Traceparent")
    if not traceparent:
        return None, None
    match = _W3C_TRACEPARENT_RE.match(traceparent.strip().lower())
    if match:
        version, trace_id, parent_id, flags = match.groups()
        if version != "ff":
            return trace_id, parent_id
    return None, None


def generate_traceparent(
    trace_id: str | None = None,
    parent_id: str | None = None,
    sampled: bool = True,
) -> str:
    """Generate W3C traceparent header."""
    if trace_id is None:
        t_id = uuidutils.generate_uuid(dashed=False)
    else:
        t_id = trace_id.replace("-", "").zfill(32)[-32:]
    if parent_id is None:
        p_id = uuidutils.generate_uuid(dashed=False)[:16]
    else:
        p_id = format(utils.shorten_id(parent_id), "016x")
    flags = "01" if sampled else "00"
    return f"00-{t_id}-{p_id}-{flags}"


def get_trace_id_headers() -> dict[str, str]:
    """Adds trace id headers (HMAC and W3C traceparent) into returned dict."""
    p = profiler.get()
    if p and p.hmac_key:
        headers: dict[str, str] = {}
        # W3C traceparent header for OpenTelemetry compatibility
        base_id = p.get_base_id().replace("-", "")
        current_id = p.get_id()
        span_id = format(utils.shorten_id(current_id), "016x")
        headers[W3C_TRACEPARENT] = generate_traceparent(base_id, span_id)

        data = {"base_id": p.get_base_id(), "parent_id": p.get_id()}
        pack = utils.signed_pack(data, p.hmac_key)
        headers[X_TRACE_INFO] = pack[0].decode()
        headers[X_TRACE_HMAC] = pack[1] or ""
        return headers
    return {}


_ENABLED: bool | None = None
_HMAC_KEYS: list[str] | tuple[str, ...] | None = None
_ALWAYS_TRACE: bool | None = None
_TRACE_SAMPLE_RATE: float | None = None


def disable() -> None:
    """Disable middleware.

    This is the alternative way to disable middleware. It will be used to be
    able to disable middleware via oslo.config.
    """
    global _ENABLED, _ALWAYS_TRACE, _TRACE_SAMPLE_RATE
    _ENABLED = False
    _ALWAYS_TRACE = False
    _TRACE_SAMPLE_RATE = 1.0


def enable(
    hmac_keys: str | None = None,
    always_trace: bool = False,
    trace_sample_rate: float = 1.0,
) -> None:
    """Enable middleware."""
    global _ENABLED, _HMAC_KEYS, _ALWAYS_TRACE, _TRACE_SAMPLE_RATE
    _ENABLED = True
    _HMAC_KEYS = utils.split(hmac_keys or "")
    _ALWAYS_TRACE = always_trace
    _TRACE_SAMPLE_RATE = trace_sample_rate


class WsgiMiddleware:
    """WSGI Middleware that enables tracing for an application."""

    def __init__(
        self,
        application: WSGIApplication,
        hmac_keys: str | None = None,
        enabled: bool = False,
        always_trace: bool = False,
        trace_sample_rate: float = 1.0,
        **kwargs: Any,
    ) -> None:
        """Initialize middleware with api-paste.ini arguments.

        :application: wsgi app
        :hmac_keys: Only trace header that was signed with one of these
                    hmac keys will be processed. This limitation is
                    essential, because it allows to profile OpenStack
                    by only those who knows this key which helps
                    avoid DDOS.
        :enabled: This middleware can be turned off fully if enabled is False.
        :always_trace: Enable always-on tracing for all incoming requests.
        :trace_sample_rate: Sample rate for always-on tracing (0.0 to 1.0).
        :kwargs: Other keyword arguments.
                 NOTE(tovin07): Currently, this `kwargs` is not used at all.
                 It's here to avoid some extra keyword arguments in local_conf
                 that cause `__init__() got an unexpected keyword argument`.
        """
        self.application = application
        self.name = "wsgi"
        self.enabled = enabled
        self.hmac_keys = utils.split(hmac_keys or "")
        self.always_trace = always_trace or strutils.bool_from_string(
            str(kwargs.get("always_trace", False))
        )
        try:
            self.trace_sample_rate = float(
                kwargs.get("trace_sample_rate", trace_sample_rate)
            )
        except (ValueError, TypeError):
            self.trace_sample_rate = 1.0

    @classmethod
    def factory(
        cls, global_conf: dict[str, Any] | None, **local_conf: Any
    ) -> Any:
        def filter_(app: Any) -> WsgiMiddleware:
            return cls(app, **local_conf)

        return filter_

    def _trace_is_valid(
        self, trace_info: dict[str, Any] | None
    ) -> TypeGuard[dict[str, Any]]:
        if not isinstance(trace_info, dict):
            return False
        trace_keys = set(trace_info.keys())
        if not all(k in trace_keys for k in _REQUIRED_KEYS):
            return False
        if trace_keys.difference(_REQUIRED_KEYS + _OPTIONAL_KEYS):
            return False
        return True

    @webob.dec.wsgify
    def __call__(
        self, request: webob.request.Request
    ) -> webob.response.Response:
        if (
            _ENABLED is not None
            and not _ENABLED
            or _ENABLED is None
            and not self.enabled
        ):
            return request.get_response(self.application)

        trace_info = None
        x_trace_info = request.headers.get(X_TRACE_INFO)
        x_trace_hmac = request.headers.get(X_TRACE_HMAC)
        keys = _HMAC_KEYS or self.hmac_keys

        if x_trace_info and x_trace_hmac:
            trace_info = utils.signed_unpack(
                x_trace_info,
                x_trace_hmac,
                keys,
            )

        w3c_trace_id, w3c_parent_id = extract_w3c_context(request.headers)

        if not self._trace_is_valid(trace_info):
            # Skip tracing for kubernetes health probes to avoid spamming spans
            if request.headers.get("User-Agent", "").startswith("kube-probe"):
                return request.get_response(self.application)

            always_trace = (
                _ALWAYS_TRACE
                if _ALWAYS_TRACE is not None
                else self.always_trace
            )
            sample_rate = (
                _TRACE_SAMPLE_RATE
                if _TRACE_SAMPLE_RATE is not None
                else self.trace_sample_rate
            )

            default_hmac_key = keys[0] if keys else "openstack-profiler"

            # Option 1: W3C traceparent header is present (e.g. from K8s Ingress / Envoy)
            if w3c_trace_id and w3c_parent_id:
                formatted_base_id = (
                    f"{w3c_trace_id[:8]}-{w3c_trace_id[8:12]}-{w3c_trace_id[12:16]}-"
                    f"{w3c_trace_id[16:20]}-{w3c_trace_id[20:]}"
                )
                trace_info = {
                    "hmac_key": default_hmac_key,
                    "base_id": formatted_base_id,
                    "parent_id": w3c_parent_id,
                }
            # Option 2: Always-on tracing for all other requests without headers
            elif always_trace:
                if sample_rate < 1.0 and random.random() >= sample_rate:
                    return request.get_response(self.application)

                trace_info = {
                    "hmac_key": default_hmac_key,
                    "base_id": str(uuidutils.generate_uuid()),
                    "parent_id": None,
                }
            else:
                return request.get_response(self.application)
        else:
            # Option 3: Valid OpenStack HMAC trace, correlate with W3C if present
            if w3c_trace_id:
                trace_info["base_id"] = (
                    f"{w3c_trace_id[:8]}-{w3c_trace_id[8:12]}-{w3c_trace_id[12:16]}-"
                    f"{w3c_trace_id[16:20]}-{w3c_trace_id[20:]}"
                )
                if w3c_parent_id:
                    trace_info["parent_id"] = w3c_parent_id

        profiler.init(
            hmac_key=trace_info["hmac_key"],
            base_id=trace_info.get("base_id"),
            parent_id=trace_info.get("parent_id"),
        )
        info = {
            "request": {
                "path": request.path,
                "query": request.query_string,
                "method": request.method,
                "scheme": request.scheme,
            }
        }
        try:
            with profiler.Trace(self.name, info=info):
                return request.get_response(self.application)
        finally:
            profiler.clean()
