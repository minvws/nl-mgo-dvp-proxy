import inject
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter as OTLPSpanExporterGRPC,
)
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from app.config.models import TelemetryConfig


@inject.autoparams()
def setup_jaeger(app: FastAPI, telemetry_config: TelemetryConfig) -> None:
    if not telemetry_config.enabled:
        return

    resource = Resource(attributes={"service.name": telemetry_config.service_name})
    tracer = TracerProvider(resource=resource)
    trace.set_tracer_provider(tracer)

    tracer.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporterGRPC(
                endpoint=telemetry_config.collector_grpc_url, insecure=True
            )
        )
    )

    FastAPIInstrumentor.instrument_app(
        app, tracer_provider=tracer, exclude_spans=["receive", "send"]
    )
