import os
import sys
import logging
import time
from functools import wraps

import psycopg
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row
from psycopg.types.json import Json

import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv

from opentelemetry import trace, metrics
from opentelemetry.trace import Status, StatusCode
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL")

if not DATABASE_URL or not AUTH_SERVICE_URL:
    log.critical("Erro: DATABASE_URL e AUTH_SERVICE_URL devem ser definidos.")
    sys.exit(1)

app = Flask(__name__)


# -------------------------------------------------
# OpenTelemetry
# -------------------------------------------------
SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "targeting-service")
OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv(
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "http://otel-collector.monitoring.svc.cluster.local:4318"
)

resource = Resource.create({
    ResourceAttributes.SERVICE_NAME: SERVICE_NAME,
    "service.version": os.getenv("SERVICE_VERSION", "1.0.0"),
    "deployment.environment": os.getenv("ENVIRONMENT", "dev"),
})

trace_provider = TracerProvider(resource=resource)
trace_exporter = OTLPSpanExporter(
    endpoint=f"{OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces"
)
trace_provider.add_span_processor(BatchSpanProcessor(trace_exporter))
trace.set_tracer_provider(trace_provider)
tracer = trace.get_tracer(__name__)

metric_exporter = OTLPMetricExporter(
    endpoint=f"{OTEL_EXPORTER_OTLP_ENDPOINT}/v1/metrics"
)
metric_reader = PeriodicExportingMetricReader(
    exporter=metric_exporter,
    export_interval_millis=10000
)
metrics_provider = MeterProvider(
    resource=resource,
    metric_readers=[metric_reader]
)
metrics.set_meter_provider(metrics_provider)
meter = metrics.get_meter(__name__)

targeting_operations_counter = meter.create_counter(
    name="targeting_rule_operations_total",
    description="Total de operações realizadas no targeting-service",
    unit="1"
)

targeting_errors_counter = meter.create_counter(
    name="targeting_rule_errors_total",
    description="Total de erros ocorridos no targeting-service",
    unit="1"
)

targeting_operation_duration = meter.create_histogram(
    name="targeting_rule_operation_duration_seconds",
    description="Tempo de execução das operações de regras de targeting",
    unit="s"
)

auth_validation_counter = meter.create_counter(
    name="targeting_auth_validations_total",
    description="Total de validações de autenticação feitas pelo targeting-service",
    unit="1"
)

auth_validation_duration = meter.create_histogram(
    name="targeting_auth_validation_duration_seconds",
    description="Tempo gasto validando autenticação no auth-service",
    unit="s"
)

RequestsInstrumentor().instrument()
FlaskInstrumentor().instrument_app(app)


# -------------------------------------------------
# PostgreSQL Connection Pool
# -------------------------------------------------
try:
    pool = ConnectionPool(
        conninfo=DATABASE_URL,
        min_size=1,
        max_size=5,
    )
    log.info("Pool de conexões com PostgreSQL inicializado.")
except Exception as e:
    log.critical(f"Erro fatal ao inicializar pool: {e}")
    sys.exit(1)


# -------------------------------------------------
# Auth Middleware
# -------------------------------------------------
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        start_time = time.time()
        auth_header = request.headers.get("Authorization")

        with tracer.start_as_current_span("validate_auth_token") as span:
            span.set_attribute("auth.service.url", AUTH_SERVICE_URL)
            span.set_attribute("http.route", request.path)

            if not auth_header:
                auth_validation_counter.add(1, {"status": "missing_header"})
                targeting_errors_counter.add(1, {
                    "operation": "auth",
                    "error_type": "missing_authorization_header"
                })
                span.set_status(Status(StatusCode.ERROR, "Authorization header ausente"))
                return jsonify({"error": "Authorization header obrigatório"}), 401

            try:
                response = requests.get(
                    f"{AUTH_SERVICE_URL}/validate",
                    headers={"Authorization": auth_header},
                    timeout=3,
                )

                duration = time.time() - start_time
                auth_validation_duration.record(duration, {
                    "status_code": str(response.status_code)
                })

                span.set_attribute("auth.status_code", response.status_code)

                if response.status_code != 200:
                    auth_validation_counter.add(1, {"status": "invalid"})
                    targeting_errors_counter.add(1, {
                        "operation": "auth",
                        "error_type": "invalid_api_key"
                    })
                    span.set_status(Status(StatusCode.ERROR, "API key inválida"))
                    return jsonify({"error": "Chave de API inválida"}), 401

                auth_validation_counter.add(1, {"status": "success"})
                span.set_status(Status(StatusCode.OK))

            except requests.exceptions.Timeout as e:
                duration = time.time() - start_time
                auth_validation_duration.record(duration, {"status_code": "timeout"})
                auth_validation_counter.add(1, {"status": "timeout"})
                targeting_errors_counter.add(1, {
                    "operation": "auth",
                    "error_type": "auth_timeout"
                })
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                return jsonify({"error": "Serviço de autenticação indisponível (timeout)"}), 504

            except requests.exceptions.RequestException as e:
                duration = time.time() - start_time
                auth_validation_duration.record(duration, {"status_code": "request_exception"})
                auth_validation_counter.add(1, {"status": "unavailable"})
                targeting_errors_counter.add(1, {
                    "operation": "auth",
                    "error_type": "auth_unavailable"
                })
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                log.error(f"Erro ao conectar ao auth-service: {e}")
                return jsonify({"error": "Serviço de autenticação indisponível"}), 503

        return f(*args, **kwargs)

    return decorated


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/telemetry")
def telemetry_info():
    return jsonify({
        "service_name": SERVICE_NAME,
        "otel_endpoint": OTEL_EXPORTER_OTLP_ENDPOINT,
        "otlp_traces_path": f"{OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces",
        "otlp_metrics_path": f"{OTEL_EXPORTER_OTLP_ENDPOINT}/v1/metrics",
        "status": "otel-configured"
    })


@app.route("/rules", methods=["POST"])
@require_auth
def create_rule():
    start_time = time.time()

    with tracer.start_as_current_span("create_targeting_rule") as span:
        data = request.get_json()

        if not data or "flag_name" not in data or "rules" not in data:
            targeting_errors_counter.add(1, {
                "operation": "create",
                "error_type": "validation_error"
            })
            span.set_status(Status(StatusCode.ERROR, "flag_name e rules obrigatórios"))
            return jsonify({"error": "'flag_name' e 'rules' (JSON) são obrigatórios"}), 400

        flag_name = data["flag_name"]
        is_enabled = data.get("is_enabled", True)

        span.set_attribute("feature_flag.name", flag_name)
        span.set_attribute("targeting_rule.enabled", is_enabled)

        try:
            with pool.connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute(
                        """
                        INSERT INTO targeting_rules
                        (flag_name, is_enabled, rules, created_at, updated_at)
                        VALUES (%s, %s, %s, NOW(), NOW())
                        RETURNING *
                        """,
                        (
                            flag_name,
                            is_enabled,
                            Json(data["rules"]),
                        ),
                    )
                    result = cur.fetchone()
                    conn.commit()

            duration = time.time() - start_time
            targeting_operations_counter.add(1, {
                "operation": "create",
                "status": "success"
            })
            targeting_operation_duration.record(duration, {
                "operation": "create",
                "status": "success"
            })
            span.set_status(Status(StatusCode.OK))

            log.info(f"Regra '{flag_name}' criada com sucesso.")
            return jsonify(result), 201

        except psycopg.errors.UniqueViolation as e:
            duration = time.time() - start_time
            targeting_errors_counter.add(1, {
                "operation": "create",
                "error_type": "unique_violation"
            })
            targeting_operation_duration.record(duration, {
                "operation": "create",
                "status": "error"
            })
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            return jsonify({"error": f"Regra para a flag '{flag_name}' já existe"}), 409

        except Exception as e:
            duration = time.time() - start_time
            targeting_errors_counter.add(1, {
                "operation": "create",
                "error_type": "internal_error"
            })
            targeting_operation_duration.record(duration, {
                "operation": "create",
                "status": "error"
            })
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            log.error(f"Erro ao criar regra: {e}")
            return jsonify({"error": "Erro interno do servidor", "details": str(e)}), 500


@app.route("/rules/<string:flag_name>", methods=["GET"])
@require_auth
def get_rule(flag_name):
    start_time = time.time()

    with tracer.start_as_current_span("get_targeting_rule") as span:
        span.set_attribute("feature_flag.name", flag_name)

        try:
            with pool.connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute(
                        "SELECT * FROM targeting_rules WHERE flag_name = %s",
                        (flag_name,),
                    )
                    rule = cur.fetchone()

            duration = time.time() - start_time

            if not rule:
                targeting_errors_counter.add(1, {
                    "operation": "get",
                    "error_type": "not_found"
                })
                targeting_operation_duration.record(duration, {
                    "operation": "get",
                    "status": "not_found"
                })
                span.set_status(Status(StatusCode.ERROR, "Regra não encontrada"))
                return jsonify({"error": "Regra não encontrada"}), 404

            targeting_operations_counter.add(1, {
                "operation": "get",
                "status": "success"
            })
            targeting_operation_duration.record(duration, {
                "operation": "get",
                "status": "success"
            })
            span.set_status(Status(StatusCode.OK))

            return jsonify(rule), 200

        except Exception as e:
            duration = time.time() - start_time
            targeting_errors_counter.add(1, {
                "operation": "get",
                "error_type": "internal_error"
            })
            targeting_operation_duration.record(duration, {
                "operation": "get",
                "status": "error"
            })
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            log.error(f"Erro ao buscar regra '{flag_name}': {e}")
            return jsonify({"error": "Erro interno do servidor", "details": str(e)}), 500


@app.route("/rules/<string:flag_name>", methods=["PUT"])
@require_auth
def update_rule(flag_name):
    start_time = time.time()

    with tracer.start_as_current_span("update_targeting_rule") as span:
        span.set_attribute("feature_flag.name", flag_name)

        data = request.get_json()

        if not data:
            targeting_errors_counter.add(1, {
                "operation": "update",
                "error_type": "empty_body"
            })
            span.set_status(Status(StatusCode.ERROR, "corpo obrigatório"))
            return jsonify({"error": "Corpo da requisição obrigatório"}), 400

        fields = []
        values = []

        if "rules" in data:
            fields.append("rules = %s")
            values.append(Json(data["rules"]))

        if "is_enabled" in data:
            fields.append("is_enabled = %s")
            values.append(data["is_enabled"])
            span.set_attribute("targeting_rule.enabled", data["is_enabled"])

        if not fields:
            targeting_errors_counter.add(1, {
                "operation": "update",
                "error_type": "validation_error"
            })
            span.set_status(Status(StatusCode.ERROR, "nenhum campo válido"))
            return jsonify({"error": "Pelo menos um campo ('rules', 'is_enabled') é obrigatório"}), 400

        values.append(flag_name)

        query = f"""
            UPDATE targeting_rules
            SET {', '.join(fields)}, updated_at = NOW()
            WHERE flag_name = %s
            RETURNING *
        """

        try:
            with pool.connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute(query, tuple(values))

                    duration = time.time() - start_time

                    if cur.rowcount == 0:
                        targeting_errors_counter.add(1, {
                            "operation": "update",
                            "error_type": "not_found"
                        })
                        targeting_operation_duration.record(duration, {
                            "operation": "update",
                            "status": "not_found"
                        })
                        span.set_status(Status(StatusCode.ERROR, "Regra não encontrada"))
                        return jsonify({"error": "Regra não encontrada"}), 404

                    updated = cur.fetchone()
                    conn.commit()

            targeting_operations_counter.add(1, {
                "operation": "update",
                "status": "success"
            })
            targeting_operation_duration.record(duration, {
                "operation": "update",
                "status": "success"
            })
            span.set_status(Status(StatusCode.OK))

            log.info(f"Regra '{flag_name}' atualizada com sucesso.")
            return jsonify(updated), 200

        except Exception as e:
            duration = time.time() - start_time
            targeting_errors_counter.add(1, {
                "operation": "update",
                "error_type": "internal_error"
            })
            targeting_operation_duration.record(duration, {
                "operation": "update",
                "status": "error"
            })
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            log.error(f"Erro ao atualizar regra '{flag_name}': {e}")
            return jsonify({"error": "Erro interno do servidor", "details": str(e)}), 500


@app.route("/rules/<string:flag_name>", methods=["DELETE"])
@require_auth
def delete_rule(flag_name):
    start_time = time.time()

    with tracer.start_as_current_span("delete_targeting_rule") as span:
        span.set_attribute("feature_flag.name", flag_name)

        try:
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM targeting_rules WHERE flag_name = %s",
                        (flag_name,),
                    )

                    duration = time.time() - start_time

                    if cur.rowcount == 0:
                        targeting_errors_counter.add(1, {
                            "operation": "delete",
                            "error_type": "not_found"
                        })
                        targeting_operation_duration.record(duration, {
                            "operation": "delete",
                            "status": "not_found"
                        })
                        span.set_status(Status(StatusCode.ERROR, "Regra não encontrada"))
                        return jsonify({"error": "Regra não encontrada"}), 404

                    conn.commit()

            targeting_operations_counter.add(1, {
                "operation": "delete",
                "status": "success"
            })
            targeting_operation_duration.record(duration, {
                "operation": "delete",
                "status": "success"
            })
            span.set_status(Status(StatusCode.OK))

            log.info(f"Regra '{flag_name}' deletada com sucesso.")
            return "", 204

        except Exception as e:
            duration = time.time() - start_time
            targeting_errors_counter.add(1, {
                "operation": "delete",
                "error_type": "internal_error"
            })
            targeting_operation_duration.record(duration, {
                "operation": "delete",
                "status": "error"
            })
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            log.error(f"Erro ao deletar regra '{flag_name}': {e}")
            return jsonify({"error": "Erro interno do servidor", "details": str(e)}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8003))
    app.run(host="0.0.0.0", port=port, debug=False)