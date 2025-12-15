import os
import sys
import logging
from functools import wraps

import psycopg
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row
from psycopg.types.json import Json

import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv


# -------------------------------------------------
# Logging
# -------------------------------------------------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# -------------------------------------------------
# Environment
# -------------------------------------------------
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL")

if not DATABASE_URL or not AUTH_SERVICE_URL:
    log.critical("Erro: DATABASE_URL e AUTH_SERVICE_URL devem ser definidos.")
    sys.exit(1)

# -------------------------------------------------
# Flask app
# -------------------------------------------------
app = Flask(__name__)

# -------------------------------------------------
# PostgreSQL Connection Pool (psycopg v3)
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
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Authorization header obrigatório"}), 401

        try:
            response = requests.get(
                f"{AUTH_SERVICE_URL}/validate",
                headers={"Authorization": auth_header},
                timeout=3,
            )

            if response.status_code != 200:
                log.warning("Falha na validação da chave de API")
                return jsonify({"error": "Chave de API inválida"}), 401

        except requests.exceptions.Timeout:
            return jsonify(
                {"error": "Serviço de autenticação indisponível (timeout)"}
            ), 504
        except requests.exceptions.RequestException as e:
            log.error(f"Erro ao conectar ao auth-service: {e}")
            return jsonify(
                {"error": "Serviço de autenticação indisponível"}
            ), 503

        return f(*args, **kwargs)

    return decorated

# -------------------------------------------------
# Health
# -------------------------------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok"})

# -------------------------------------------------
# Create rule
# -------------------------------------------------
@app.route("/rules", methods=["POST"])
@require_auth
def create_rule():
    data = request.get_json()

    if not data or "flag_name" not in data or "rules" not in data:
        return jsonify(
            {"error": "'flag_name' e 'rules' (JSON) são obrigatórios"}
        ), 400

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
                        data["flag_name"],
                        data.get("is_enabled", True),
                        Json(data["rules"]),
                    ),
                )
                result = cur.fetchone()
                conn.commit()

        log.info(f"Regra '{data['flag_name']}' criada com sucesso.")
        return jsonify(result), 201

    except psycopg.errors.UniqueViolation:
        return jsonify(
            {"error": f"Regra para a flag '{data['flag_name']}' já existe"}
        ), 409
    except Exception as e:
        log.error(f"Erro ao criar regra: {e}")
        return jsonify(
            {"error": "Erro interno do servidor", "details": str(e)}
        ), 500

# -------------------------------------------------
# Get rule
# -------------------------------------------------
@app.route("/rules/<string:flag_name>", methods=["GET"])
@require_auth
def get_rule(flag_name):
    try:
        with pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT * FROM targeting_rules WHERE flag_name = %s",
                    (flag_name,),
                )
                rule = cur.fetchone()

        if not rule:
            return jsonify({"error": "Regra não encontrada"}), 404

        return jsonify(rule), 200

    except Exception as e:
        log.error(f"Erro ao buscar regra '{flag_name}': {e}")
        return jsonify(
            {"error": "Erro interno do servidor", "details": str(e)}
        ), 500

# -------------------------------------------------
# Update rule
# -------------------------------------------------
@app.route("/rules/<string:flag_name>", methods=["PUT"])
@require_auth
def update_rule(flag_name):
    data = request.get_json()

    if not data:
        return jsonify({"error": "Corpo da requisição obrigatório"}), 400

    fields = []
    values = []

    if "rules" in data:
        fields.append("rules = %s")
        values.append(Json(data["rules"]))

    if "is_enabled" in data:
        fields.append("is_enabled = %s")
        values.append(data["is_enabled"])

    if not fields:
        return jsonify(
            {"error": "Pelo menos um campo ('rules', 'is_enabled') é obrigatório"}
        ), 400

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

                if cur.rowcount == 0:
                    return jsonify({"error": "Regra não encontrada"}), 404

                updated = cur.fetchone()
                conn.commit()

        log.info(f"Regra '{flag_name}' atualizada com sucesso.")
        return jsonify(updated), 200

    except Exception as e:
        log.error(f"Erro ao atualizar regra '{flag_name}': {e}")
        return jsonify(
            {"error": "Erro interno do servidor", "details": str(e)}
        ), 500

# -------------------------------------------------
# Delete rule
# -------------------------------------------------
@app.route("/rules/<string:flag_name>", methods=["DELETE"])
@require_auth
def delete_rule(flag_name):
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM targeting_rules WHERE flag_name = %s",
                    (flag_name,),
                )

                if cur.rowcount == 0:
                    return jsonify({"error": "Regra não encontrada"}), 404

                conn.commit()

        log.info(f"Regra '{flag_name}' deletada com sucesso.")
        return "", 204

    except Exception as e:
        log.error(f"Erro ao deletar regra '{flag_name}': {e}")
        return jsonify(
            {"error": "Erro interno do servidor", "details": str(e)}
        ), 500

# -------------------------------------------------
# Main
# -------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8003))
    app.run(host="0.0.0.0", port=port, debug=False)
