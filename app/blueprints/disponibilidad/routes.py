from flask import Blueprint, request, jsonify, current_app
from app.schemas.validators import DisponibilidadQuerySchema
from app.services.db_service import DatabaseService

disponibilidad_bp = Blueprint("disponibilidad", __name__, url_prefix="/api/v1/disponibilidad")
db = DatabaseService.get_instance()

@disponibilidad_bp.route("", methods=["GET"])
def consultar_disponibilidad():
    """
    CU02 — Consultar Disponibilidad.
    Calcula dinámicamente las franjas horarias libres para un profesional médico y fecha dada.
    ---
    tags:
      - Disponibilidad
    summary: Consulta los horarios libres de un profesional en una fecha (CU02)
    parameters:
      - in: query
        name: id_profesional
        required: true
        type: string
        example: PRF-001
      - in: query
        name: fecha
        required: true
        type: string
        format: date
        example: "2026-09-25"
    responses:
      200:
        description: Lista de franjas horarias disponibles
      400:
        description: Parámetros inválidos
      404:
        description: Profesional no encontrado
    """
    args = {
        "id_profesional": request.args.get("id_profesional"),
        "fecha": request.args.get("fecha")
    }
    schema = DisponibilidadQuerySchema()
    errors = schema.validate(args)
    if errors:
        return jsonify({"error": "Parámetros inválidos", "detalles": errors}), 400

    horas_jornada = current_app.config["HORAS_JORNADA"]
    disponibles, err = db.get_disponibilidad(
        id_profesional=args["id_profesional"],
        fecha=str(args["fecha"]),
        horas_jornada=horas_jornada
    )
    if err:
        return jsonify({"error": err}), 404

    return jsonify({
        "id_profesional": args["id_profesional"],
        "fecha": str(args["fecha"]),
        "horarios_disponibles": disponibles,
        "horarios_ocupados": [h for h in horas_jornada if h not in disponibles],
        "total_disponibles": len(disponibles),
        "total_ocupados": len(horas_jornada) - len(disponibles)
    }), 200
