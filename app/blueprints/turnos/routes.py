from flask import Blueprint, request, jsonify, g, current_app
from app.schemas.validators import ReservarTurnoSchema, CancelarTurnoSchema
from app.middleware.auth import jwt_required_custom
from app.services.db_service import DatabaseService

turnos_bp = Blueprint("turnos", __name__, url_prefix="/api/v1/turnos")
db = DatabaseService.get_instance()

@turnos_bp.route("", methods=["POST"])
@jwt_required_custom(optional=True)
def reservar_turno():
    """
    CU03 — Reservar Turno.
    Reserva un horario para consulta médica verificando reglas de disponibilidad atómica.
    ---
    tags:
      - Turnos
    summary: Registra una nueva reserva de turno médico (CU03)
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [id_profesional, fecha, hora]
          properties:
            ci:
              type: string
              example: 8452136 SC
            id_paciente:
              type: string
            id_profesional:
              type: string
              example: PRF-001
            fecha:
              type: string
              format: date
              example: "2026-09-25"
            hora:
              type: string
              example: "09:00"
    responses:
      201:
        description: Turno reservado con éxito
      400:
        description: Datos faltantes o inválidos
      409:
        description: Conflicto de horario no disponible
    """
    data = request.get_json() or {}
    schema = ReservarTurnoSchema()
    errors = schema.validate(data)
    if errors:
        return jsonify({"error": "Validación fallida", "detalles": errors}), 400

    # Determinar el paciente: por CI o por ID o por token
    paciente = None
    if data.get("ci"):
        paciente = db.get_paciente_by_ci(data["ci"])
    elif data.get("id_paciente"):
        paciente = db.get_paciente_by_id(data["id_paciente"])
    elif getattr(g, "current_user", None):
        if g.current_user.get("paciente_id"):
            paciente = db.get_paciente_by_id(g.current_user["paciente_id"])
        # Fallback: el claim paciente_id del JWT puede no existir si la ficha se
        # creó en la misma sesión (registro + reserva inmediata). El vínculo vivo
        # está en la BD (pacientes.id_usuario).
        if not paciente:
            paciente = db.get_paciente_by_user_id(g.current_user["sub"])

    if not paciente:
        return jsonify({"error": "No existe un paciente registrado con esos datos. Regístrelo previamente (CU01)."}), 400

    # DEFENSA BOLA: Si el usuario es de rol paciente, no debe poder reservar para otro paciente
    user = getattr(g, "current_user", None)
    if user and user.get("role") == "paciente":
        if paciente["id_usuario"] and paciente["id_usuario"] != user["sub"]:
            return jsonify({"error": "Acceso denegado: no puede reservar turnos para un paciente ajeno"}), 403

    horas_jornada = current_app.config["HORAS_JORNADA"]
    turno, err = db.create_turno(
        id_paciente=paciente["id"],
        id_profesional=data["id_profesional"],
        fecha=str(data["fecha"]),
        hora=data["hora"],
        horas_jornada=horas_jornada
    )
    if err:
        return jsonify({"error": err}), 409

    return jsonify({
        "mensaje": f"Turno reservado para el {turno['fecha']} a las {turno['hora']}.",
        "turno": turno
    }), 201

@turnos_bp.route("", methods=["GET"])
@jwt_required_custom(optional=True)
def buscar_turnos():
    """
    CU04 — Consultar Turnos.
    Permite consultar turnos por CI del paciente o código de turno.
    Aplica defensas estrictas contra BOLA / IDOR.
    ---
    tags:
      - Turnos
    summary: Consulta y busca turnos registrados (CU04)
    parameters:
      - in: query
        name: ci
        type: string
        example: 8452136 SC
      - in: query
        name: id_turno
        type: string
        example: TUR-A1B2C
    responses:
      200:
        description: Listado de turnos coincidentes
    """
    ci = request.args.get("ci")
    id_turno = request.args.get("id_turno")

    user = getattr(g, "current_user", None)

    # Si un usuario autenticado con rol paciente consulta, aseguramos BOLA
    if user and user.get("role") == "paciente":
        mi_paciente = db.get_paciente_by_user_id(user["sub"])
        if mi_paciente:
            # Forzamos que solo consulte sus propios turnos
            turnos = db.search_turnos(id_paciente=mi_paciente["id"], id_turno=id_turno)
            return jsonify({
                "total": len(turnos),
                "turnos": turnos
            }), 200

    # Si es personal médico
    if user and user.get("role") == "medico":
        prof = db.get_profesional_by_id_or_code(user["sub"])
        id_prof = prof["id"] if prof else None
        turnos = db.search_turnos(ci=ci, id_turno=id_turno, id_profesional=id_prof)
        return jsonify({
            "total": len(turnos),
            "turnos": turnos
        }), 200

    # Consulta general por CI o código de turno (CU04 del frontend)
    turnos = db.search_turnos(ci=ci, id_turno=id_turno)
    return jsonify({
        "total": len(turnos),
        "turnos": turnos
    }), 200

@turnos_bp.route("/<identifier>", methods=["GET"])
@jwt_required_custom(optional=True)
def get_turno(identifier):
    """
    Obtiene el detalle de un turno específico con control de autorización.
    ---
    tags:
      - Turnos
    summary: Consulta un turno por su ID o código
    parameters:
      - in: path
        name: identifier
        required: true
        type: string
        example: TUR-10001
    responses:
      200:
        description: Detalle del turno
      404:
        description: Turno no encontrado
    """
    turno = db.get_turno_by_id(identifier)
    if not turno:
        return jsonify({"error": "No se encontró ningún turno con ese identificador"}), 404

    # DEFENSA BOLA: Verificar pertenencia si es paciente
    user = getattr(g, "current_user", None)
    if user and user.get("role") == "paciente":
        if turno["paciente"]["id_usuario"] and turno["paciente"]["id_usuario"] != user["sub"]:
            return jsonify({"error": "Acceso denegado: este turno pertenece a otro paciente"}), 403

    return jsonify({"turno": turno}), 200

@turnos_bp.route("/<identifier>/cancelar", methods=["PATCH", "POST"])
@jwt_required_custom(optional=True)
def cancelar_turno(identifier):
    """
    CU05 — Cancelar Turno.
    Cancela un turno activo validando permisos y pertenencia.
    ---
    tags:
      - Turnos
    summary: Cancela un turno existente (CU05)
    parameters:
      - in: path
        name: identifier
        required: true
        type: string
        example: TUR-A1B2C
      - in: body
        name: body
        schema:
          type: object
          properties:
            motivo:
              type: string
              example: Cambio de planes del paciente
    responses:
      200:
        description: Turno cancelado correctamente
      403:
        description: No autorizado para cancelar este turno ajeno (BOLA)
      404:
        description: Turno no encontrado
    """
    turno = db.get_turno_by_id(identifier)
    if not turno:
        return jsonify({"error": "No se encontró ningún turno con ese identificador."}), 404

    # DEFENSA CONTRA BOLA / IDOR (OWASP API1:2023)
    user = getattr(g, "current_user", None)
    if user and user.get("role") == "paciente":
        if turno["paciente"]["id_usuario"] and turno["paciente"]["id_usuario"] != user["sub"]:
            return jsonify({"error": "Acceso denegado: no tiene autorización para cancelar un turno ajeno"}), 403

    data = request.get_json() or {}
    schema = CancelarTurnoSchema()
    data_clean = schema.load(data)

    turno_actualizado, err = db.cancel_turno(identifier, motivo=data_clean.get("motivo", "Cancelado por el usuario"))
    if err and "previamente" in err:
        return jsonify({
            "mensaje": "Este turno ya estaba cancelado.",
            "turno": turno_actualizado
        }), 200

    return jsonify({
        "mensaje": "Turno cancelado correctamente.",
        "turno": turno_actualizado
    }), 200
