from flask import Blueprint, request, jsonify, g, current_app
from app.schemas.validators import ReservarTurnoSchema, CancelarTurnoSchema
from app.middleware.auth import jwt_required_custom, roles_required
from app.services.db_service import DatabaseService

turnos_bp = Blueprint("turnos", __name__, url_prefix="/api/v1/turnos")
db = DatabaseService.get_instance()

def _mi_profesional(user):
    """Resuelve la ficha profesional del usuario médico autenticado.

    Devuelve (profesional, 403_response). Si el usuario tiene rol 'medico' pero no
    está vinculado a ningún profesional, se deniega el acceso: sin esa ficha no se
    puede acotar la consulta y terminaría exponiendo la agenda de todo el centro.
    """
    if not user or user.get("role") != "medico":
        return None, None
    profesional = db.get_profesional_by_user_id(user["sub"])
    if not profesional:
        return None, (
            jsonify({
                "error": "Acceso denegado: tu usuario no está vinculado a una ficha de profesional."
            }),
            403
        )
    return profesional, None

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
        description: "Conflicto: horario no disponible, o el paciente ya tiene un turno ese día"
      403:
        description: El rol médico no puede registrar turnos
    """
    data = request.get_json() or {}

    # El personal médico tiene acceso de solo lectura a su agenda: no registra turnos.
    if getattr(g, "current_user", None) and g.current_user.get("role") == "medico":
        return jsonify({
            "error": "Acceso denegado: el personal médico no puede registrar turnos."
        }), 403

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
        # Rescate de fichas huérfanas creadas sin autenticación (id_usuario NULL):
        # si el correo de la ficha coincide con el email del token, es el mismo paciente.
        if not paciente and g.current_user.get("email"):
            paciente = db.get_paciente_by_correo(g.current_user["email"])

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
@jwt_required_custom()
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
      401:
        description: Falta autenticación: la agenda nunca se expone sin sesión
    """
    ci = request.args.get("ci")
    id_turno = request.args.get("id_turno")

    user = getattr(g, "current_user", None)

    # Si un usuario autenticado con rol paciente consulta, aseguramos BOLA.
    # Falla en CERRADO: si la cuenta no tiene ficha de paciente vinculada, se
    # devuelve una lista vacía. Antes caía en la consulta general y el paciente
    # veía la agenda completa de los demás (OWASP API1:2023).
    if user and user.get("role") == "paciente":
        mi_paciente = db.get_paciente_by_user_id(user["sub"])
        if not mi_paciente:
            return jsonify({
                "error": "Tu cuenta todavía no tiene una ficha de paciente registrada. "
                         "Registrate en el centro de salud para consultar tus turnos.",
                "total": 0,
                "turnos": []
            }), 200
        # Forzamos que solo consulte sus propios turnos, ignorando cualquier
        # 'ci' que envíe: el filtro lo impone la identidad del token, no el cliente.
        turnos = db.search_turnos(id_paciente=mi_paciente["id"], id_turno=id_turno)
        return jsonify({
            "total": len(turnos),
            "turnos": turnos
        }), 200

    # El personal médico solo puede ver los turnos de su propia agenda.
    if user and user.get("role") == "medico":
        profesional, error = _mi_profesional(user)
        if error:
            return error
        turnos = db.search_turnos(id_profesional=profesional["id"], id_turno=id_turno)
        return jsonify({
            "total": len(turnos),
            "turnos": turnos
        }), 200

    # Consulta general por CI o código de turno: reservada a administración y
    # recepción, que son los roles autorizados a ver toda la agenda.
    if user.get("role") not in ("admin", "recepcionista"):
        return jsonify({
            "error": "Acceso denegado: tu rol no puede consultar la agenda general."
        }), 403

    turnos = db.search_turnos(ci=ci, id_turno=id_turno)
    return jsonify({
        "total": len(turnos),
        "turnos": turnos
    }), 200

@turnos_bp.route("/<identifier>", methods=["GET"])
@jwt_required_custom()
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
      401:
        description: Falta autenticación
      403:
        description: El turno pertenece a otro paciente u otro profesional
      404:
        description: Turno no encontrado
    """
    user = getattr(g, "current_user", None)
    turno = db.get_turno_by_id(identifier)
    if not turno:
        return jsonify({"error": "No se encontró ningún turno con ese identificador"}), 404

    rol = user.get("role")

    # El personal administrativo (recepción/admin) consulta cualquier turno por
    # código: es el flujo de atención en mostrador. Se retourne temprano.
    if rol in ("admin", "recepcionista"):
        return jsonify({"turno": turno}), 200

    # DEFENSA BOLA — paciente: solo el suyo, y falla en CERRADO.
    # Una ficha sin 'id_usuario' (alta de recepción, sin cuenta) NO es de nadie
    # autenticable: se deniega en vez de dejarlo pasar.
    if rol == "paciente":
        duenio = turno["paciente"].get("id_usuario")
        if not duenio or duenio != user["sub"]:
            return jsonify({
                "error": "Acceso denegado: este turno no pertenece a tu ficha de paciente."
            }), 403
        return jsonify({"turno": turno}), 200

    # El personal médico solo accede a los turnos de su propia agenda.
    if rol == "medico":
        profesional, error = _mi_profesional(user)
        if error:
            return error
        if turno["profesional"]["id"] != profesional["id"]:
            return jsonify({
                "error": "Acceso denegado: este turno pertenece a la agenda de otro profesional."
            }), 403

    return jsonify({"turno": turno}), 200

@turnos_bp.route("/<identifier>/atender", methods=["PATCH"])
@jwt_required_custom()
@roles_required("medico", "admin")
def registrar_atencion(identifier):
    """
    Registra que el paciente de un turno fue atendido por el profesional.
    Es la única acción de escritura del personal médico, y solo sobre su propia
    agenda. El turno sigue ocupando su franja y el día del paciente.
    ---
    tags:
      - Turnos
    summary: Marca un turno como 'atendido' (médico o admin)
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
            atendido:
              type: boolean
              default: true
              example: false
              description: false para deshacer y devolver el turno a 'reservado'
    responses:
      200:
        description: Estado de atención actualizado
      401:
        description: Falta autenticación o el token es inválido
      403:
        description: El turno pertenece a la agenda de otro profesional
      404:
        description: Turno no encontrado
    """
    turno = db.get_turno_by_id(identifier)
    if not turno:
        return jsonify({"error": "No se encontró ningún turno con ese identificador."}), 404

    user = g.current_user
    if user.get("role") == "medico":
        profesional, error = _mi_profesional(user)
        if error:
            return error
        if turno["profesional"]["id"] != profesional["id"]:
            return jsonify({
                "error": "Acceso denegado: este turno pertenece a la agenda de otro profesional."
            }), 403

    data = request.get_json(silent=True) or {}
    atendido = data.get("atendido", True)

    turno_actualizado, err = db.marcar_atencion(identifier, bool(atendido))
    if err:
        return jsonify({"error": err}), 400

    return jsonify({
        "mensaje": (
            "Atención registrada correctamente." if atendido
            else "Se deshizo la atención: el turno vuelve a estar reservado."
        ),
        "turno": turno_actualizado
    }), 200

@turnos_bp.route("/<identifier>/cancelar", methods=["PATCH", "POST"])
@jwt_required_custom()
@roles_required("admin")
def cancelar_turno(identifier):
    """
    CU05 — Cancelar Turno (solo personal administrativo).
    Cancela un turno activo. La cancelación es una operación de staff: el paciente
    no puede anular su propia reserva, debe solicitarlo en recepción.
    ---
    tags:
      - Turnos
    summary: Cancela un turno existente (CU05) - requiere rol admin
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
      401:
        description: Falta autenticación o el token es inválido
      403:
        description: Solo un administrador puede cancelar turnos
      404:
        description: Turno no encontrado
    """
    turno = db.get_turno_by_id(identifier)
    if not turno:
        return jsonify({"error": "No se encontró ningún turno con ese identificador."}), 404

    data = request.get_json(silent=True) or {}
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
