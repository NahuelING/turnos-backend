from flask import Blueprint, request, jsonify, g
from app.schemas.validators import PacienteSchema
from app.middleware.auth import jwt_required_custom, roles_required
from app.services.db_service import DatabaseService

pacientes_bp = Blueprint("pacientes", __name__, url_prefix="/api/v1/pacientes")
db = DatabaseService.get_instance()

@pacientes_bp.route("", methods=["POST"])
@jwt_required_custom(optional=True)
def create_paciente():
    """
    CU01 — Registrar Paciente.
    Permite registrar la ficha médica de un paciente en el sistema.
    ---
    tags:
      - Pacientes
    summary: Registra un nuevo paciente en el centro de salud (CU01)
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [nombre, apellido, CI, telefono, correo]
          properties:
            nombre:
              type: string
              example: Marcela
            apellido:
              type: string
              example: Rojas
            CI:
              type: string
              example: 8452136 SC
            telefono:
              type: string
              example: 70011122
            correo:
              type: string
              example: marcela.rojas@correo.bo
    responses:
      201:
        description: Paciente registrado exitosamente
      400:
        description: Datos inválidos o CI duplicado
    """
    data = request.get_json() or {}
    schema = PacienteSchema()
    errors = schema.validate(data)
    if errors:
        return jsonify({"error": "Error de validación", "detalles": errors}), 400

    user_id = g.current_user["sub"] if hasattr(g, "current_user") and g.current_user else None

    paciente, err = db.create_paciente(
        nombre=data["nombre"],
        apellido=data["apellido"],
        ci=data["CI"],
        telefono=data["telefono"],
        correo=data["correo"],
        id_usuario=user_id
    )
    if err:
        return jsonify({"error": err}), 400

    return jsonify({
        "mensaje": f"Paciente registrado: {paciente['nombre']} {paciente['apellido']} (CI {paciente['ci']})",
        "paciente": paciente
    }), 201

@pacientes_bp.route("", methods=["GET"])
@jwt_required_custom(optional=True)
def get_pacientes():
    """
    Búsqueda y listado de pacientes.
    Permite buscar por CI (usado en CU03/CU04) o listar si es personal autorizado.
    ---
    tags:
      - Pacientes
    summary: Busca un paciente por CI o lista pacientes
    parameters:
      - in: query
        name: ci
        type: string
        description: Cédula de Identidad a buscar
        example: 8452136 SC
    responses:
      200:
        description: Paciente encontrado o listado
      404:
        description: No existe paciente con ese CI
    """
    ci = request.args.get("ci")
    if ci:
        paciente = db.get_paciente_by_ci(ci)
        if not paciente:
            return jsonify({"error": "No existe un paciente registrado con ese CI."}), 404
        return jsonify({"paciente": paciente}), 200

    # Si no se pasó CI, listar pacientes (restringido a staff/médicos para evitar data leaks)
    user = getattr(g, "current_user", None)
    # El personal médico NO accede al padrón general: solo ve los pacientes que
    # tienen turno con él, a través de su propia agenda.
    if not user or user.get("role") not in ["admin", "recepcionista"]:
        return jsonify({
            "error": "Para consultar el padrón general de pacientes debe autenticarse con rol administrativo o de recepción."
        }), 403

    limit = min(int(request.args.get("limit", 50)), 100)
    offset = int(request.args.get("offset", 0))
    pacientes = db.list_pacientes(limit=limit, offset=offset)
    return jsonify({
        "total": len(pacientes),
        "pacientes": pacientes
    }), 200

@pacientes_bp.route("/<identifier>", methods=["GET"])
@jwt_required_custom()
def get_paciente_by_id(identifier):
    """
    Consulta de ficha médica de paciente con protección estricta contra BOLA / IDOR.
    ---
    tags:
      - Pacientes
    summary: Consulta la ficha de un paciente específico
    parameters:
      - in: path
        name: identifier
        required: true
        type: string
    responses:
      200:
        description: Detalle del paciente
      403:
        description: No tiene permiso para consultar datos de otro paciente
      404:
        description: Paciente no encontrado
    """
    paciente = db.get_paciente_by_id(identifier)
    if not paciente:
        return jsonify({"error": "Paciente no encontrado"}), 404

    # DEFENSA CONTRA BOLA / IDOR (OWASP API1:2023)
    user = g.current_user
    # El paciente solo puede ver su propia ficha
    if user.get("role") == "paciente":
        if paciente["id_usuario"] != user["sub"]:
            return jsonify({"error": "Acceso denegado: no puede acceder al expediente de otro paciente"}), 403

    # El personal médico no consulta fichas por identificador: accede únicamente a
    # los datos de sus propios pacientes a través de su agenda.
    if user.get("role") == "medico":
        return jsonify({
            "error": "Acceso denegado: consulte la agenda de sus pacientes."
        }), 403

    return jsonify({"paciente": paciente}), 200

