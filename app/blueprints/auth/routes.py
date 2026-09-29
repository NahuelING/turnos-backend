from flask import Blueprint, request, jsonify, g, current_app
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from app.schemas.validators import RegistroUsuarioSchema, LoginSchema, CrearUsuarioAdminSchema
from app.middleware.auth import create_access_token, create_refresh_token, decode_token, jwt_required_custom, roles_required
from app.services.db_service import DatabaseService
from app import limiter

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")
db = DatabaseService.get_instance()

@auth_bp.route("/usuarios", methods=["POST"])
@jwt_required_custom()
@roles_required("admin")
def crear_usuario_admin():
    """
    Crea una cuenta con cualquier rol, incluyendo los privilegiados.
    ---
    tags:
      - Autenticación
    summary: Crea un usuario con el rol indicado (solo admin)
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [username, email, password, rol]
          properties:
            username:
              type: string
              example: dra_rojas
            email:
              type: string
              example: marcela.rojas@saludperiurbano.gob.bo
            password:
              type: string
              example: Medico123!
            rol:
              type: string
              enum: [paciente, medico, recepcionista, admin]
    responses:
      201:
        description: Usuario creado exitosamente con el rol solicitado
      400:
        description: Datos inválidos o usuario ya existente
      401:
        description: Falta autenticación
      403:
        description: Se requiere rol de administrador
    """
    data = request.get_json() or {}
    errors = CrearUsuarioAdminSchema().validate(data)
    if errors:
        return jsonify({"error": "Validación fallida", "detalles": errors}), 400

    user, err = db.create_user(
        username=data["username"].strip(),
        email=data["email"].strip().lower(),
        password=data["password"],
        rol_nombre=data["rol"]
    )
    if err:
        return jsonify({"error": err}), 400

    return jsonify({
        "mensaje": "Usuario creado exitosamente por el administrador",
        "usuario": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "rol": user["rol_nombre"]
        }
    }), 201


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Registro de nuevos usuarios en el sistema.
    ---
    tags:
      - Autenticación
    summary: Registra un nuevo usuario con credenciales seguras
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [username, email, password]
          properties:
            username:
              type: string
              example: juan_paciente
            email:
              type: string
              example: juan.perez@correo.bo
            password:
              type: string
              example: Paciente123!
    responses:
      201:
        description: Usuario creado exitosamente con rol 'paciente'
      400:
        description: Datos inválidos o usuario ya existente
      403:
        description: Se intentó asignar un rol privilegiado
    description: >
      Alta de cuentas de PACIENTE, el único rol que puede crearse sin
      intervencion de un administrador. Los roles 'medico', 'recepcionista' y
      'admin' se crean unicamente por un admin autenticado, evitando el
      escalamiento de privilegios (OWASP API5:2023 - Broken Function Level
      Authorization). Si el cuerpo incluye un 'rol', se responde 403 en lugar
      de aceptarlo en silencio, para que el cliente detecte el intento de escalada.
    """
    data = request.get_json() or {}
    schema = RegistroUsuarioSchema()
    errors = schema.validate(data)
    if errors:
        return jsonify({"error": "Validación fallida", "detalles": errors}), 400

    # Bloqueo de escalamiento de privilegios: el registro público es solo de
    # pacientes. Cualquier rol privilegiado requiere un admin autenticado.
    if data.get("rol") and data["rol"] != "paciente":
        return jsonify({
            "error": "El registro público solo permite crear cuentas de paciente.",
            "rol_recibido": data["rol"],
            "roles_permitidos_autoregistro": ["paciente"]
        }), 403

    user, err = db.create_user(
        username=data["username"].strip(),
        email=data["email"].strip().lower(),
        password=data["password"],
        rol_nombre="paciente"
    )
    if err:
        return jsonify({"error": err}), 400

    return jsonify({
        "mensaje": "Usuario registrado exitosamente",
        "usuario": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "rol": user["rol_nombre"]
        }
    }), 201

@auth_bp.route("/login", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_LOGIN"],
               key_func=get_remote_address,
               error_message="Demasiados intentos fallidos. Espera un minuto antes de reintentar.")
def login():
    """
    Autenticación y generación de tokens JWT (Access y Refresh).
    ---
    tags:
      - Autenticación
    summary: Inicia sesión y retorna Access Token y Refresh Token
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [username, password]
          properties:
            username:
              type: string
              example: juan_paciente
            password:
              type: string
              example: Paciente123!
    responses:
      200:
        description: Autenticación exitosa
      401:
        description: Credenciales incorrectas
    """
    data = request.get_json() or {}
    schema = LoginSchema()
    errors = schema.validate(data)
    if errors:
        return jsonify({"error": "Validación fallida", "detalles": errors}), 400

    user = db.get_user_by_username_or_email(data["username"].strip())
    if not user or not check_password_hash(user["password_hash"], data["password"]):
        return jsonify({"error": "Credenciales inválidas. Verifique su usuario y contraseña."}), 401

    # Obtener IDs vinculados si es paciente o profesional médico
    paciente = db.get_paciente_by_user_id(user["id"])
    profesional = db.get_profesional_by_user_id(user["id"])

    paciente_id = paciente["id"] if paciente else None
    profesional_id = profesional["id"] if profesional else None

    access_token = create_access_token(
        user_id=user["id"],
        username=user["username"],
        email=user["email"],
        role=user["rol_nombre"],
        paciente_id=paciente_id,
        profesional_id=profesional_id
    )
    refresh_token = create_refresh_token(user["id"])

    return jsonify({
        "mensaje": "Autenticación satisfactoria",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "usuario": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "rol": user["rol_nombre"],
            "paciente": paciente,
            "profesional": profesional
        }
    }), 200

@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    """
    Renueva el Access Token utilizando un Refresh Token válido.
    ---
    tags:
      - Autenticación
    summary: Rotación de Access Token
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [refresh_token]
          properties:
            refresh_token:
              type: string
    responses:
      200:
        description: Nuevo Access Token emitido
      401:
        description: Refresh token inválido o expirado
    """
    data = request.get_json() or {}
    token = data.get("refresh_token")
    if not token:
        return jsonify({"error": "El campo refresh_token es obligatorio"}), 400

    payload, err = decode_token(token, expected_type="refresh")
    if err:
        return jsonify({"error": err}), 401

    user = db.get_user_by_id(payload["sub"])
    if not user:
        return jsonify({"error": "Usuario ya no existe o está inactivo"}), 401

    paciente = db.get_paciente_by_user_id(user["id"])
    profesional = db.get_profesional_by_user_id(user["id"])

    new_access_token = create_access_token(
        user_id=user["id"],
        username=user["username"],
        email=user["email"],
        role=user["rol_nombre"],
        paciente_id=paciente["id"] if paciente else None,
        profesional_id=profesional["id"] if profesional else None
    )

    return jsonify({
        "access_token": new_access_token,
        "token_type": "Bearer"
    }), 200

@auth_bp.route("/me", methods=["GET"])
@jwt_required_custom()
def me():
    """
    Retorna la información del usuario autenticado desde el JWT claim.
    ---
    tags:
      - Autenticación
    summary: Consulta el perfil del usuario actual
    security:
      - BearerAuth: []
    responses:
      200:
        description: Perfil del usuario
      401:
        description: Token ausente o inválido
    """
    user_id = g.current_user["sub"]
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    paciente = db.get_paciente_by_user_id(user_id)
    profesional = db.get_profesional_by_user_id(user_id)
    return jsonify({
        "usuario": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "rol": user["rol_nombre"],
            "paciente": paciente,
            "profesional": profesional
        }
    }), 200
