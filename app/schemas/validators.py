import re
from marshmallow import Schema, fields, validate, validates, ValidationError

# Expresiones regulares auditadas correspondientes al frontend del centro de salud periurbano
REGEX_NOMBRE = r"^[A-Za-zÀ-ÖØ-öø-ÿÑñ\s]{2,40}$"
REGEX_CI = r"^\d{5,9}(\s?[A-Z]{2})?$"
REGEX_TELEFONO = r"^[67]\d{7}$"
REGEX_CORREO = r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$"
REGEX_HORA = r"^(08|09|10|11|14|15|16):00$"

def sanitizar_string(valor):
    if not isinstance(valor, str):
        return valor
    # Quitar espacios laterales y prevenir inyección de caracteres de control
    limpio = valor.strip()
    return limpio

class CrearUsuarioAdminSchema(Schema):
    """Alta de usuarios por parte de un administrador (roles privilegiados)."""
    username = fields.String(
        required=True,
        validate=validate.Length(min=3, max=40),
        error_messages={"required": "El nombre de usuario es obligatorio."}
    )
    email = fields.Email(
        required=True,
        error_messages={"required": "El correo electrónico es obligatorio.", "invalid": "Correo electrónico inválido."}
    )
    password = fields.String(
        required=True,
        validate=validate.Length(min=8, max=64),
        error_messages={"required": "La contraseña es obligatoria y debe tener al menos 8 caracteres."}
    )
    rol = fields.String(
        required=True,
        validate=validate.OneOf(
            ["paciente", "medico", "recepcionista", "admin"],
            error="Rol no válido. Roles admitidos: paciente, medico, recepcionista, admin."
        )
    )

class RegistroUsuarioSchema(Schema):
    username = fields.String(
        required=True,
        validate=validate.Length(min=3, max=40),
        error_messages={"required": "El nombre de usuario es obligatorio."}
    )
    email = fields.Email(
        required=True,
        error_messages={"required": "El correo electrónico es obligatorio.", "invalid": "Correo electrónico inválido."}
    )
    password = fields.String(
        required=True,
        validate=validate.Length(min=8, max=64),
        error_messages={"required": "La contraseña es obligatoria y debe tener al menos 8 caracteres."}
    )
    rol = fields.String(
        load_default="paciente",
        validate=validate.OneOf(["paciente", "medico", "recepcionista", "admin"])
    )

class LoginSchema(Schema):
    username = fields.String(required=True, error_messages={"required": "El usuario o email es obligatorio."})
    password = fields.String(required=True, error_messages={"required": "La contraseña es obligatoria."})

class PacienteSchema(Schema):
    nombre = fields.String(
        required=True,
        error_messages={"required": "El nombre es obligatorio."}
    )
    apellido = fields.String(
        required=True,
        error_messages={"required": "El apellido es obligatorio."}
    )
    CI = fields.String(
        required=True,
        error_messages={"required": "El CI es obligatorio."}
    )
    telefono = fields.String(
        required=True,
        error_messages={"required": "El teléfono es obligatorio."}
    )
    correo = fields.String(
        required=True,
        error_messages={"required": "El correo es obligatorio."}
    )

    @validates("nombre")
    def validar_nombre(self, value):
        v = sanitizar_string(value)
        if not re.match(REGEX_NOMBRE, v):
            raise ValidationError("Usa solo letras y espacios (2 a 40 caracteres).")

    @validates("apellido")
    def validar_apellido(self, value):
        v = sanitizar_string(value)
        if not re.match(REGEX_NOMBRE, v):
            raise ValidationError("Usa solo letras y espacios (2 a 40 caracteres).")

    @validates("CI")
    def validar_ci(self, value):
        v = sanitizar_string(value)
        if not re.match(REGEX_CI, v):
            raise ValidationError("Formato de CI inválido. Ejemplo: 8452136 o 8452136 SC.")

    @validates("telefono")
    def validar_telefono(self, value):
        v = sanitizar_string(value)
        if not re.match(REGEX_TELEFONO, v):
            raise ValidationError("Ingresa un celular boliviano válido de 8 dígitos (inicia en 6 o 7).")

    @validates("correo")
    def validar_correo(self, value):
        v = sanitizar_string(value)
        if not re.match(REGEX_CORREO, v):
            raise ValidationError("Ingresa un correo electrónico válido.")

class DisponibilidadQuerySchema(Schema):
    id_profesional = fields.String(
        required=True,
        error_messages={"required": "El parámetro id_profesional es obligatorio."}
    )
    fecha = fields.Date(
        required=True,
        format="%Y-%m-%d",
        error_messages={"required": "El parámetro fecha es obligatorio en formato YYYY-MM-DD."}
    )

class ReservarTurnoSchema(Schema):
    id_paciente = fields.String(
        required=False,
        allow_none=True
    )
    ci = fields.String(
        required=False,
        allow_none=True
    )
    id_profesional = fields.String(
        required=True,
        error_messages={"required": "Elige un profesional."}
    )
    fecha = fields.Date(
        required=True,
        format="%Y-%m-%d",
        error_messages={"required": "Elige una fecha válida (YYYY-MM-DD)."}
    )
    hora = fields.String(
        required=True,
        validate=validate.OneOf(
            ["08:00", "09:00", "10:00", "11:00", "14:00", "15:00", "16:00"],
            error="El horario debe ser una de las franjas hábiles: 08:00, 09:00, 10:00, 11:00, 14:00, 15:00, 16:00."
        ),
        error_messages={"required": "Elige un horario."}
    )

    @validates("ci")
    def validar_ci_opcional(self, value):
        if value:
            v = sanitizar_string(value)
            if not re.match(REGEX_CI, v):
                raise ValidationError("Formato de CI inválido.")

class CancelarTurnoSchema(Schema):
    motivo = fields.String(
        required=False,
        validate=validate.Length(max=200),
        load_default="Cancelado por el usuario"
    )
