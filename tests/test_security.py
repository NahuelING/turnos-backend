import pytest
from app import create_app
from app.services.db_service import DatabaseService
from app.middleware.auth import create_access_token

@pytest.fixture
def app():
    app = create_app("testing")
    return app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def db():
    return DatabaseService.get_instance()

@pytest.fixture
def token_admin(app):
    with app.app_context():
        return create_access_token(
            user_id="a0000000-0000-0000-0000-000000000001",
            username="admin_salud",
            email="admin@saludperiurbano.gob.bo",
            role="admin"
        )

@pytest.fixture
def token_paciente_1(app, db):
    with app.app_context():
        user = db.get_user_by_username_or_email("juan_paciente")
        paciente = db.get_paciente_by_user_id(user["id"])
        return create_access_token(
            user_id=user["id"],
            username=user["username"],
            email=user["email"],
            role="paciente",
            paciente_id=paciente["id"] if paciente else None
        )

@pytest.fixture
def token_paciente_2(app, db):
    with app.app_context():
        user = db.get_user_by_username_or_email("maria_paciente")
        if not user:
            user, _ = db.create_user("maria_paciente", "maria@correo.bo", "Paciente456!", "paciente")
            p2, _ = db.create_paciente("María", "Mamani", "7654321 LP", "71122334", "maria@correo.bo", id_usuario=user["id"])
        else:
            p2 = db.get_paciente_by_user_id(user["id"])

        return create_access_token(
            user_id=user["id"],
            username=user["username"],
            email=user["email"],
            role="paciente",
            paciente_id=p2["id"] if p2 else None
        )

# ==============================================================================
# 1. ATAQUE 1: Inyección SQL (OWASP A03 / API3)
# ==============================================================================
def test_ataque_sql_injection_en_busqueda_paciente(client):
    """
    Intento de SQL Injection en el parámetro CI de búsqueda de paciente.
    Debe fallar limpiamente o retornar 404/400 sin filtrar otros registros.
    """
    payload_malicioso = "' OR '1'='1' --"
    res = client.get(f"/api/v1/pacientes?ci={payload_malicioso}")
    # Debe retornar 404 (no encontrado) o 400, nunca 200 con registros indebidos
    assert res.status_code in [400, 404]

def test_ataque_sql_injection_en_turnos(client):
    """
    Intento de inyección de cláusula UNION SELECT o bypass en el código de turno.
    """
    payload = "TUR-00000' UNION SELECT * FROM usuarios --"
    res = client.get(f"/api/v1/turnos/{payload}")
    assert res.status_code in [400, 404]

# ==============================================================================
# 2. ATAQUE 2: Broken Object Level Authorization (BOLA / IDOR / OWASP API1:2023)
# ==============================================================================
def test_ataque_bola_consultar_turno_ajeno(client, db, token_paciente_1, token_paciente_2):
    """
    Paciente 2 intenta consultar el turno privado del Paciente 1.
    El sistema debe denegar el acceso con 403 Forbidden.
    """
    # 1. Reservar un turno para Paciente 1
    paciente_1 = db.get_paciente_by_ci("8452136 SC")
    turno_p1, _ = db.create_turno(
        id_paciente=paciente_1["id"],
        id_profesional="PRF-001",
        fecha="2026-10-10",
        hora="08:00",
        horas_jornada=["08:00", "09:00"]
    )

    # 2. Paciente 2 intenta consultar el turno de Paciente 1 pasando su token
    headers_p2 = {"Authorization": f"Bearer {token_paciente_2}"}
    res = client.get(f"/api/v1/turnos/{turno_p1['idTurno']}", headers=headers_p2)
    assert res.status_code == 403
    assert "Acceso denegado" in res.get_json()["error"]

def test_ataque_bola_cancelar_turno_ajeno(client, db, token_paciente_2):
    """
    Paciente 2 intenta cancelar el turno del Paciente 1.
    El sistema debe bloquear la cancelación maliciosa con 403 Forbidden.
    """
    paciente_1 = db.get_paciente_by_ci("8452136 SC")
    turno_p1, _ = db.create_turno(
        id_paciente=paciente_1["id"],
        id_profesional="PRF-001",
        fecha="2026-10-10",
        hora="09:00",
        horas_jornada=["08:00", "09:00"]
    )

    headers_p2 = {"Authorization": f"Bearer {token_paciente_2}"}
    res = client.patch(f"/api/v1/turnos/{turno_p1['idTurno']}/cancelar", headers=headers_p2)
    assert res.status_code == 403
    assert "Acceso denegado" in res.get_json()["error"]

# ==============================================================================
# 3. ATAQUE 3: Broken Authentication (OWASP API2:2023)
# ==============================================================================
def test_ataque_token_jwt_manipulado(client):
    """
    Intento de enviar un token JWT con firma modificada o manipulada.
    """
    token_falso = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvY2tlciJ9.invalidSignatureABC123"
    headers = {"Authorization": f"Bearer {token_falso}"}
    res = client.get("/api/v1/auth/me", headers=headers)
    assert res.status_code == 401

def test_ataque_token_sin_cabecera(client):
    """
    Intento de acceder a un recurso protegido sin credenciales.
    """
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401

# ==============================================================================
# 4. ATAQUE 4: Broken Function Level Authorization (BFLA / OWASP API5:2023)
# ==============================================================================
def test_ataque_bfla_paciente_intentando_listar_todos_los_pacientes(client, token_paciente_1):
    """
    Un paciente autenticado intenta descargar todo el padrón de pacientes del centro.
    El sistema debe denegarlo con 403 Forbidden.
    """
    headers = {"Authorization": f"Bearer {token_paciente_1}"}
    res = client.get("/api/v1/pacientes", headers=headers)
    assert res.status_code == 403

def test_admin_puede_listar_pacientes(client, token_admin):
    """
    Un administrador autenticado sí cuenta con permisos para listar los pacientes.
    """
    headers = {"Authorization": f"Bearer {token_admin}"}
    res = client.get("/api/v1/pacientes", headers=headers)
    assert res.status_code == 200
    assert "pacientes" in res.get_json()

# ==============================================================================
# 5. ATAQUE 5: Doble Reserva Concurrente (Race Condition / Integridad)
# ==============================================================================
def test_prevencion_doble_reserva_mismo_horario(client):
    """
    Intento de reservar dos veces exactamente el mismo horario con el mismo profesional.
    El segundo intento debe ser rechazado con 409 Conflict.
    """
    payload = {
        "ci": "8452136 SC",
        "id_profesional": "PRF-002",
        "fecha": "2026-10-15",
        "hora": "10:00"
    }

    # Primera reserva -> 201 Created
    res1 = client.post("/api/v1/turnos", json=payload)
    assert res1.status_code == 201

    # Segunda reserva idéntica -> 409 Conflict
    res2 = client.post("/api/v1/turnos", json=payload)
    assert res2.status_code == 409
    assert "no disponible" in res2.get_json()["error"]

# ==============================================================================
# 6. CABECERAS DE SEGURIDAD HTTP (OWASP ASVS)
# ==============================================================================
def test_cabeceras_http_seguridad(client):
    """
    Verifica que la API inyecte las cabeceras recomendadas por OWASP ASVS v4.0.
    """
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "Strict-Transport-Security" in res.headers
    assert "Content-Security-Policy" in res.headers
