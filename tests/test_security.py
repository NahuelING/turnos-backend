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

def test_ataque_sql_injection_en_turnos(client, token_admin):
    """
    Intento de inyección de cláusula UNION SELECT o bypass en el código de turno.
    Se envía con sesión para que la prueba alcance la consulta y no se detenga en
    el control de autenticación.
    """
    headers = {"Authorization": f"Bearer {token_admin}"}
    payloads = [
        "TUR-00000' UNION SELECT * FROM usuarios --",
        "TUR-00000' OR '1'='1",
        "' OR 1=1 --",
    ]
    for payload in payloads:
        res = client.get(f"/api/v1/turnos/{payload}", headers=headers)
        assert res.status_code in [400, 404], f"payload {payload!r} -> {res.status_code}"
        # Nunca debe devolver filas de 'usuarios' ni un 200 con datos
        assert "password_hash" not in res.get_data(as_text=True)

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
    # Fecha distinta a la del test anterior: la regla de un turno por día impide
    # que el mismo paciente tenga dos turnos reservados en la misma fecha.
    turno_p1, _ = db.create_turno(
        id_paciente=paciente_1["id"],
        id_profesional="PRF-001",
        fecha="2026-10-11",
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
# 6. AISLAMIENTO DE LA AGENDA DEL PROFESIONAL MÉDICO
# ==============================================================================
def test_medico_solo_ve_su_propia_agenda(client, db):
    """
    Cada profesional médico debe ver únicamente los turnos de los pacientes que tiene
    asignados, nunca los de otro colega.
    """
    headers_rojas = client.post("/api/v1/auth/login", json={
        "username": "dra_rojas", "password": "Medico123!"
    }).get_json()
    headers_fernandez = client.post("/api/v1/auth/login", json={
        "username": "dr_fernandez", "password": "Medico123!"
    }).get_json()
    assert headers_rojas["usuario"]["profesional"]["idProfesional"] == "PRF-001"
    assert headers_fernandez["usuario"]["profesional"]["idProfesional"] == "PRF-002"

    # Cada profesional tiene su propio paciente en la misma fecha
    paciente_1 = db.get_paciente_by_ci("8452136 SC")
    paciente_2, _ = db.create_paciente("Sofia", "Gutierrez", "4455667 TR",
                                       "70556677", "sofia.gutierrez@correo.bo")
    t_rojas, _ = db.create_turno(paciente_1["id"], "PRF-001", "2026-10-20", "08:00",
                                ["08:00", "09:00", "10:00"])
    t_fernandez, _ = db.create_turno(paciente_2["id"], "PRF-002", "2026-10-20", "09:00",
                                      ["08:00", "09:00", "10:00"])
    assert t_rojas and t_fernandez

    # La Dra. Rojas solo ve el suyo
    res = client.get("/api/v1/turnos", headers={"Authorization": f"Bearer {headers_rojas['access_token']}"})
    assert res.status_code == 200
    codigos = {t["idTurno"] for t in res.get_json()["turnos"]}
    assert t_rojas["idTurno"] in codigos
    assert t_fernandez["idTurno"] not in codigos

    # Y no puede abrir el turno del colega por identificador
    res = client.get(f"/api/v1/turnos/{t_fernandez['idTurno']}",
                     headers={"Authorization": f"Bearer {headers_rojas['access_token']}"})
    assert res.status_code == 403

def test_medico_es_solo_lectura(client, db):
    """
    El personal médico no registra turnos, no cancela y no accede al padrón
    general de pacientes.
    """
    token = client.post("/api/v1/auth/login", json={
        "username": "dra_rojas", "password": "Medico123!"
    }).get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # No puede registrar turnos
    res = client.post("/api/v1/turnos", headers=headers, json={
        "ci": "8452136 SC", "id_profesional": "PRF-001",
        "fecha": "2026-10-21", "hora": "11:00"
    })
    assert res.status_code == 403

    # No puede cancelar
    res = client.patch("/api/v1/turnos/TUR-00000/cancelar", headers=headers, json={})
    assert res.status_code in (403, 404)
    assert res.status_code == 403

    # No puede listar el padrón general de pacientes
    res = client.get("/api/v1/pacientes", headers=headers)
    assert res.status_code == 403

    # No puede consultar una ficha de paciente por identificador
    ficha = db.get_paciente_by_ci("8452136 SC")
    res = client.get(f"/api/v1/pacientes/{ficha['id']}", headers=headers)
    assert res.status_code == 403

# ==============================================================================
# 7. REGISTRO DE ATENCIÓN DEL PACIENTE
# ==============================================================================
def test_medico_registra_atencion_de_su_turno(client, db):
    """
    El médico marca como atendido un turno de su propia agenda. El turno sigue
    ocupando su franja: la atención no libera el horario ni el día del paciente.
    """
    token = client.post("/api/v1/auth/login", json={
        "username": "dra_rojas", "password": "Medico123!"
    }).get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    paciente, _ = db.create_paciente("Rita", "Salazar", "3344556 CB",
                                    "70445566", "rita.salazar@correo.bo")
    turno, err = db.create_turno(paciente["id"], "PRF-001", "2026-10-30", "08:00",
                                 ["08:00", "09:00", "10:00"])
    assert turno and not err

    # Marcar como atendido
    res = client.patch(f"/api/v1/turnos/{turno['idTurno']}/atender", headers=headers, json={})
    assert res.status_code == 200
    assert res.get_json()["turno"]["estado"] == "atendido"

    # El horario sigue ocupado: la disponibilidad no lo ofrece de nuevo
    disp = client.get("/api/v1/disponibilidad?id_profesional=PRF-001&fecha=2026-10-30").get_json()
    assert "08:00" not in disp["horarios_disponibles"]
    assert "08:00" in disp["horarios_ocupados"]

    # El paciente no puede pedir otro turno ese mismo día
    otro, err = db.create_turno(paciente["id"], "PRF-002", "2026-10-30", "15:00",
                                ["08:00", "09:00", "10:00", "15:00"])
    assert otro is None
    assert "un turno por dia" in err

    # Pero sí puede pedir ese mismo horario en otro día
    manana, err = db.create_turno(paciente["id"], "PRF-001", "2026-10-31", "08:00",
                                  ["08:00", "09:00", "10:00", "15:00"])
    assert manana and not err

    # Deshacer la atención devuelve el turno a 'reservado'
    res = client.patch(f"/api/v1/turnos/{turno['idTurno']}/atender", headers=headers,
                       json={"atendido": False})
    assert res.status_code == 200
    assert res.get_json()["turno"]["estado"] == "reservado"

def test_atencion_limitada_a_la_agenda_del_medico(client, db):
    """
    Ningún otro rol puede registrar atención, y un médico no puede marcar el turno
    de un colega ni el de un paciente ajeno.
    """
    headers_rojas = {"Authorization": "Bearer " + client.post("/api/v1/auth/login", json={
        "username": "dra_rojas", "password": "Medico123!"
    }).get_json()["access_token"]}
    headers_fernandez = {"Authorization": "Bearer " + client.post("/api/v1/auth/login", json={
        "username": "dr_fernandez", "password": "Medico123!"
    }).get_json()["access_token"]}

    paciente, _ = db.create_paciente("Hugo", "Salcedo", "2233445 SC",
                                    "70334455", "hugo.salcedo@correo.bo")
    t_rojas, _ = db.create_turno(paciente["id"], "PRF-001", "2026-11-05", "10:00",
                                 ["08:00", "09:00", "10:00"])

    # Fernández intenta marcar un turno de Rojas
    res = client.patch(f"/api/v1/turnos/{t_rojas['idTurno']}/atender",
                       headers=headers_fernandez, json={})
    assert res.status_code == 403

    # Un paciente no puede marcar su propio turno como atendido
    token_paciente = client.post("/api/v1/auth/login", json={
        "username": "juan.perez@correo.bo", "password": "Paciente123!"
    }).get_json()["access_token"]
    t_paciente, _ = db.create_turno(paciente["id"], "PRF-002", "2026-11-06", "10:00",
                                    ["08:00", "09:00", "10:00"])
    res = client.patch(f"/api/v1/turnos/{t_paciente['idTurno']}/atender",
                       headers={"Authorization": f"Bearer {token_paciente}"}, json={})
    assert res.status_code == 403

    # Sin token tampoco
    res = client.patch(f"/api/v1/turnos/{t_rojas['idTurno']}/atender", json={})
    assert res.status_code == 401

    # Rojas sí puede marcar el suyo
    res = client.patch(f"/api/v1/turnos/{t_rojas['idTurno']}/atender",
                       headers=headers_rojas, json={})
    assert res.status_code == 200

def test_registro_publico_no_permite_escalar_a_admin(client):
    """
    El registro público es una vía de escalamiento de privilegios si acepta un
    'rol' del cuerpo. Solo puede crear pacientes; los roles privilegiados
    requieren un admin autenticado (OWASP API5:2023).
    """
    for rol in ("admin", "medico", "recepcionista"):
        res = client.post("/api/v1/auth/register", json={
            "username": f"escalado_{rol}", "email": f"escalado_{rol}@evil.com",
            "password": "Malicioso123!", "rol": rol,
        })
        assert res.status_code == 403, f"rol={rol} deberia ser rechazado"
        assert res.get_json()["rol_recibido"] == rol

    # Y el atacante no puede autenticarse con la cuenta que intentaba crear
    res = client.post("/api/v1/auth/login", json={
        "username": "escalado_admin", "password": "Malicioso123!"})
    assert res.status_code == 401

    # El registro sin 'rol' sigue creando pacientes
    res = client.post("/api/v1/auth/register", json={
        "username": "paciente_ok", "email": "paciente_ok@correo.bo",
        "password": "Paciente123!"})
    assert res.status_code == 201
    assert res.get_json()["usuario"]["rol"] == "paciente"

def test_admin_puede_crear_usuarios_con_rol_privilegiado(client):
    """La alta de médicos y admins sí existe, pero detrás de autenticación admin."""
    token = client.post("/api/v1/auth/login", json={
        "username": "admin_salud", "password": "Admin123!"
    }).get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/v1/auth/usuarios", headers=headers, json={
        "username": "medico_nuevo", "email": "medico_nuevo@salud.gob.bo",
        "password": "Medico123!", "rol": "medico"})
    assert res.status_code == 201
    assert res.get_json()["usuario"]["rol"] == "medico"

    # Un paciente no puede usar esa vía
    tok_pac = client.post("/api/v1/auth/login", json={
        "username": "juan.perez@correo.bo", "password": "Paciente123!"
    }).get_json()["access_token"]
    res = client.post("/api/v1/auth/usuarios",
                      headers={"Authorization": f"Bearer {tok_pac}"},
                      json={"username": "otro_admin", "email": "otro@x.com",
                            "password": "Malicioso123!", "rol": "admin"})
    assert res.status_code == 403

    # Sin token tampoco
    res = client.post("/api/v1/auth/usuarios", json={
        "username": "otro_admin", "email": "otro@x.com",
        "password": "Malicioso123!", "rol": "admin"})
    assert res.status_code == 401

def test_agenda_nunca_se_expone_sin_autenticacion(client):
    """
    La agenda completa es un dato sensible: nombre, CI y hora de cada paciente.
    Sin token no puede devolverse, ni siquiera filtrando por CI.
    (OWASP API5:2023 - sin esto la API 'expone endpoints').
    """
    for url in ("/api/v1/turnos", "/api/v1/turnos?ci=8452136 SC"):
        res = client.get(url)
        assert res.status_code == 401, f"{url} permitio acceso anonimo"
        assert "turnos" not in res.get_json()

    # Tampoco alcanza con inventar un token
    res = client.get("/api/v1/turnos", headers={"Authorization": "Bearer token-falso"})
    assert res.status_code == 401

def test_paciente_sin_ficha_no_ve_la_agenda_ajena(client, db):
    """
    Una cuenta de paciente sin ficha vinculada debe fallar en CERRADO: devolver
    una lista vacía. Antes caia en la consulta general y exponia los turnos de
    todos los pacientes.
    """
    # Cuenta huérfana: usuario sin fila en 'pacientes'
    db.create_user("huerfano_01", "huerfano@correo.bo", "Paciente123!", "paciente")
    token = client.post("/api/v1/auth/login", json={
        "username": "huerfano_01", "password": "Paciente123!"}).get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Hay turnos de otros pacientes en la base de pruebas
    otro, _ = db.create_paciente("Rocio", "Medina", "7788990 SC",
                                 "70112233", "rocio.medina@correo.bo")
    db.create_turno(otro["id"], "PRF-001", "2026-12-10", "08:00",
                    ["08:00", "09:00", "10:00"])

    res = client.get("/api/v1/turnos", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["turnos"] == []
    assert res.get_json()["total"] == 0

    # Tampoco puede filtrar por el CI de otro paciente
    res = client.get("/api/v1/turnos?ci=7788990%20SC", headers=headers)
    assert res.get_json()["turnos"] == []

    # Y no puede buscar el turno ajeno por código
    ajeno, _err = db.create_turno(otro["id"], "PRF-002", "2026-12-12", "11:00",
                                  ["08:00", "09:00", "10:00", "11:00"])
    res = client.get(f"/api/v1/turnos/{ajeno['idTurno']}", headers=headers)
    assert res.status_code == 403

def test_paciente_solo_ve_sus_propios_turnos(client, db):
    """El filtro por CI del cliente se ignora: manda la identidad del token."""
    token = client.post("/api/v1/auth/login", json={
        "username": "juan.perez@correo.bo", "password": "Paciente123!"
    }).get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Turno de otro paciente en la misma fecha
    otro, _ = db.create_paciente("Elena", "Cruz", "6655443 SC",
                                 "70115566", "elena.cruz@correo.bo")
    db.create_turno(otro["id"], "PRF-001", "2026-12-11", "10:00",
                    ["08:00", "09:00", "10:00"])

    res = client.get("/api/v1/turnos", headers=headers)
    cis = {t["paciente"]["ci"] for t in res.get_json()["turnos"]}
    assert "6655443 SC" not in cis, "el paciente vio turnos ajenos"

    # Pedir explícitamente la CI ajena devuelve solo los suyos
    res = client.get("/api/v1/turnos?ci=6655443%20SC", headers=headers)
    cias = {t["paciente"]["ci"] for t in res.get_json()["turnos"]}
    assert "6655443 SC" not in cias

# ==============================================================================
# 7. CABECERAS DE SEGURIDAD HTTP (OWASP ASVS)
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
