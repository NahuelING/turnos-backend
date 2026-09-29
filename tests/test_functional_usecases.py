import pytest
from app import create_app
from app.middleware.auth import create_access_token
from app.services.db_service import DatabaseService

@pytest.fixture
def app():
    return create_app("testing")

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

def test_cu01_registrar_paciente(client):
    """
    CU01 — Registrar paciente con validaciones de negocio bolivianas.
    """
    payload = {
        "nombre": "Carlos",
        "apellido": "Alvarez",
        "CI": "6123456 LP",
        "telefono": "78899001",
        "correo": "carlos.alvarez@salud.bo"
    }
    res = client.post("/api/v1/pacientes", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert "paciente" in data
    assert data["paciente"]["nombre"] == "Carlos"
    assert data["paciente"]["ci"] == "6123456 LP"

def test_cu02_consultar_disponibilidad(client):
    """
    CU02 — Consultar franjas horarias disponibles para un profesional en una fecha.
    """
    res = client.get("/api/v1/disponibilidad?id_profesional=PRF-001&fecha=2026-11-20")
    assert res.status_code == 200
    data = res.get_json()
    assert "horarios_disponibles" in data
    assert len(data["horarios_disponibles"]) > 0
    assert "08:00" in data["horarios_disponibles"]

def test_cu03_reservar_turno(client):
    """
    CU03 — Reservar turno exitosamente para un paciente registrado.
    """
    payload = {
        "ci": "8452136 SC",
        "id_profesional": "PRF-003",
        "fecha": "2026-11-20",
        "hora": "14:00"
    }
    res = client.post("/api/v1/turnos", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert "turno" in data
    assert data["turno"]["fecha"] == "2026-11-20"
    assert data["turno"]["hora"] == "14:00"

    # Verificar que el horario 14:00 ya no figure en la disponibilidad (CU02)
    disp_res = client.get("/api/v1/disponibilidad?id_profesional=PRF-003&fecha=2026-11-20")
    disp_data = disp_res.get_json()
    assert "14:00" not in disp_data["horarios_disponibles"]

def test_cu03_un_turno_por_dia(client, token_admin):
    """
    CU03 — Regla de negocio: un paciente no puede registrar un segundo turno
    el mismo día, aunque sea en otro horario y con otro profesional.
    """
    # Paciente propio para no depender del estado compartido de otros tests
    alta = client.post("/api/v1/pacientes", json={
        "nombre": "Lucia",
        "apellido": "Mamani",
        "CI": "7788990 CB",
        "telefono": "70112233",
        "correo": "lucia.mamani@correo.bo"
    })
    assert alta.status_code == 201
    ci = alta.get_json()["paciente"]["ci"]

    # 1. Primer turno del día: se permite
    primero = client.post("/api/v1/turnos", json={
        "ci": ci,
        "id_profesional": "PRF-001",
        "fecha": "2026-12-01",
        "hora": "09:00"
    })
    assert primero.status_code == 201

    # 2. Segundo turno del mismo día, otro horario y otro profesional: se rechaza
    segundo = client.post("/api/v1/turnos", json={
        "ci": ci,
        "id_profesional": "PRF-002",
        "fecha": "2026-12-01",
        "hora": "15:00"
    })
    assert segundo.status_code == 409
    assert "un turno por dia" in segundo.get_json()["error"]

    # 3. Al día siguiente sí se puede volver a reservar
    siguiente = client.post("/api/v1/turnos", json={
        "ci": ci,
        "id_profesional": "PRF-002",
        "fecha": "2026-12-02",
        "hora": "15:00"
    })
    assert siguiente.status_code == 201

    # 4. Cancelar el turno del día 1 vuelve a liberar ese día
    cancelar = client.patch(
        f"/api/v1/turnos/{primero.get_json()['turno']['idTurno']}/cancelar",
        json={"motivo": "Cambio de planes"},
        headers={"Authorization": f"Bearer {token_admin}"}
    )
    assert cancelar.status_code == 200

    reintento = client.post("/api/v1/turnos", json={
        "ci": ci,
        "id_profesional": "PRF-001",
        "fecha": "2026-12-01",
        "hora": "11:00"
    })
    assert reintento.status_code == 201

def test_cu04_consultar_turno(client, token_admin):
    """
    CU04 — Consultar turnos por CI del paciente.

    La consulta por CI es una búsqueda administrativa: sin sesión la agenda
    completa nunca se expone.
    """
    res = client.get("/api/v1/turnos?ci=8452136 SC", headers={"Authorization": f"Bearer {token_admin}"})
    assert res.status_code == 200
    data = res.get_json()
    assert "turnos" in data
    assert len(data["turnos"]) > 0

    # Sin token no se devuelve ninguna agenda
    anon = client.get("/api/v1/turnos?ci=8452136 SC")
    assert anon.status_code == 401

def test_cu05_cancelar_turno(client, token_admin):
    """
    CU05 — Cancelar turno existente y verificar liberación de horario o actualización de estado.
    """
    # 1. Crear turno a cancelar
    payload = {
        "ci": "8452136 SC",
        "id_profesional": "PRF-001",
        "fecha": "2026-11-25",
        "hora": "11:00"
    }
    create_res = client.post("/api/v1/turnos", json=payload)
    assert create_res.status_code == 201
    turno_creado = create_res.get_json()["turno"]

    # 2. Cancelar turno (solo el personal administrativo puede hacerlo)
    cancel_res = client.patch(
        f"/api/v1/turnos/{turno_creado['idTurno']}/cancelar",
        json={"motivo": "Urgencia personal"},
        headers={"Authorization": f"Bearer {token_admin}"}
    )
    assert cancel_res.status_code == 200
    assert cancel_res.get_json()["turno"]["estado"] == "cancelado"

def test_cu05_cancelar_requiere_admin(client):
    """
    CU05 — Un usuario no administrativo no puede cancelar turnos.
    """
    alta = client.post("/api/v1/pacientes", json={
        "nombre": "Pedro",
        "apellido": "Loayza",
        "CI": "5566778 OR",
        "telefono": "70334455",
        "correo": "pedro.loayza@correo.bo"
    })
    ci = alta.get_json()["paciente"]["ci"]

    creado = client.post("/api/v1/turnos", json={
        "ci": ci,
        "id_profesional": "PRF-001",
        "fecha": "2026-12-10",
        "hora": "08:00"
    })
    assert creado.status_code == 201
    id_turno = creado.get_json()["turno"]["idTurno"]

    # Sin token -> 401
    anonimo = client.patch(f"/api/v1/turnos/{id_turno}/cancelar", json={})
    assert anonimo.status_code == 401

    # Con token de rol no administrativo -> 403
    paciente_token = client.post("/api/v1/auth/login", json={
        "username": "juan.perez@correo.bo",
        "password": "Paciente123!"
    }).get_json()["access_token"]
    paciente = client.patch(
        f"/api/v1/turnos/{id_turno}/cancelar",
        json={},
        headers={"Authorization": f"Bearer {paciente_token}"}
    )
    assert paciente.status_code == 403
