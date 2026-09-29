import sqlite3
import uuid
import os
import threading
from werkzeug.security import generate_password_hash, check_password_hash

# Estados que OCUPAN la agenda. Un turno 'atendido' sigue bloqueando su franja
# horaria y el día del paciente: solo 'cancelado' los libera. El paciente que ya
# fue atendido puede pedir ese mismo horario, pero en otra fecha.
ESTADOS_OCUPAN = ("reservado", "atendido")
_SQL_OCUPAN = "estado IN ('reservado', 'atendido')"

class DatabaseService:
    """
    Servicio de Base de Datos y Repositorio Relacional.
    Diseñado con el patrón Repository y soporte de consultas parametrizadas
    para garantizar CERO vulnerabilidades a Inyección SQL (OWASP A03 / API3).
    Soporta ejecución local con SQLite y sincronización con el esquema PostgreSQL/Supabase.
    """
    _instance = None
    _lock = threading.Lock()
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    def __init__(self, db_path=None):
        # Persistencia por defecto en un archivo (turnos.db) para que los datos
        # sobrevivan a reinicios del servidor. En testing se usa ':memory:' y se
        # puede forzar otra ruta con la variable DB_PATH.
        if db_path is None:
            if os.getenv("FLASK_ENV") == "testing":
                db_path = ":memory:"
            else:
                db_path = os.getenv("DB_PATH") or os.path.join(self.PROJECT_ROOT, "turnos.db")
        self.db_path = db_path
        self._lock_conn = threading.RLock()
        self._conn = None
        self._init_db()

    @classmethod
    def get_instance(cls, db_path=None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance

    def _get_connection(self):
        # Conexión única compartida entre hilos. Antes se usaba una conexión por
        # hilo (threading.local); con SQLite ':memory:' eso creaba una BD vacía
        # distinta por request ("no such table: usuarios"). check_same_thread=False
        # permite compartir una sola conexión entre los hilos del servidor.
        if self._conn is None:
            with self._lock_conn:
                if self._conn is None:
                    self._conn = sqlite3.connect(
                        self.db_path,
                        check_same_thread=False,
                        detect_types=sqlite3.PARSE_DECLTYPES
                    )
                    self._conn.row_factory = sqlite3.Row
                    self._conn.execute("PRAGMA foreign_keys = ON;")
        return self._conn

    def _init_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # 1. Tabla de roles
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY,
                nombre TEXT NOT NULL UNIQUE,
                descripcion TEXT
            );
        """)

        # 2. Tabla de usuarios
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                id_rol INTEGER NOT NULL,
                activo INTEGER DEFAULT 1,
                FOREIGN KEY (id_rol) REFERENCES roles(id)
            );
        """)

        # 3. Tabla de pacientes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pacientes (
                id TEXT PRIMARY KEY,
                id_paciente_codigo TEXT NOT NULL UNIQUE,
                id_usuario TEXT UNIQUE,
                nombre TEXT NOT NULL,
                apellido TEXT NOT NULL,
                ci TEXT NOT NULL UNIQUE,
                telefono TEXT NOT NULL,
                correo TEXT NOT NULL,
                FOREIGN KEY (id_usuario) REFERENCES usuarios(id)
            );
        """)

        # 4. Tabla de profesionales
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS profesionales (
                id TEXT PRIMARY KEY,
                id_profesional_codigo TEXT NOT NULL UNIQUE,
                id_usuario TEXT UNIQUE,
                nombre TEXT NOT NULL,
                apellido TEXT NOT NULL,
                especialidad TEXT NOT NULL,
                telefono TEXT NOT NULL,
                activo INTEGER DEFAULT 1,
                FOREIGN KEY (id_usuario) REFERENCES usuarios(id)
            );
        """)

        # 5. Tabla de turnos con constraint de unicidad condicional simulado
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS turnos (
                id TEXT PRIMARY KEY,
                id_turno_codigo TEXT NOT NULL UNIQUE,
                id_paciente TEXT NOT NULL,
                id_profesional TEXT NOT NULL,
                fecha TEXT NOT NULL,
                hora TEXT NOT NULL,
                estado TEXT DEFAULT 'reservado',
                motivo_cancelacion TEXT,
                FOREIGN KEY (id_paciente) REFERENCES pacientes(id),
                FOREIGN KEY (id_profesional) REFERENCES profesionales(id)
            );
        """)

        # Índices únicos PARCIALES sobre los estados que ocupan la agenda. Se recrean
        # si la base los tiene con un predicado anterior (p. ej. una BD creada antes
        # de que existiera el estado 'atendido').
        self._asegurar_indices_activos(conn, cursor)

        conn.commit()
        self._seed_initial_data(conn)

    def _asegurar_indices_activos(self, conn, cursor):
        """Deja ambos índices con el predicado de los estados que ocupan la agenda."""
        self._asegurar_indice(
            conn, cursor,
            nombre="uq_turno_profesional_fecha_hora",
            crear=f"""
                CREATE UNIQUE INDEX uq_turno_profesional_fecha_hora
                ON turnos (id_profesional, fecha, hora)
                WHERE {_SQL_OCUPAN};
            """,
            violados=f"""
                SELECT id_profesional, fecha, hora, COUNT(*) AS total
                FROM turnos WHERE {_SQL_OCUPAN}
                GROUP BY id_profesional, fecha, hora HAVING COUNT(*) > 1;
            """,
            aviso="horarios duplicados en la misma agenda",
        )
        self._asegurar_indice(
            conn, cursor,
            nombre="uq_turno_paciente_fecha",
            crear=f"""
                CREATE UNIQUE INDEX uq_turno_paciente_fecha
                ON turnos (id_paciente, fecha)
                WHERE {_SQL_OCUPAN};
            """,
            violados=f"""
                SELECT p.ci AS ci, t.fecha AS fecha, COUNT(*) AS total
                FROM turnos t JOIN pacientes p ON p.id = t.id_paciente
                WHERE {_SQL_OCUPAN.replace('estado', 't.estado')}
                GROUP BY t.id_paciente, t.fecha HAVING COUNT(*) > 1;
            """,
            aviso="un turno por dia",
        )

    def _asegurar_indice(self, conn, cursor, nombre, crear, violados, aviso):
        """
        Crea un índice único parcial. Solo reemplaza al existente si los datos lo
        permiten: si hay filas que violarían el predicado, avisa y conserva el
        índice anterior en lugar de romper el arranque. La validación de create_turno
        sigue impidiendo duplicados nuevos mientras tanto.
        """
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name = ?;", (nombre,))
        existente = cursor.fetchone()
        if existente and _SQL_OCUPAN in existente["sql"]:
            return  # ya está con el predicado correcto

        cursor.execute(violados)
        conflictos = cursor.fetchall()
        if conflictos:
            print(f"[AVISO] No se pudo activar la protección '{aviso}'.")
            print(f"[AVISO] Datos existentes en conflicto (la API sigue validando en el momento):")
            for fila in conflictos:
                detalle = fila["ci"] if "ci" in fila.keys() else fila["hora"]
                print(f"[AVISO]   - {detalle}: {dict(fila)}")
            return


        cursor.execute(f"DROP INDEX IF EXISTS {nombre};")
        cursor.execute(crear)
        conn.commit()

    def _seed_initial_data(self, conn):
        cursor = conn.cursor()
        # Roles
        roles_data = [
            (1, "admin", "Administrador del sistema"),
            (2, "recepcionista", "Personal de recepción"),
            (3, "medico", "Profesional médico"),
            (4, "paciente", "Paciente usuario")
        ]
        cursor.executemany("INSERT OR IGNORE INTO roles (id, nombre, descripcion) VALUES (?, ?, ?);", roles_data)

        # Profesionales idénticos a los del frontend turnos-app
        profesionales_data = [
            (str(uuid.uuid4()), "PRF-001", None, "Marcela", "Rojas", "Medicina General", "70011122", 1),
            (str(uuid.uuid4()), "PRF-002", None, "Diego", "Fernández", "Pediatría", "70033344", 1),
            (str(uuid.uuid4()), "PRF-003", None, "Ana", "Quispe", "Odontología", "70055566", 1),
        ]
        cursor.executemany("""
            INSERT OR IGNORE INTO profesionales 
            (id, id_profesional_codigo, id_usuario, nombre, apellido, especialidad, telefono, activo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, profesionales_data)

        # Usuarios de prueba con hashes seguros (pbkdf2:sha256)
        pw_admin = generate_password_hash("Admin123!")
        pw_medico = generate_password_hash("Medico123!")
        pw_paciente = generate_password_hash("Paciente123!")

        u_admin_id = "a0000000-0000-0000-0000-000000000001"
        u_medico_id = "a0000000-0000-0000-0000-000000000002"
        u_paciente_id = "a0000000-0000-0000-0000-000000000003"
        u_medico_2_id = "a0000000-0000-0000-0000-000000000004"
        u_medico_3_id = "a0000000-0000-0000-0000-000000000005"

        usuarios_data = [
            (u_admin_id, "admin_salud", "admin@saludperiurbano.gob.bo", pw_admin, 1),
            (u_medico_id, "dra_rojas", "marcela.rojas@saludperiurbano.gob.bo", pw_medico, 3),
            (u_paciente_id, "juan_paciente", "juan.perez@correo.bo", pw_paciente, 4),
            (u_medico_2_id, "dr_fernandez", "diego.fernandez@saludperiurbano.gob.bo", pw_medico, 3),
            (u_medico_3_id, "dra_quispe", "ana.quispe@saludperiurbano.gob.bo", pw_medico, 3),
        ]
        cursor.executemany("""
            INSERT OR IGNORE INTO usuarios (id, username, email, password_hash, id_rol)
            VALUES (?, ?, ?, ?, ?);
        """, usuarios_data)

        # Vincular cada profesional médico con su usuario para que pueda iniciar
        # sesión y ver únicamente su propia agenda.
        medicos = {
            "PRF-001": u_medico_id,
            "PRF-002": u_medico_2_id,
            "PRF-003": u_medico_3_id,
        }
        for codigo, usuario_id in medicos.items():
            cursor.execute(
                "UPDATE profesionales SET id_usuario = ? WHERE id_profesional_codigo = ?;",
                (usuario_id, codigo)
            )

        # Paciente de prueba
        p_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT OR IGNORE INTO pacientes 
            (id, id_paciente_codigo, id_usuario, nombre, apellido, ci, telefono, correo)
            VALUES (?, 'PAC-10001', ?, 'Juan', 'Pérez', '8452136 SC', '70099887', 'juan.perez@correo.bo');
        """, (p_id, u_paciente_id))

        conn.commit()

    # --------------------------------------------------------------------------
    # MÉTODOS DE USUARIOS Y AUTENTICACIÓN
    # --------------------------------------------------------------------------
    def get_user_by_username_or_email(self, identifier):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.*, r.nombre as rol_nombre 
            FROM usuarios u
            JOIN roles r ON u.id_rol = r.id
            WHERE (u.username = ? OR u.email = ?) AND u.activo = 1;
        """, (identifier, identifier))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.id_rol, r.nombre as rol_nombre
            FROM usuarios u
            JOIN roles r ON u.id_rol = r.id
            WHERE u.id = ? AND u.activo = 1;
        """, (str(user_id),))
        row = cursor.fetchone()
        return dict(row) if row else None

    def create_user(self, username, email, password, rol_nombre="paciente"):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM roles WHERE nombre = ?;", (rol_nombre,))
        rol_row = cursor.fetchone()
        if not rol_row:
            return None, "El rol especificado no existe."

        user_id = str(uuid.uuid4())
        pw_hash = generate_password_hash(password)
        try:
            cursor.execute("""
                INSERT INTO usuarios (id, username, email, password_hash, id_rol)
                VALUES (?, ?, ?, ?, ?);
            """, (user_id, username, email, pw_hash, rol_row["id"]))
            conn.commit()
            return self.get_user_by_id(user_id), None
        except sqlite3.IntegrityError as e:
            return None, "El nombre de usuario o correo ya se encuentra registrado."

    # --------------------------------------------------------------------------
    # MÉTODOS DE PROFESIONALES
    # --------------------------------------------------------------------------
    def get_profesionales(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, id_profesional_codigo as idProfesional, nombre, apellido, especialidad, telefono
            FROM profesionales
            WHERE activo = 1
            ORDER BY nombre ASC;
        """)
        return [dict(row) for row in cursor.fetchall()]

    def get_profesional_by_id_or_code(self, identifier):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, id_profesional_codigo as idProfesional, nombre, apellido, especialidad, telefono, id_usuario
            FROM profesionales
            WHERE (id = ? OR id_profesional_codigo = ?) AND activo = 1;
        """, (identifier, identifier))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_profesional_by_user_id(self, user_id):
        """Resuelve el profesional a partir del 'sub' del JWT (usuarios.id)."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, id_profesional_codigo as idProfesional, id_usuario, nombre, apellido, especialidad, telefono
            FROM profesionales
            WHERE id_usuario = ? AND activo = 1;
        """, (str(user_id),))
        row = cursor.fetchone()
        return dict(row) if row else None

    # --------------------------------------------------------------------------
    # MÉTODOS DE PACIENTES (CU01)
    # --------------------------------------------------------------------------
    def get_paciente_by_ci(self, ci):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, id_paciente_codigo as idPaciente, id_usuario, nombre, apellido, ci, telefono, correo
            FROM pacientes
            WHERE ci = ?;
        """, (ci.strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_paciente_by_id(self, paciente_id):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, id_paciente_codigo as idPaciente, id_usuario, nombre, apellido, ci, telefono, correo
            FROM pacientes
            WHERE id = ? OR id_paciente_codigo = ?;
        """, (str(paciente_id), str(paciente_id)))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_paciente_by_user_id(self, user_id):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, id_paciente_codigo as idPaciente, id_usuario, nombre, apellido, ci, telefono, correo
            FROM pacientes
            WHERE id_usuario = ?;
        """, (str(user_id),))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_paciente_by_correo(self, correo):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, id_paciente_codigo as idPaciente, id_usuario, nombre, apellido, ci, telefono, correo
            FROM pacientes
            WHERE LOWER(correo) = ?;
        """, (str(correo).strip().lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None

    def create_paciente(self, nombre, apellido, ci, telefono, correo, id_usuario=None):
        conn = self._get_connection()
        cursor = conn.cursor()
        existing = self.get_paciente_by_ci(ci)
        if existing:
            return None, "Ya existe un paciente registrado con esa cédula de identidad."

        paciente_id = str(uuid.uuid4())
        # Código secuencial legible PAC-XXXXX
        short_code = f"PAC-{uuid.uuid4().hex[:5].upper()}"

        try:
            cursor.execute("""
                INSERT INTO pacientes (id, id_paciente_codigo, id_usuario, nombre, apellido, ci, telefono, correo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (paciente_id, short_code, str(id_usuario) if id_usuario else None, nombre.strip(), apellido.strip(), ci.strip(), telefono.strip(), correo.strip()))
            conn.commit()
            return self.get_paciente_by_id(paciente_id), None
        except sqlite3.IntegrityError as e:
            return None, "Error de integridad al registrar paciente: CI o usuario duplicado."

    def list_pacientes(self, limit=50, offset=0):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, id_paciente_codigo as idPaciente, nombre, apellido, ci, telefono, correo
            FROM pacientes
            ORDER BY apellido ASC, nombre ASC
            LIMIT ? OFFSET ?;
        """, (limit, offset))
        return [dict(row) for row in cursor.fetchall()]

    # --------------------------------------------------------------------------
    # MÉTODOS DE DISPONIBILIDAD (CU02)
    # --------------------------------------------------------------------------
    def get_disponibilidad(self, id_profesional, fecha, horas_jornada):
        profesional = self.get_profesional_by_id_or_code(id_profesional)
        if not profesional:
            return None, "Profesional no encontrado"

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT hora
            FROM turnos
            WHERE (id_profesional = ? OR id_profesional = ?)
              AND fecha = ?
              AND {_SQL_OCUPAN};
        """, (profesional["id"], profesional["idProfesional"], fecha))
        ocupadas = {row["hora"] for row in cursor.fetchall()}
        disponibles = [h for h in horas_jornada if h not in ocupadas]
        return disponibles, None

    # --------------------------------------------------------------------------
    # MÉTODOS DE TURNOS (CU03, CU04, CU05)
    # --------------------------------------------------------------------------
    def create_turno(self, id_paciente, id_profesional, fecha, hora, horas_jornada):
        """
        Reserva un turno atómicamente previniendo condiciones de carrera (Race Conditions).
        """
        profesional = self.get_profesional_by_id_or_code(id_profesional)
        if not profesional:
            return None, "El profesional especificado no existe."

        paciente = self.get_paciente_by_id(id_paciente)
        if not paciente:
            return None, "El paciente especificado no existe."

        if hora not in horas_jornada:
            return None, f"La hora {hora} no es un horario hábil de atención."

        conn = self._get_connection()
        cursor = conn.cursor()

        # Comprobar disponibilidad con bloqueo atómico. Un turno 'atendido' sigue
        # ocupando la franja: solo 'cancelado' la libera.
        cursor.execute(f"""
            SELECT id FROM turnos
            WHERE (id_profesional = ? OR id_profesional = ?)
              AND fecha = ?
              AND hora = ?
              AND {_SQL_OCUPAN};
        """, (profesional["id"], profesional["idProfesional"], fecha, hora))
        if cursor.fetchone():
            return None, "Este horario ya está reservado (no disponible). Elige otro horario."

        # Regla de negocio: un paciente no puede tener dos turnos activos el mismo
        # día, sin importar el horario ni el profesional. Los estados 'atendido' y
        # 'cancelado' no cuentan. Cancelar o deshacer la atención libera el día.
        cursor.execute(f"""
            SELECT hora, estado FROM turnos
            WHERE id_paciente = ?
              AND fecha = ?
              AND {_SQL_OCUPAN}
            LIMIT 1;
        """, (paciente["id"], fecha))
        turno_del_dia = cursor.fetchone()
        if turno_del_dia:
            # El estado importa: un turno 'atendido' también bloquea el día y el
            # mensaje debe decirlo, o el paciente cree que puede reintentar.
            estado_texto = "atendido" if turno_del_dia["estado"] == "atendido" else "reservado"
            return None, (
                f"Ya tenes un turno {estado_texto} el {fecha} a las "
                f"{turno_del_dia['hora']}. "
                "Solo se permite un turno por dia: elige otra fecha o cancela ese turno."
            )

        turno_id = str(uuid.uuid4())
        short_code = f"TUR-{uuid.uuid4().hex[:5].upper()}"

        try:
            cursor.execute("""
                INSERT INTO turnos (id, id_turno_codigo, id_paciente, id_profesional, fecha, hora, estado)
                VALUES (?, ?, ?, ?, ?, ?, 'reservado');
            """, (turno_id, short_code, paciente["id"], profesional["id"], fecha, hora))
            conn.commit()
            return self.get_turno_by_id(turno_id), None
        except sqlite3.IntegrityError as e:
            conn.rollback()
            # El índice uq_turno_paciente_fecha solo puede dispararse por una carrera
            # entre dos reservas concurrentes del mismo paciente y día.
            if "uq_turno_paciente_fecha" in str(e) or "turnos.id_paciente" in str(e):
                return None, (
                    f"Ya tenes un turno reservado el {fecha}. "
                    "Solo se permite un turno por dia: elige otra fecha o cancela ese turno."
                )
            return None, "Ese horario ya fue reservado concurrentemente. Por favor elige otro."

    def get_turno_by_id(self, turno_id):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, t.id_turno_codigo as idTurno, t.fecha, t.hora, t.estado, t.motivo_cancelacion,
                   p.id as id_paciente_uuid, p.id_paciente_codigo as idPaciente, p.nombre as pac_nombre, p.apellido as pac_apellido, p.ci as pac_ci, p.id_usuario as pac_usuario_id,
                   pr.id as id_profesional_uuid, pr.id_profesional_codigo as idProfesional, pr.nombre as prof_nombre, pr.apellido as prof_apellido, pr.especialidad, pr.id_usuario as prof_usuario_id
            FROM turnos t
            JOIN pacientes p ON t.id_paciente = p.id
            JOIN profesionales pr ON t.id_profesional = pr.id
            WHERE t.id = ? OR t.id_turno_codigo = ?;
        """, (str(turno_id), str(turno_id)))
        row = cursor.fetchone()
        if not row:
            return None
        return self._format_turno(row)

    def search_turnos(self, ci=None, id_turno=None, id_paciente=None, id_profesional=None):
        conn = self._get_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT t.id, t.id_turno_codigo as idTurno, t.fecha, t.hora, t.estado, t.motivo_cancelacion,
                   p.id as id_paciente_uuid, p.id_paciente_codigo as idPaciente, p.nombre as pac_nombre, p.apellido as pac_apellido, p.ci as pac_ci, p.id_usuario as pac_usuario_id,
                   pr.id as id_profesional_uuid, pr.id_profesional_codigo as idProfesional, pr.nombre as prof_nombre, pr.apellido as prof_apellido, pr.especialidad, pr.id_usuario as prof_usuario_id
            FROM turnos t
            JOIN pacientes p ON t.id_paciente = p.id
            JOIN profesionales pr ON t.id_profesional = pr.id
            WHERE 1=1
        """
        params = []
        if id_turno:
            query += " AND (t.id = ? OR LOWER(t.id_turno_codigo) = LOWER(?))"
            params.extend([id_turno.strip(), id_turno.strip()])
        if ci:
            query += " AND p.ci = ?"
            params.append(ci.strip())
        if id_paciente:
            query += " AND (p.id = ? OR p.id_paciente_codigo = ?)"
            params.extend([str(id_paciente), str(id_paciente)])
        if id_profesional:
            query += " AND (pr.id = ? OR pr.id_profesional_codigo = ?)"
            params.extend([str(id_profesional), str(id_profesional)])

        query += " ORDER BY t.fecha DESC, t.hora DESC"
        cursor.execute(query, params)
        return [self._format_turno(row) for row in cursor.fetchall()]

    def cancel_turno(self, turno_id, motivo="Cancelado por el usuario"):
        turno = self.get_turno_by_id(turno_id)
        if not turno:
            return None, "No se encontró ningún turno con ese identificador."
        if turno["estado"] == "cancelado":
            return turno, "El turno ya se encontraba cancelado previamente."

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE turnos 
            SET estado = 'cancelado', motivo_cancelacion = ?
            WHERE id = ? OR id_turno_codigo = ?;
        """, (motivo, turno["id"], turno["idTurno"]))
        conn.commit()
        return self.get_turno_by_id(turno["id"]), None

    def marcar_atencion(self, turno_id, atendido=True):
        """
        Marca un turno como 'atendido' o lo devuelve a 'reservado' (deshacer).

        El turno sigue ocupando la franja horaria y el día del paciente: la atención
        no libera la agenda, solo queda registrado que la consulta ya se realizó.
        """
        turno = self.get_turno_by_id(turno_id)
        if not turno:
            return None, "No se encontró ningún turno con ese identificador."
        if turno["estado"] == "cancelado":
            return None, "No se puede registrar la atención de un turno cancelado."

        nuevo_estado = "atendido" if atendido else "reservado"
        if turno["estado"] == nuevo_estado:
            mensaje = "El turno ya figuraba como atendido." if atendido else "El turno ya estaba reservado."
            return turno, mensaje

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE turnos
            SET estado = ?, motivo_cancelacion = NULL
            WHERE id = ? OR id_turno_codigo = ?;
        """, (nuevo_estado, turno["id"], turno["idTurno"]))
        conn.commit()
        return self.get_turno_by_id(turno["id"]), None

    def _format_turno(self, row):
        return {
            "id": row["id"],
            "idTurno": row["idTurno"],
            "fecha": row["fecha"],
            "hora": row["hora"],
            "estado": row["estado"],
            "motivo_cancelacion": row["motivo_cancelacion"],
            "paciente": {
                "id": row["id_paciente_uuid"],
                "idPaciente": row["idPaciente"],
                "nombre": row["pac_nombre"],
                "apellido": row["pac_apellido"],
                "ci": row["pac_ci"],
                "id_usuario": row["pac_usuario_id"]
            },
            "profesional": {
                "id": row["id_profesional_uuid"],
                "idProfesional": row["idProfesional"],
                "nombre": row["prof_nombre"],
                "apellido": row["prof_apellido"],
                "especialidad": row["especialidad"],
                "id_usuario": row["prof_usuario_id"]
            }
        }
