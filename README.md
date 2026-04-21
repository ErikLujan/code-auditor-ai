> **Estado del Proyecto:** En Desarrollo (Fase 1 Completada)
> *Nota: Este es un README temporal y en construcción. Se irá actualizando conforme avance el desarrollo de las siguientes fases.*

## Visión General

Desarrollo de un agente de IA especializado en el análisis automático de repositorios de GitHub. El sistema está diseñado para identificar vulnerabilidades de seguridad, violaciones de principios de arquitectura (SOLID, DRY, POO), deuda técnica y problemas de calidad. 

El objetivo final es generar reportes priorizados con recomendaciones accionables, integrables en pipelines CI/CD y accesibles vía dashboard web.

## Estado Actual: Fase 1 (MVP) Completada

Por el momento, se ha finalizado la **Fase 1**, la cual establece toda la infraestructura base, seguridad y el núcleo de la API REST. 

**Características implementadas:**
* **API RESTful** robusta construida con **FastAPI**.
* **Autenticación Segura:** Sistema completo basado en JWT (register, login, refresh) con encriptación de contraseñas vía `bcrypt`.
* **Base de Datos:** Integración con **PostgreSQL (Supabase)** utilizando SQLAlchemy Async y migraciones gestionadas por Alembic.
* **Gestión Base:** CRUD de repositorios validando URLs de GitHub y preparación de los modelos de Análisis.
* **Seguridad y Estabilidad:** Rate limiting implementado con `slowapi`, sanitización de inputs, y manejo seguro de configuraciones mediante `pydantic-settings`.
* **Observabilidad:** Logging estructurado implementado con `structlog` (incluyendo `request_id`).
* **Testing:** Entorno de pruebas robusto usando `pytest` y `aiosqlite` (base de datos en memoria para aislamiento). 60/60 tests pasando con una cobertura de ~80%.

## Stack Tecnológico Actual

* **Backend:** Python, FastAPI
* **ORM & BD:** SQLAlchemy (Async), Alembic, PostgreSQL (Supabase)
* **Validación:** Pydantic
* **Seguridad:** PyJWT, passlib/bcrypt
* **Testing:** pytest, pytest-cov, aiosqlite

*(En fases posteriores se incorporará OpenAI API, Celery, Redis, PyGithub, y herramientas de análisis AST/Semgrep).*

## Estructura del Proyecto (Fase 1)
```text
src/
├── api/
│   ├── deps.py            # Dependencias (auth, paginación)
│   ├── routers/           # Endpoints de Autenticación y Análisis
│   └── schemas/           # Modelos de validación Pydantic
├── core/
│   ├── config.py          # Settings centralizados
│   ├── exceptions.py      # Jerarquía de errores
│   ├── logging.py         # Configuración de structlog
│   └── security.py        # Hashing, JWT y validaciones
└── db/
    ├── database.py        # Configuración del motor async
    ├── models.py          # Modelos ORM (User, Repository, Analysis, Finding)
    └── repositories.py    # Patrón Repository para acceso a datos
```

---

## Próximos Pasos (Fase 2: Integración LLM)
El desarrollo activo se enfoca ahora en la Fase 2, que dotará al sistema de su inteligencia principal:

* Integración con GitHub: Conexión vía PyGithub para la descarga y lectura temporal de repositorios.
* Análisis Estático: Implementación de un parser AST para Python que detecte secretos, inyecciones y malas prácticas a nivel de código.
* Integración IA: Conexión con la API de OpenAI con prompts diseñados para analizar arquitectura y proponer mejoras.
* Ejecución de Análisis: Conectar los endpoints de la API creados en la Fase 1 con el motor de análisis real para transicionar los estados de PENDING a COMPLETED.
