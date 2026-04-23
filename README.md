> **Estado del Proyecto:** En Desarrollo (Fase 3 Completada)
>
> *Nota: Este es un README temporal y en construcción. Se irá actualizando conforme avance el desarrollo de las siguientes fases.*

## Visión General

Desarrollo de un agente de IA especializado en el análisis automático de repositorios de GitHub. El sistema está diseñado para identificar vulnerabilidades de seguridad, violaciones de principios de arquitectura (SOLID, DRY, POO), deuda técnica y problemas de calidad. 

El objetivo final es generar reportes priorizados con recomendaciones accionables, integrables en pipelines CI/CD y accesibles vía dashboard web.

## Estado Actual: Fase 3 (Escalabilidad, Automatización y Webhooks) Completada

El proyecto ha superado su **Fase 3**, transformando la API en un sistema distribuido capaz de procesar auditorías pesadas en segundo plano, manejar eventos en tiempo real y optimizar recursos mediante caché.

**Características implementadas:**
* **Colas Distribuidas (Celery + Redis):** Transición de tareas en memoria (`BackgroundTasks`) a un worker independiente (Celery) orquestado por Redis, permitiendo análisis concurrentes sin bloquear la API.
* **Caché Inteligente:** Implementación de Redis para almacenar resultados de auditorías. Evita la re-ejecución de análisis costosos (AST/LLM) si el commit del repositorio no ha cambiado (`cache_hit`).
* **Integración Activa (Webhooks):** Endpoint dedicado para la recepción automática de eventos push de GitHub, validado mediante firmas criptográficas estrictas (HMAC-SHA256) para evitar suplantaciones de identidad.
* **Observabilidad:** Integración de Prometheus para la exposición de métricas de salud y rendimiento del sistema.
* **Motor de Análisis Híbrido (Fase 2):** Análisis estático nativo (AST, Regex) y análisis dinámico con modelos LLM avanzados para detección de inyecciones SQL, deuda técnica y violaciones de diseño.
* **Base de Datos y Autenticación:** PostgreSQL (Supabase) asíncrono y sistema de autenticación JWT robusto.
* **Testing Riguroso:** Suite de pruebas con 110 tests de integración y unitarios pasando exitosamente, alcanzando un ~80% de cobertura del código (pytest).

## Stack Tecnológico Actual

* **Backend:** Python, FastAPI
* **Procesamiento Asíncrono:** Celery
* **Mensajería y Caché:** Redis
* **IA y Análisis:** API compatible con OpenAI (OpenRouter/Groq), analizadores AST nativos de Python.
* **ORM & BD:** SQLAlchemy (Async), Alembic, PostgreSQL (Supabase)
* **Validación:** Pydantic, Pydantic-Settings
* **Seguridad:** PyJWT, passlib/bcrypt, validación HMAC-SHA256
* **Observabilidad:** Prometheus
* **Testing:** pytest, pytest-cov, unittest.mock, aiosqlite

## Estructura del Proyecto (Fase 3)
```text
src/
├── agents/
│   ├── code_auditor_agent.py  # Orquestador principal de análisis
│   ├── github_client.py       # Gestión efímera de repositorios
│   └── llm_client.py          # Cliente resiliente de IA
├── analyzers/
│   ├── ast_analyzer.py        # Detección de código estático (AST)
│   ├── base.py                # Clase base abstracta
│   └── secret_detector.py     # Escáner de credenciales hardcodeadas
├── api/
│   ├── deps.py                # Dependencias (auth, Rate Limiter)
│   ├── routers/               # Endpoints REST (auth, repos, analyses, webhooks)
│   └── schemas/               # Modelos Pydantic
├── core/
│   ├── cache.py               # Gestión de caché en Redis
│   ├── celery_app.py          # Configuración del worker distribuido
│   ├── config.py              # Settings centralizados
│   ├── exceptions.py          # Jerarquía de errores
│   ├── logging.py             # Configuración de structlog
│   └── security.py            # Hashing, JWT y validaciones criptográficas
├── db/
│   ├── database.py            # Motor async y session manager
│   ├── models.py              # Entidades ORM
│   └── repositories.py        # Acceso a datos
├── services/
│   └── analysis_service.py    # Lógica de negocio de auditorías
└── tasks/
    └── analysis_tasks.py      # Tareas asíncronas de Celery
tests/
├── conftest.py                 # Fixtures globales (BD SQLite en memoria, cliente HTTP mockeado)
├── unit/                       # Pruebas aisladas de componentes core
│   ├── test_ast_analyzer.py    # Validación de reglas AST, anti-patrones y casos borde
│   ├── test_llm_client.py      # Resiliencia de IA y parseo estricto (API OpenAI mockeada)
│   ├── test_secret_detector.py # Verificación de regex para credenciales y falsos positivos
│   └── test_security.py        # Validaciones de JWT, hashing de contraseñas y sanitización
└── integration/                # Pruebas de integración, endpoints y base de datos
    ├── test_analysis_flow.py   # Orquestación del servicio de análisis con sesiones de BD
    ├── test_auth.py            # Flujos completos de registro, login y refresh de tokens
    ├── test_repositories.py    # CRUD de repositorios y encolado correcto de auditorías
    └── test_webhook.py         # Validación criptográfica y recepción de eventos
```

---

## Próximos Pasos (Fase 4: Interfaz, Integración y Despliegue))
Con un backend escalable y automatizado, la siguiente fase se centrará en transformar el motor en un producto interactivo y prepararlo para entornos productivos:

* **Desarrollo Frontend (Dashboard SPA):** Construcción de una interfaz web (posiblemente Angular/React) para visualizar métricas, detallar hallazgos y administrar repositorios.
* **Integración Activa con GitHub:** Configurar el agente como una GitHub App para que pueda publicar comentarios directamente en las líneas de código afectadas dentro de los Pull Requests.
* **Infraestructura CI/CD y Dockerización:** Empaquetar FastAPI, Celery y Redis en contenedores Docker y configurar flujos automatizados de GitHub Actions para asegurar despliegues continuos.
