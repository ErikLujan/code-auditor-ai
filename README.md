> > **Estado del Proyecto:** En Desarrollo (Fase 2 Completada)
> *Nota: Este es un README temporal y en construcción. Se irá actualizando conforme avance el desarrollo de las siguientes fases.*

## Visión General

Desarrollo de un agente de IA especializado en el análisis automático de repositorios de GitHub. El sistema está diseñado para identificar vulnerabilidades de seguridad, violaciones de principios de arquitectura (SOLID, DRY, POO), deuda técnica y problemas de calidad. 

El objetivo final es generar reportes priorizados con recomendaciones accionables, integrables en pipelines CI/CD y accesibles vía dashboard web.

## Estado Actual: Fase 2 (Motor de Análisis e IA) Completada

El proyecto ha superado su **Fase 2**, dotando a la API de su motor de auditoría central, análisis estático y capacidades de Inteligencia Artificial.

**Características implementadas:**
* **API RESTful y Autenticación:** Base robusta en **FastAPI** con sistema JWT seguro (bcrypt).
* **Motor de Análisis Híbrido:** * **Análisis Estático (AST y Regex):** Detección de secretos hardcodeados, funciones excesivamente largas y bloques `except` silenciosos.
* **Análisis Dinámico con LLM:** Integración con proveedores compatibles con OpenAI (OpenRouter, Groq) usando modelos avanzados (ej. Llama 3) para detectar Inyecciones SQL, problemas de arquitectura (SOLID) y deuda técnica.
* **Integración con GitHub:** Clonado seguro y efímero de repositorios. El sistema descarga, analiza y limpia el almacenamiento local automáticamente (`stateless`).
* **Resiliencia y Asincronismo:** Tareas ejecutadas en segundo plano (`BackgroundTasks`), con manejo de reintentos (backoff) para APIs externas y *graceful degradation* (si el LLM falla, el reporte estático se guarda igual).
* **Base de Datos y Transacciones:** PostgreSQL (Supabase) con manejo seguro de sesiones asíncronas y control estricto de excepciones.
* **Seguridad y Rate Limiting:** Implementación de Rate Limiting nativo inyectado por dependencias para proteger endpoints críticos y controlar el gasto de tokens.

## Stack Tecnológico Actual

* **Backend:** Python, FastAPI
* **IA y Análisis:** API compatible con OpenAI (OpenRouter/Groq), analizadores AST nativos de Python.
* **ORM & BD:** SQLAlchemy (Async), Alembic, PostgreSQL (Supabase)
* **Validación:** Pydantic, Pydantic-Settings
* **Seguridad:** PyJWT, passlib/bcrypt
* **Testing:** pytest, pytest-cov, aiosqlite

*(En fases posteriores se incorporará Celery, Redis para colas distribuidas y posiblemente un frontend web).*

## Estructura del Proyecto (Fase 1)
```text
src/
├── agents/
│   ├── code_auditor_agent.py  # Orquestador de análisis
│   ├── github_client.py       # Gestión efímera de repositorios
│   ├── llm_client.py          # Cliente resiliente de IA
│   └── static_analyzers/      # AST y Secret Detectors
├── api/
│   ├── deps.py                # Dependencias (auth, Rate Limiter)
│   ├── routers/               # Endpoints REST
│   └── schemas/               # Modelos de validación Pydantic
├── core/
│   ├── config.py              # Settings centralizados
│   ├── exceptions.py          # Jerarquía de errores del dominio
│   ├── logging.py             # Configuración de structlog
│   └── security.py            # Hashing, JWT y sanitización
├── db/
│   ├── database.py            # Motor async y session manager
│   ├── models.py              # Entidades ORM
│   └── repositories.py        # Patrón Repository
└── services/
    └── analysis_service.py    # Lógica de negocio de auditorías
```

---

## Próximos Pasos (Fase 3: Escalabilidad y Automatización)
Con el motor de análisis operativo, el enfoque se desplaza a escalar el procesamiento y automatizar la recepción de código:

* **Colas Distribuidas:** Reemplazar `BackgroundTasks` por **Celery + Redis** para manejar múltiples análisis concurrentes de repositorios pesados sin bloquear la API.
* **Webhooks de GitHub:** Crear endpoints para recibir eventos `push` o `pull_request` y disparar auditorías automáticamente en pipelines CI/CD.
* **Dashboard / CLI:** Desarrollo de una interfaz para visualizar las métricas y hallazgos de forma amigable.
