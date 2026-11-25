"""
Benchmark Dataset Generator for Call Me Selection Intelligence
Generates 105 multi-domain natural language objectives with ground-truth relevance labels,
train/eval split (70 train, 35 eval), and domain categories.
"""

import json

OBJECTIVES = [
    # -------------------------------------------------------------------------
    # Domain 1: Python & Backend Architecture (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-001",
        "split": "train",
        "domain": "backend_python",
        "query": "Build a resilient background task processing system in Django with Celery task queues and automated retries",
        "expected_capabilities": ["django-celery", "django-patterns"],
        "expect_abstain": False,
        "description": "Django and Celery background task queue implementation"
    },
    {
        "id": "OBJ-002",
        "split": "train",
        "domain": "backend_python",
        "query": "Implement clean Pythonic data processing pipelines with dependency injection and robust error handling",
        "expected_capabilities": ["python-patterns", "error-handling"],
        "expect_abstain": False,
        "description": "Idiomatic Python backend architecture"
    },
    {
        "id": "OBJ-003",
        "split": "eval",
        "domain": "backend_python",
        "query": "Develop a FastAPI REST service with structured Pydantic v2 validation models and async database connection pooling",
        "expected_capabilities": ["fastapi-patterns", "python-patterns"],
        "expect_abstain": False,
        "description": "FastAPI service with async database connection pool"
    },
    {
        "id": "OBJ-004",
        "split": "train",
        "domain": "backend_python",
        "query": "Architect a Django application following service layer patterns, custom middleware, and query optimization",
        "expected_capabilities": ["django-patterns", "postgres-patterns"],
        "expect_abstain": False,
        "description": "Enterprise Django service architecture"
    },
    {
        "id": "OBJ-005",
        "split": "eval",
        "domain": "backend_python",
        "query": "Create an async telemetry ingestion worker using Celery beat schedules and canvas workflows",
        "expected_capabilities": ["django-celery", "telemetry-service"],
        "expect_abstain": False,
        "description": "Celery beat scheduled telemetry tasks"
    },
    {
        "id": "OBJ-006",
        "split": "train",
        "domain": "backend_python",
        "query": "Refactor monolithic Django REST Framework viewsets into modular serializers and domain services",
        "expected_capabilities": ["django-patterns", "orch-refine-code"],
        "expect_abstain": False,
        "description": "DRF viewset refactoring"
    },
    {
        "id": "OBJ-007",
        "split": "train",
        "domain": "backend_python",
        "query": "Build a high-performance Python analytics consumer using multiprocessing and zero-copy buffers",
        "expected_capabilities": ["python-patterns", "data-throughput-accelerator"],
        "expect_abstain": False,
        "description": "High throughput Python consumer"
    },
    {
        "id": "OBJ-008",
        "split": "eval",
        "domain": "backend_python",
        "query": "Implement a Django Celery periodic report generation pipeline with dead letter queues",
        "expected_capabilities": ["django-celery"],
        "expect_abstain": False,
        "description": "Periodic Celery beat reports"
    },
    {
        "id": "OBJ-009",
        "split": "train",
        "domain": "backend_python",
        "query": "Construct a Python microservice with graceful shutdown, signal handling, and structured JSON logging",
        "expected_capabilities": ["python-patterns", "error-handling"],
        "expect_abstain": False,
        "description": "Production Python microservice"
    },
    {
        "id": "OBJ-010",
        "split": "eval",
        "domain": "backend_python",
        "query": "Set up a FastAPI OpenAPI documentation generator with custom bearer token security schemes",
        "expected_capabilities": ["fastapi-patterns", "security-review"],
        "expect_abstain": False,
        "description": "FastAPI security scheme setup"
    },

    # -------------------------------------------------------------------------
    # Domain 2: Frontend & UI Systems (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-011",
        "split": "train",
        "domain": "frontend_web",
        "query": "Create an accessible React design system modal component with focus trapping and keyboard navigation",
        "expected_capabilities": ["frontend-patterns", "accessibility"],
        "expect_abstain": False,
        "description": "Accessible React dialog/modal"
    },
    {
        "id": "OBJ-012",
        "split": "train",
        "domain": "frontend_web",
        "query": "Optimize Next.js App Router server components and client state synchronization for minimal re-renders",
        "expected_capabilities": ["frontend-patterns", "react-performance"],
        "expect_abstain": False,
        "description": "Next.js performance and server components"
    },
    {
        "id": "OBJ-013",
        "split": "eval",
        "domain": "frontend_web",
        "query": "Convert Figma UI mockups into Vue 3 composition API components with Pinia state management",
        "expected_capabilities": ["ui-to-vue", "vue-patterns"],
        "expect_abstain": False,
        "description": "Figma to Vue 3 composition"
    },
    {
        "id": "OBJ-014",
        "split": "train",
        "domain": "frontend_web",
        "query": "Design an elegant landing page using hallmark anti-slop typography, restrained palettes, and editorial layout",
        "expected_capabilities": ["hallmark", "landing-page-design"],
        "expect_abstain": False,
        "description": "Hallmark non-slop landing page"
    },
    {
        "id": "OBJ-015",
        "split": "eval",
        "domain": "frontend_web",
        "query": "Configure Vite build tool with chunk splitting, manual vendor chunks, and asset compression plugins",
        "expected_capabilities": ["vite-patterns"],
        "expect_abstain": False,
        "description": "Vite build tool configuration"
    },
    {
        "id": "OBJ-016",
        "split": "train",
        "domain": "frontend_web",
        "query": "Implement fluid spring physics and momentum flick gestures for interactive iOS web navigation",
        "expected_capabilities": ["liquid-glass-design", "frontend-patterns"],
        "expect_abstain": False,
        "description": "Liquid glass interface physics"
    },
    {
        "id": "OBJ-017",
        "split": "train",
        "domain": "frontend_web",
        "query": "Build a responsive Vue 3 dashboard table with sorting, pagination, and empty state fallbacks",
        "expected_capabilities": ["vue-patterns", "ui-to-vue"],
        "expect_abstain": False,
        "description": "Vue 3 data table"
    },
    {
        "id": "OBJ-018",
        "split": "eval",
        "domain": "frontend_web",
        "query": "Audit web application UI states against the 6 interactive component states including loading and error",
        "expected_capabilities": ["frontend-patterns", "design-review"],
        "expect_abstain": False,
        "description": "Comprehensive UI states audit"
    },
    {
        "id": "OBJ-019",
        "split": "train",
        "domain": "frontend_web",
        "query": "Set up Bun as a high-speed runtime, bundler, and test runner for modern TypeScript frontends",
        "expected_capabilities": ["bun-runtime", "typescript-patterns"],
        "expect_abstain": False,
        "description": "Bun runtime frontend toolchain"
    },
    {
        "id": "OBJ-020",
        "split": "eval",
        "domain": "frontend_web",
        "query": "Design an interactive analytics dashboard with real-time SSE chart updates in React",
        "expected_capabilities": ["frontend-patterns", "dashboard-builder"],
        "expect_abstain": False,
        "description": "React analytics telemetry dashboard"
    },

    # -------------------------------------------------------------------------
    # Domain 3: Systems Programming (Rust, Go, C++) (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-021",
        "split": "train",
        "domain": "systems_programming",
        "query": "Write idiomatic Rust async actors using Tokio channels and bounded mpsc communication",
        "expected_capabilities": ["rust-patterns", "rust-testing"],
        "expect_abstain": False,
        "description": "Rust async actor pattern"
    },
    {
        "id": "OBJ-022",
        "split": "train",
        "domain": "systems_programming",
        "query": "Build a concurrent Go worker pool with context cancellation, errgroup synchronization, and rate limiting",
        "expected_capabilities": ["golang-patterns", "golang-testing"],
        "expect_abstain": False,
        "description": "Go concurrency and worker pools"
    },
    {
        "id": "OBJ-023",
        "split": "eval",
        "domain": "systems_programming",
        "query": "Enforce modern C++20 Core Guidelines including RAII smart pointers, concepts, and zero raw new calls",
        "expected_capabilities": ["cpp-coding-standards", "cpp-testing"],
        "expect_abstain": False,
        "description": "Modern C++ Core Guidelines enforcement"
    },
    {
        "id": "OBJ-024",
        "split": "train",
        "domain": "systems_programming",
        "query": "Implement custom Rust error types using thiserror and propagate results with ? operator",
        "expected_capabilities": ["rust-patterns"],
        "expect_abstain": False,
        "description": "Rust error handling patterns"
    },
    {
        "id": "OBJ-025",
        "split": "eval",
        "domain": "systems_programming",
        "query": "Develop a high-performance Go HTTP middleware chaining engine with structured context values",
        "expected_capabilities": ["golang-patterns"],
        "expect_abstain": False,
        "description": "Idiomatic Go HTTP middleware"
    },
    {
        "id": "OBJ-026",
        "split": "train",
        "domain": "systems_programming",
        "query": "Configure GoogleTest and CTest harnesses with AddressSanitizer and UndefinedBehaviorSanitizer",
        "expected_capabilities": ["cpp-testing", "cpp-coding-standards"],
        "expect_abstain": False,
        "description": "C++ sanitizers and testing harness"
    },
    {
        "id": "OBJ-027",
        "split": "train",
        "domain": "systems_programming",
        "query": "Write a zero-allocation byte parser in Rust with lifetime annotations and slice indexing",
        "expected_capabilities": ["rust-patterns"],
        "expect_abstain": False,
        "description": "Zero-allocation Rust parser"
    },
    {
        "id": "OBJ-028",
        "split": "eval",
        "domain": "systems_programming",
        "query": "Implement Go table-driven unit tests with subtests and benchmark memory allocations",
        "expected_capabilities": ["golang-testing", "golang-patterns"],
        "expect_abstain": False,
        "description": "Go table-driven testing and allocation benchmarks"
    },
    {
        "id": "OBJ-029",
        "split": "train",
        "domain": "systems_programming",
        "query": "Refactor legacy C++ code to use std::span, std::string_view, and constexpr compile-time evaluation",
        "expected_capabilities": ["cpp-coding-standards"],
        "expect_abstain": False,
        "description": "C++ Modernization to C++20"
    },
    {
        "id": "OBJ-030",
        "split": "eval",
        "domain": "systems_programming",
        "query": "Implement a lock-free ring buffer queue in Rust using atomic CAS operations",
        "expected_capabilities": ["rust-patterns"],
        "expect_abstain": False,
        "description": "Lock-free Rust atomic queue"
    },

    # -------------------------------------------------------------------------
    # Domain 4: Database & Data Engineering (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-031",
        "split": "train",
        "domain": "database_sql",
        "query": "Design an optimized PostgreSQL schema with partial indexes, BRIN indexes for time-series, and row level security",
        "expected_capabilities": ["postgres-patterns", "database-migrations"],
        "expect_abstain": False,
        "description": "PostgreSQL indexing and RLS design"
    },
    {
        "id": "OBJ-032",
        "split": "train",
        "domain": "database_sql",
        "query": "Optimize slow ClickHouse analytical queries with ReplacingMergeTree and primary key sorting order",
        "expected_capabilities": ["clickhouse-io"],
        "expect_abstain": False,
        "description": "ClickHouse analytics query tuning"
    },
    {
        "id": "OBJ-033",
        "split": "eval",
        "domain": "database_sql",
        "query": "Write zero-downtime database migrations with backward-compatible schema changes and expand-contract pattern",
        "expected_capabilities": ["database-migrations", "postgres-patterns"],
        "expect_abstain": False,
        "description": "Zero-downtime database migration"
    },
    {
        "id": "OBJ-034",
        "split": "train",
        "domain": "database_sql",
        "query": "Tune MySQL InnoDB connection pooling, transaction isolation levels, and composite index cardinality",
        "expected_capabilities": ["mysql-patterns"],
        "expect_abstain": False,
        "description": "MySQL query and index optimization"
    },
    {
        "id": "OBJ-035",
        "split": "eval",
        "domain": "database_sql",
        "query": "Partition high-volume ClickHouse event telemetry tables by month with TTL compression codecs",
        "expected_capabilities": ["clickhouse-io"],
        "expect_abstain": False,
        "description": "ClickHouse table partitioning and TTL"
    },
    {
        "id": "OBJ-036",
        "split": "train",
        "domain": "database_sql",
        "query": "Build a Prisma ORM data modeling schema with multi-tenant relations and composite foreign keys",
        "expected_capabilities": ["prisma-patterns", "postgres-patterns"],
        "expect_abstain": False,
        "description": "Prisma multi-tenant schema"
    },
    {
        "id": "OBJ-037",
        "split": "train",
        "domain": "database_sql",
        "query": "Implement distributed caching invalidation strategies using Redis pub/sub and write-through cache",
        "expected_capabilities": ["redis-patterns"],
        "expect_abstain": False,
        "description": "Redis caching and invalidation"
    },
    {
        "id": "OBJ-038",
        "split": "eval",
        "domain": "database_sql",
        "query": "Diagnose Postgres deadlocks and lock contention using pg_stat_activity and lock monitoring queries",
        "expected_capabilities": ["postgres-patterns"],
        "expect_abstain": False,
        "description": "PostgreSQL lock contention diagnosis"
    },
    {
        "id": "OBJ-039",
        "split": "train",
        "domain": "database_sql",
        "query": "Create an automated database migration verification runner with rollback validation in CI",
        "expected_capabilities": ["database-migrations"],
        "expect_abstain": False,
        "description": "Database migration CI verification"
    },
    {
        "id": "OBJ-040",
        "split": "eval",
        "domain": "database_sql",
        "query": "Configure MySQL semi-synchronous replication and GTID failover recovery topology",
        "expected_capabilities": ["mysql-patterns"],
        "expect_abstain": False,
        "description": "MySQL replication topology"
    },

    # -------------------------------------------------------------------------
    # Domain 5: Testing, QA & Reliability (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-041",
        "split": "train",
        "domain": "testing_qa",
        "query": "Build comprehensive pytest test suites using fixtures, parametrization, and branch coverage enforcement",
        "expected_capabilities": ["python-testing", "test-driven-development"],
        "expect_abstain": False,
        "description": "Pytest comprehensive test suite"
    },
    {
        "id": "OBJ-042",
        "split": "train",
        "domain": "testing_qa",
        "query": "Write end-to-end browser tests in Playwright using Page Object Model and trace artifact capture",
        "expected_capabilities": ["e2e-testing"],
        "expect_abstain": False,
        "description": "Playwright Page Object Model tests"
    },
    {
        "id": "OBJ-043",
        "split": "eval",
        "domain": "testing_qa",
        "query": "Apply strict test-driven development: write red failing unit tests first, implement minimum green code, then refactor",
        "expected_capabilities": ["test-driven-development", "tdd"],
        "expect_abstain": False,
        "description": "Test-driven development red-green-refactor loop"
    },
    {
        "id": "OBJ-044",
        "split": "train",
        "domain": "testing_qa",
        "query": "Implement Rust property-based tests using proptest crate to explore invariant edge cases",
        "expected_capabilities": ["rust-testing"],
        "expect_abstain": False,
        "description": "Rust property-based testing"
    },
    {
        "id": "OBJ-045",
        "split": "eval",
        "domain": "testing_qa",
        "query": "Investigate and resolve flaky Playwright browser integration tests with race condition debugging",
        "expected_capabilities": ["e2e-testing", "systematic-debugging"],
        "expect_abstain": False,
        "description": "Debugging flaky Playwright tests"
    },
    {
        "id": "OBJ-046",
        "split": "train",
        "domain": "testing_qa",
        "query": "Set up C# xUnit test project with FluentAssertions and Moq service mock dependencies",
        "expected_capabilities": ["csharp-testing"],
        "expect_abstain": False,
        "description": "C# xUnit testing with Moq"
    },
    {
        "id": "OBJ-047",
        "split": "train",
        "domain": "testing_qa",
        "query": "Audit existing test suite to detect redundant, duplicate, or low-value tests bloating CI runs",
        "expected_capabilities": ["test-audit"],
        "expect_abstain": False,
        "description": "Test suite deduplication audit"
    },
    {
        "id": "OBJ-048",
        "split": "eval",
        "domain": "testing_qa",
        "query": "Develop an automated UI demo recording script using Playwright with mouse motion smoothing",
        "expected_capabilities": ["ui-demo"],
        "expect_abstain": False,
        "description": "Playwright UI demo recording"
    },
    {
        "id": "OBJ-049",
        "split": "train",
        "domain": "testing_qa",
        "query": "Implement Spring Boot integration tests with MockMvc and dynamic Testcontainers for PostgreSQL",
        "expected_capabilities": ["springboot-tdd"],
        "expect_abstain": False,
        "description": "Spring Boot Testcontainers testing"
    },
    {
        "id": "OBJ-050",
        "split": "eval",
        "domain": "testing_qa",
        "query": "Isolate and fix hard-to-reproduce bug using systematic root-cause hypothesis generation",
        "expected_capabilities": ["systematic-debugging", "diagnosing-bugs"],
        "expect_abstain": False,
        "description": "Systematic root cause debugging"
    },

    # -------------------------------------------------------------------------
    # Domain 6: 3D, CGI & Computer Graphics (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-051",
        "split": "train",
        "domain": "graphics_3d",
        "query": "Model a sci-fi mechanical device in Blender using boolean bevel workflows, panel lines, and clean quad topology",
        "expected_capabilities": ["hard-surface", "blender-modeler"],
        "expect_abstain": False,
        "description": "Hard-surface mechanical modeling in Blender"
    },
    {
        "id": "OBJ-052",
        "split": "train",
        "domain": "graphics_3d",
        "query": "Set up a three-point cinematic studio lighting rig in Blender with warm key, cool fill, and crisp rim illumination",
        "expected_capabilities": ["lighting", "camera-cinematography"],
        "expect_abstain": False,
        "description": "Blender cinematic studio lighting"
    },
    {
        "id": "OBJ-053",
        "split": "eval",
        "domain": "graphics_3d",
        "query": "Create AAA character hair and fur grooming in Blender with hair cards and directional flow curves",
        "expected_capabilities": ["hair-groom", "character-artist"],
        "expect_abstain": False,
        "description": "Character hair groom in Blender"
    },
    {
        "id": "OBJ-054",
        "split": "train",
        "domain": "graphics_3d",
        "query": "Generate procedural rock and terrain landscapes using Blender Geometry Nodes with custom scatter distribution",
        "expected_capabilities": ["geometry-nodes", "procedural-modeling"],
        "expect_abstain": False,
        "description": "Geometry Nodes procedural terrain"
    },
    {
        "id": "OBJ-055",
        "split": "eval",
        "domain": "graphics_3d",
        "query": "Build a production-ready PBR material with metallic roughness workflow, procedural scratches, and edge wear",
        "expected_capabilities": ["materials", "lookdev"],
        "expect_abstain": False,
        "description": "PBR materials and lookdev in Blender"
    },
    {
        "id": "OBJ-056",
        "split": "train",
        "domain": "graphics_3d",
        "query": "Rig a bipedal humanoid character in Blender with IK FK switching constraints and weight painting",
        "expected_capabilities": ["rigging", "character-artist"],
        "expect_abstain": False,
        "description": "Humanoid character rigging in Blender"
    },
    {
        "id": "OBJ-057",
        "split": "train",
        "domain": "graphics_3d",
        "query": "Author optimized game LOD meshes and convex UCX collision proxies for Unreal Engine export",
        "expected_capabilities": ["unreal-export", "lod-pipeline", "collision-proxy"],
        "expect_abstain": False,
        "description": "Game asset LOD and collision export"
    },
    {
        "id": "OBJ-058",
        "split": "eval",
        "domain": "graphics_3d",
        "query": "Animate a smooth walk cycle keyframe sequence with easing curves in Blender Graph Editor",
        "expected_capabilities": ["animation"],
        "expect_abstain": False,
        "description": "Character walk cycle animation"
    },
    {
        "id": "OBJ-059",
        "split": "train",
        "domain": "graphics_3d",
        "query": "Perform clean retopology over high-poly sculpted character mesh ensuring quad loop edge flow",
        "expected_capabilities": ["retopology", "sculpting"],
        "expect_abstain": False,
        "description": "Production quad retopology"
    },
    {
        "id": "OBJ-060",
        "split": "eval",
        "domain": "graphics_3d",
        "query": "Set up architectural visualization interior scene with physically accurate sunlight, portals, and Cycles rendering",
        "expected_capabilities": ["archviz", "rendering"],
        "expect_abstain": False,
        "description": "Archviz interior rendering"
    },

    # -------------------------------------------------------------------------
    # Domain 7: Security, Compliance & Governance (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-061",
        "split": "train",
        "domain": "security_compliance",
        "query": "Conduct comprehensive OWASP Top 10 security audit to identify injection risks, broken auth, and sensitive data leakage",
        "expected_capabilities": ["security-review", "cso"],
        "expect_abstain": False,
        "description": "OWASP Top 10 security audit"
    },
    {
        "id": "OBJ-062",
        "split": "train",
        "domain": "security_compliance",
        "query": "Audit healthcare data ingestion endpoints for strict HIPAA PHI privacy compliance and encryption at rest",
        "expected_capabilities": ["hipaa-compliance", "security-review"],
        "expect_abstain": False,
        "description": "HIPAA compliance audit"
    },
    {
        "id": "OBJ-063",
        "split": "eval",
        "domain": "security_compliance",
        "query": "Scan third-party agent skills and plugins with SkillSpector to detect malicious prompt injection or credential harvesting",
        "expected_capabilities": ["skill-inspector"],
        "expect_abstain": False,
        "description": "SkillSpector agent skill security review"
    },
    {
        "id": "OBJ-064",
        "split": "train",
        "domain": "security_compliance",
        "query": "Implement secure JWT session authentication with HTTP-only cookies, CSRF protection, and token rotation",
        "expected_capabilities": ["security-review", "backend-patterns"],
        "expect_abstain": False,
        "description": "Secure JWT authentication setup"
    },
    {
        "id": "OBJ-065",
        "split": "eval",
        "domain": "security_compliance",
        "query": "Review API endpoints to prevent path traversal attacks, insecure direct object references (IDOR), and SSRF",
        "expected_capabilities": ["security-review", "cso"],
        "expect_abstain": False,
        "description": "Path traversal and IDOR security review"
    },
    {
        "id": "OBJ-066",
        "split": "train",
        "domain": "security_compliance",
        "query": "Enforce safe destructive command guardrails preventing unintentional database drop or force push in production",
        "expected_capabilities": ["guard", "careful"],
        "expect_abstain": False,
        "description": "Destructive command safety guardrails"
    },
    {
        "id": "OBJ-067",
        "split": "train",
        "domain": "security_compliance",
        "query": "Audit cloud deployment infrastructure for principle of least privilege IAM roles and secret token leaks",
        "expected_capabilities": ["security-review"],
        "expect_abstain": False,
        "description": "IAM least privilege security audit"
    },
    {
        "id": "OBJ-068",
        "split": "eval",
        "domain": "security_compliance",
        "query": "Inspect code for silent failures, unhandled promise rejections, and uncaught exceptions",
        "expected_capabilities": ["error-handling", "systematic-debugging"],
        "expect_abstain": False,
        "description": "Silent failure hunting"
    },
    {
        "id": "OBJ-069",
        "split": "train",
        "domain": "security_compliance",
        "query": "Verify cryptographic hash signatures of downloaded binary packages and enforce checksum verification",
        "expected_capabilities": ["security-review"],
        "expect_abstain": False,
        "description": "Cryptographic signature verification"
    },
    {
        "id": "OBJ-070",
        "split": "eval",
        "domain": "security_compliance",
        "query": "Audit Django REST API authorization policies against broken object level authorization vulnerabilities",
        "expected_capabilities": ["django-patterns", "security-review"],
        "expect_abstain": False,
        "description": "Django API security audit"
    },

    # -------------------------------------------------------------------------
    # Domain 8: System Architecture & Engineering Practice (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-071",
        "split": "train",
        "domain": "architecture_strategy",
        "query": "Structure an Architecture Decision Record (ADR) documenting context, evaluated options, and trade-offs",
        "expected_capabilities": ["architecture-decision-records", "domain-modeling"],
        "expect_abstain": False,
        "description": "Architecture Decision Record generation"
    },
    {
        "id": "OBJ-072",
        "split": "train",
        "domain": "architecture_strategy",
        "query": "Conduct Garry Tan YC Office Hours review questioning problem formulation before writing any code",
        "expected_capabilities": ["office-hours", "spec"],
        "expect_abstain": False,
        "description": "Office hours problem interrogation"
    },
    {
        "id": "OBJ-073",
        "split": "eval",
        "domain": "architecture_strategy",
        "query": "Adopt senior minimalist ponytail engineering: remove unnecessary wrappers, eliminate boilerplate, favor standard libraries",
        "expected_capabilities": ["ponytail", "deslop-shared-libs"],
        "expect_abstain": False,
        "description": "Ponytail minimalist architecture"
    },
    {
        "id": "OBJ-074",
        "split": "train",
        "domain": "architecture_strategy",
        "query": "Draft a formal technical specification with ASCII data flows, failure modes, and test matrices",
        "expected_capabilities": ["spec", "plan-eng-review"],
        "expect_abstain": False,
        "description": "Technical specification authoring"
    },
    {
        "id": "OBJ-075",
        "split": "eval",
        "domain": "architecture_strategy",
        "query": "Convene a structured four-voice council to evaluate architectural trade-offs between monolith and microservices",
        "expected_capabilities": ["council"],
        "expect_abstain": False,
        "description": "Four-voice architectural council"
    },
    {
        "id": "OBJ-076",
        "split": "train",
        "domain": "architecture_strategy",
        "query": "Build a domain glossary clarifying ubiquitous language and entity boundaries across microservices",
        "expected_capabilities": ["domain-modeling"],
        "expect_abstain": False,
        "description": "Domain-driven design ubiquitous language"
    },
    {
        "id": "OBJ-077",
        "split": "train",
        "domain": "architecture_strategy",
        "query": "Establish an engineering review process for autonomous AI agents generating production code",
        "expected_capabilities": ["ai-first-engineering", "agentic-engineering"],
        "expect_abstain": False,
        "description": "AI-first engineering team governance"
    },
    {
        "id": "OBJ-078",
        "split": "eval",
        "domain": "architecture_strategy",
        "query": "Perform an engineering plan review evaluating edge cases, blast radius, and backward compatibility",
        "expected_capabilities": ["plan-eng-review", "autoplan"],
        "expect_abstain": False,
        "description": "Eng manager plan review"
    },
    {
        "id": "OBJ-079",
        "split": "train",
        "domain": "architecture_strategy",
        "query": "Conduct a developer experience audit measuring time to first build, command ergonomics, and documentation clarity",
        "expected_capabilities": ["devex-review"],
        "expect_abstain": False,
        "description": "Developer experience audit"
    },
    {
        "id": "OBJ-080",
        "split": "eval",
        "domain": "architecture_strategy",
        "query": "Apply Andrej Karpathy guidelines: avoid premature abstraction, surgical diffs, and verifiable success criteria",
        "expected_capabilities": ["andrej-karpathy-skills"],
        "expect_abstain": False,
        "description": "Karpathy coding guidelines"
    },

    # -------------------------------------------------------------------------
    # Domain 9: DevOps, Cloud & Runtime Operations (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-081",
        "split": "train",
        "domain": "devops_cloud",
        "query": "Deploy and manage containerized services on an Uncloud cluster with automated Caddy reverse proxy ingress",
        "expected_capabilities": ["uncloud"],
        "expect_abstain": False,
        "description": "Uncloud service deployment and Caddy ingress"
    },
    {
        "id": "OBJ-082",
        "split": "train",
        "domain": "devops_cloud",
        "query": "Write multi-stage Dockerfiles optimizing layer caching, non-root user execution, and minimal image size",
        "expected_capabilities": ["docker-patterns"],
        "expect_abstain": False,
        "description": "Multi-stage Dockerfile optimization"
    },
    {
        "id": "OBJ-083",
        "split": "eval",
        "domain": "devops_cloud",
        "query": "Configure Kubernetes Deployment manifests with pod disruption budgets, readiness probes, and resource limits",
        "expected_capabilities": ["kubernetes-patterns"],
        "expect_abstain": False,
        "description": "Kubernetes manifest configuration"
    },
    {
        "id": "OBJ-084",
        "split": "train",
        "domain": "devops_cloud",
        "query": "Set up Grafana SigNoz monitoring dashboards answering key operator questions on latency and error rate",
        "expected_capabilities": ["dashboard-builder"],
        "expect_abstain": False,
        "description": "Grafana monitoring dashboard builder"
    },
    {
        "id": "OBJ-085",
        "split": "eval",
        "domain": "devops_cloud",
        "query": "Execute post-deployment canary verification monitoring error spikes, latency degradation, and rollbacks",
        "expected_capabilities": ["canary"],
        "expect_abstain": False,
        "description": "Post-deploy canary monitoring"
    },
    {
        "id": "OBJ-086",
        "split": "train",
        "domain": "devops_cloud",
        "query": "Configure Git worktrees for clean isolated workspace branching during feature implementation",
        "expected_capabilities": ["using-git-worktrees"],
        "expect_abstain": False,
        "description": "Git worktree workspace isolation"
    },
    {
        "id": "OBJ-087",
        "split": "train",
        "domain": "devops_cloud",
        "query": "Track Claude Code token usage, spending metrics, and session cost attribution against budget limits",
        "expected_capabilities": ["cost-tracking"],
        "expect_abstain": False,
        "description": "LLM cost and token tracking"
    },
    {
        "id": "OBJ-088",
        "split": "eval",
        "domain": "devops_cloud",
        "query": "Set up Husky pre-commit hooks running lint-staged formatting, TypeScript typecheck, and unit tests",
        "expected_capabilities": ["setup-pre-commit"],
        "expect_abstain": False,
        "description": "Husky and lint-staged pre-commit setup"
    },
    {
        "id": "OBJ-089",
        "split": "train",
        "domain": "devops_cloud",
        "query": "Automate shipping workflow: merge base, run regression checks, bump semantic version, and open PR",
        "expected_capabilities": ["ship"],
        "expect_abstain": False,
        "description": "Automated ship and PR workflow"
    },
    {
        "id": "OBJ-090",
        "split": "eval",
        "domain": "devops_cloud",
        "query": "Audit CI pipeline workflows for test execution performance and test fixture drift",
        "expected_capabilities": ["rea-ci-tests-audit"],
        "expect_abstain": False,
        "description": "CI test workflow audit"
    },

    # -------------------------------------------------------------------------
    # Domain 10: Multi-Intent Composite Tasks (10 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-091",
        "split": "train",
        "domain": "composite_multi_intent",
        "query": "Build a Python telemetry service, assemble it into a working application, and run automated unit tests",
        "expected_capabilities": ["telemetry-service", "app-assembly", "test-runner"],
        "expect_abstain": False,
        "description": "Telemetry service assembly and testing DAG"
    },
    {
        "id": "OBJ-092",
        "split": "train",
        "domain": "composite_multi_intent",
        "query": "Design a key-value caching service with TTL expiry, and verify with automated pytest tests",
        "expected_capabilities": ["python-patterns", "python-testing"],
        "expect_abstain": False,
        "description": "Key-value caching service and unit tests"
    },
    {
        "id": "OBJ-093",
        "split": "eval",
        "domain": "composite_multi_intent",
        "query": "Model a 3D robot asset in Blender, configure PBR materials, and export optimized GLTF for Godot",
        "expected_capabilities": ["hard-surface", "materials", "godot-export"],
        "expect_abstain": False,
        "description": "Blender 3D robot modeling, shading, and engine export"
    },
    {
        "id": "OBJ-094",
        "split": "train",
        "domain": "composite_multi_intent",
        "query": "Refactor backend API endpoints, verify zero behavior regression with pytest, and update release changelog",
        "expected_capabilities": ["orch-refine-code", "python-testing", "rea-changelog-update"],
        "expect_abstain": False,
        "description": "Behavior-preserving refactoring with changelog update"
    },
    {
        "id": "OBJ-095",
        "split": "eval",
        "domain": "composite_multi_intent",
        "query": "Build a React customer dashboard component, connect to backend API, and write Playwright E2E verification tests",
        "expected_capabilities": ["frontend-patterns", "dashboard-builder", "e2e-testing"],
        "expect_abstain": False,
        "description": "React dashboard with E2E Playwright verification"
    },
    {
        "id": "OBJ-096",
        "split": "train",
        "domain": "composite_multi_intent",
        "query": "Implement health monitoring module, connect to central telemetry aggregator, and verify with tests",
        "expected_capabilities": ["health-monitor", "telemetry-service", "test-runner"],
        "expect_abstain": False,
        "description": "Health monitor and telemetry integration"
    },
    {
        "id": "OBJ-097",
        "split": "eval",
        "domain": "composite_multi_intent",
        "query": "Perform OWASP Top 10 security review on authentication code and write regression tests proving fix",
        "expected_capabilities": ["security-review", "python-testing"],
        "expect_abstain": False,
        "description": "Security review with verification regression tests"
    },
    {
        "id": "OBJ-098",
        "split": "train",
        "domain": "composite_multi_intent",
        "query": "Create an architectural decision record for database migration and implement the schema migration scripts",
        "expected_capabilities": ["architecture-decision-records", "database-migrations"],
        "expect_abstain": False,
        "description": "ADR creation and database migration scripts"
    },
    {
        "id": "OBJ-099",
        "split": "eval",
        "domain": "composite_multi_intent",
        "query": "Scaffold a new CLI utility, configure pre-commit hooks, and verify unit test coverage",
        "expected_capabilities": ["python-patterns", "setup-pre-commit", "python-testing"],
        "expect_abstain": False,
        "description": "CLI scaffolding with hooks and tests"
    },
    {
        "id": "OBJ-100",
        "split": "train",
        "domain": "composite_multi_intent",
        "query": "Design an interactive Three.js 3D mechanical simulator with telemetry dashboard HUD overlay",
        "expected_capabilities": ["teardown", "apple-design"],
        "expect_abstain": False,
        "description": "Teardown 3D simulation with HUD"
    },

    # -------------------------------------------------------------------------
    # Domain 11: Out-of-Domain & Adversarial Abstention (5 items)
    # -------------------------------------------------------------------------
    {
        "id": "OBJ-101",
        "split": "train",
        "domain": "out_of_domain_abstain",
        "query": "Provide a medical diagnosis for recurring chest pain and recommend prescription medication",
        "expected_capabilities": [],
        "expect_abstain": True,
        "description": "Medical advice query where system must abstain"
    },
    {
        "id": "OBJ-102",
        "split": "eval",
        "domain": "out_of_domain_abstain",
        "query": "Predict tomorrow's closing stock price of Apple with buy sell trading signals",
        "expected_capabilities": [],
        "expect_abstain": True,
        "description": "Financial stock prediction where system must abstain"
    },
    {
        "id": "OBJ-103",
        "split": "train",
        "domain": "out_of_domain_abstain",
        "query": "How do I bake a chocolate sourdough bread at high altitude with steam injection?",
        "expected_capabilities": [],
        "expect_abstain": True,
        "description": "Baking recipe query where system must abstain"
    },
    {
        "id": "OBJ-104",
        "split": "eval",
        "domain": "out_of_domain_abstain",
        "query": "Write a legal contract for buying real estate in California under probate law",
        "expected_capabilities": [],
        "expect_abstain": True,
        "description": "Legal probate contract where system must abstain"
    },
    {
        "id": "OBJ-105",
        "split": "eval",
        "domain": "out_of_domain_abstain",
        "query": "Translate this ancient Sumerian cuneiform tablet into classical Latin verse",
        "expected_capabilities": [],
        "expect_abstain": True,
        "description": "Ancient language translation where system must abstain"
    }
]

if __name__ == "__main__":
    out_file = "benchmark/dataset_100_objectives.json"
    with open(out_file, "w") as f:
        json.dump(OBJECTIVES, f, indent=2)
    print(f"Generated {len(OBJECTIVES)} benchmark objectives in {out_file}")
    train_count = sum(1 for o in OBJECTIVES if o["split"] == "train")
    eval_count = sum(1 for o in OBJECTIVES if o["split"] == "eval")
    abstain_count = sum(1 for o in OBJECTIVES if o["expect_abstain"])
    print(f"Train set: {train_count}, Eval set: {eval_count}, Abstention set: {abstain_count}")
