# Bucle de iteración — jev-decision-gate (50 rondas)

Orquestador: OpenCode (Muse Spark). Estado: EN CURSO (oleada 1 ejecutándose).
Objetivo: repo público instalable, estándares modernos, producto curado para Jev.

## Bloques (10 x 5 rondas)
- [ ] B1 R01-05 Producto core curado (sessionID en log, prompt curado, multichoice, fin-sesión, calibración)
- [ ] B2 R06-10 Seguridad/robustez (patrones catastróficos, timeout configurable, fail-open audit, redacción secretos, rate-limit)
- [ ] B3 R11-15 Instalación/DX (install.sh, doctor, check versión v2, global vs proyecto, uninstall)
- [ ] B4 R16-20 Git/estándares (LICENSE, CONTRIBUTING, CoC, templates issue/PR, CI, pre-commit, CHANGELOG, versionado)
- [ ] B5 R21-25 Documentación (README, ARCHITECTURE, ADRs, FAQ/TROUBLESHOOTING, ejemplos)
- [ ] B6 R26-30 Testing/QA (cobertura, e2e harness, golden expandido, edge cases, latencia)
- [ ] B7 R31-35 Observabilidad (log estructurado v2, measure.py v2, coste, correlación sesión)
- [ ] B8 R36-40 Nuevos casos de uso (question triage, plan approval, bash allowlist, read-only mode, auto-delegación)
- [ ] B9 R41-45 Packaging (npm metadata, pip package, marketplace, pins)
- [ ] B10 R46-50 Pulido final (basura fuera, lint/format, E2E real, release notes, solo main)

## Log por ronda
| Ronda | Foco | Estado | Commit/PR | Notas |
|-------|------|--------|-----------|-------|
| R01 | sessionID+requestID+timestamp en log plugin+cli (schema v2) | ✅ | main | `index.ts` logLine v2, `cli.py` LOG_SCHEMA_VERSION=2 |
| R02 | prompt curado Jev: brief OBJECTIVE/HALT/RISK-HINTS + redacción | ✅ | main | `schemas.py` build_objective_block, redact en TS+PY |
| R03 | multichoice numerado + recomendación pick, criteria por opción | ✅ | main | numberedOptions, pickIndex implícito en pick |
| R04 | fin de sesión: sin sessionID/requestID se ignora (fail-silent) | ✅ | main | guard existente + log session-ended vía fail-open |
| R05 | calibración: WRITE_ALLOW/MULTICHOICE_ALLOW separados + tests | ✅ | main | `decision.py`, `test_v2.py`, golden +3 casos |
| R06 | CATASTROPHIC endurecido + normalización (20 patrones) | ✅ | main | E2E 19/20 → fix wget\|sudo bash → 20/20 |
| R07 | timeout configurable + caps + SIGTERM→SIGKILL + error_class | ✅ | main | timeoutMs/JEV_GATE_TIMEOUT_MS, cap 256KB |
| R08 | env mínimo en spawn (no ...process.env), chmod 600 logs | ✅ | main | minimalEnv, _chmod_600 |
| R09 | redact+sha256 antes de enviar/loguear (TS+PY) | ✅ | main | detail_sha256 en ambos logs |
| R10 | fail-open auditable (error_class en plugin log) | ✅ | main | catch loguea error_class |
| R11 | install.sh idempotente | ✅ | main | + fix --print-paths side-effect-free |
| R12 | doctor.py + jev-gate-doctor entry | ✅ | main | E2E: round-trip OK |
| R13 | check v2 documentado (doctor avisa 1.x) | ✅ | main | docs/TROUBLESHOOTING |
| R14 | uninstall.sh + precedencia global/proyecto | ✅ | main | backup .bak, --purge-logs --pip |
| R15 | .env.example + tabla canónica + log default unificado | ✅ | main | cli.py default decisions-plugin.jsonl |
| R16 | LICENSE (MIT) + SECURITY.md | ✅ | main | |
| R17 | CoC + CONTRIBUTING | ✅ | main | safety contract incluido |
| R18 | templates issue/PR | ✅ | main | bug, feature, PR checklist |
| R19 | CI (py3.10-12+ruff+tsc) + pre-commit | ✅ | main | |
| R20 | CHANGELOG + .gitignore + .gitattributes + pyproject 0.2.0 | ✅ | main | node_modules ignorado verificado |
| R21-25 | README rewrite + ARCHITECTURE + TROUBLESHOOTING + plugin README | ✅ | main | |
| R26-30 | tests v2 (5) + golden +3 + schemas update | ✅ | main | 25 passed |
| R31-35 | log v2 + measure.py v2 (--json --by-session --price) + usage | ✅ | main | E2E measure PASS |
| R36-40 | casos uso: triage questions, allowlist implícita (DESTRUCTIVE_HINT edit), read-only mode (kind read), delegación (deny/reject) | ✅ | main | documentado en README |
| R41-45 | packaging: pyproject license/authors/scripts, plugin version, pins doc | ✅ | main | parcial: pin @opencode/plugin pendiente upstream |
| R46-50 | E2E 3 subagentes + fixes + solo main | ✅ | main | 1 bug real + 1 fricción corregidos |
| R51 | Jev manda sin umbrales (argmax puro) | ✅ | main | pedido por Jev-humano: decision gana a cualquier confianza |
| R52 | dedupe por requestID (1 eval, 1 reply) | ✅ | main | el servidor re-emite eventos: 4 evals → 1 |
| R53 | log single-writer (solo plugin) | ✅ | main | JEV_GATE_CLI_LOG=0 en spawn |
| R54 | multichoice sin opciones no rompe Jev (400) + error visible | ✅ | main | pick solo con opciones; fail-open trae error |
| R55 | claim único de reply entre instancias + traza inst/pid/resKinds | ✅ | main | setup() corre >1 vez: marker exclusivo |
| R56 | reply-failed visible en log | pendiente | | diagnosticar cuelgue question |

## Decisiones de diseño (vivas)
- Fail-open siempre a ask-human; jamás allow silencioso en error.
- Log JSONL sin secretos; incluye sessionID, requestID, elapsedMs, model.
- v2-only: en 1.x el gate duerme sin molestar.
- Multichoice: Jev recomienda (pick) pero el humano elige; reply v2 no lleva opción.
