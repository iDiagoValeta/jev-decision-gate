# jev-decision-gate: diseño v1

Fecha: 2026-09-19
Repo: https://github.com/iDiagoValeta/jev-decision-gate (privado)
Estado: spec validado en brainstorming, pendiente de plan de implementación

## 1. Problema y objetivo

En un loop de agente tipo opencode, el programador sufre parones: permisos de tools, preguntas multiopción, confirmaciones. Este repo construye un gate externo que deja a Jev decidir desde el primer run en base a un objetivo explícito, sin aprender del historial del usuario y sin fase shadow.

Objetivo medible v1: resolver parones sin humano cuando la confidence es alta, y devolver ask-human cuando no lo es. Cero falsos allow en acciones destructivas en pruebas propias.

## 2. Alcance y no objetivos

Incluye:
- Gate local que recibe cada parón de opencode con su objetivo de tarea.
- Una sola llamada a Jev por parón con preguntas en paralelo.
- Respuesta allow, deny, pick option o ask-human.
- Fail open a humano ante cualquier fallo propio.
- Log JSONL auditable por decisión.

No incluye:
- Aprender de decisiones pasadas del usuario.
- Modo shadow u observación previa.
- Generación de texto, solo decisiones estructuradas.
- Soporte multimodal, solo texto.

## 3. Arquitectura

Proceso pequeño externo a opencode, corriendo en local junto al agente.

Flujo:
1. Opencode envía evento de parón: tipo, detalle de tool, objetivo de la tarea, contexto mínimo.
2. Gate construye state objeto y questions tipadas.
3. Gate llama a POST https://api.typesafe.ai/v1/systemone con model jev-latest en v1, jev-1.13.0 pineado si se calibran thresholds.
4. Gate aplica thresholds por riesgo y responde.
5. Si confidence baja o hay error, responde ask-human y opencode muestra el parón original.

La key TYPESAFE_API_KEY solo vive en el gate. Nunca sale al agente ni a logs.

## 4. Modelo de decisión con Jev

Basado en docs oficiales: state como objeto con campos nombrados, contenido en state y juicio en questions, todo en inglés, questions estructuradas con JSON.

State objeto:
- objective: objetivo de la tarea del programador, en inglés, 1 a 3 frases.
- halt: tipo de parón, herramienta, comando o diff, opciones candidatas si hay pregunta multiopción.
- context: cwd, riesgo declarado por opencode, últimos pasos relevantes.
- policy: resumen corto de lo permitido y lo prohibido.

Questions en una sola llamada:
- decision Choice con instructions estructuradas y criteria allow, deny, ask-human, cada una con what, not_for y examples.
- safe Noul con instructions de si es seguro respecto al objective, criteria true y false con definición y ejemplos.
- risk Score con levels tipo negligible, reversible, destructive, cada nivel con summary y signals.
- Cuando el parón es multiopción, una Choice extra pick con las opciones del agente como criteria.

Respuesta Jev: decision con choice, probabilities y confidence. safe con noul 0 a 1. risk con score y confidence. Noul no trae confidence por diseño de la API.

Regla de combinación en código:
- Si confidence de decision menor a 0.5, ask-human directo.
- Si decision es allow pero risk alto o safe bajo, degradar a ask-human.
- Thresholds por riesgo: lecturas umbral bajo tipo 0.6, escrituras reversibles más alto, destructivos tipo push o rm umbral 0.85 o superior. Valores iniciales conservadores, a ajustar con datos propios.
- Pin de modelo: log del campo model de respuesta para saber qué versión respondió.

Referencias:
- https://docs.typesafe.ai/concepts/state
- https://docs.typesafe.ai/primitives/advanced
- https://docs.typesafe.ai/confidence
- https://docs.typesafe.ai/patterns/confidence-routing
- https://docs.typesafe.ai/api
- https://docs.typesafe.ai/models

## 5. Flujo de datos y errores

Request ejemplo lógica, sin código final:
state con objective, halt, context y policy. questions con decision, safe y risk. model jev-latest.

Manejo de errores de API:
- 401 o 422: error de config, a humano más log y alerta, no reintentar en loop.
- 429 o 529: un reintento con backoff corto, si persiste a humano.
- Timeout o red: a humano.
- Nunca allow por defecto en fallo.

Límites a respetar: 64k tokens por request, 32k para state más la pregunta más larga. 250k tok por segundo y 1200 req por minuto, con límites dinámicos según docs. SDKs con retry y header retry-after si se usan.

## 6. Testing y éxito

Pruebas v1:
- Set propio de parones con etiqueta esperada allow, deny o ask-human, incluyendo destructivos trampa.
- Assert de cero falsos allow en destructivos.
- Medición de calibración: a mayor confidence, mayor acierto.
- Medición de latencia p95 añadida por parón, objetivo bajo 500ms.
- Medición de coste por decisión con input_tokens de usage, output gratis.

Éxito v1: porcentaje alto de parones triviales resueltos sin humano, cero automatizaciones peligrosas, thresholds documentados con datos propios.

## 7. Riesgos abiertos

- API de hooks de opencode por verificar: formato exacto del evento de permiso y cómo inyectar allow o deny sin romper el loop.
- Rendimiento de Jev en instrucciones en español frente a inglés, docs indican mejor precisión en inglés.
- Thresholds iniciales son conservadores por diseño, harán más ask-human al inicio hasta calibrar.
- Rate limits dinámicos en TypeSafe por alta demanda, según warning en docs de modelos.

## 8. Siguiente paso

Invocar skill writing-plans para plan de implementación. Primer entregable esperado: cliente mínimo contra POST /v1/systemone más gate local con fail open y log, sin integración completa con opencode hasta verificar su API de permisos.
