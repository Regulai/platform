<p align="center">
  <img src="https://regulai.a0.digital/img/logo-p.png" width="220" alt="regulAI">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Django-5.2-green.svg" alt="Django">
  <img src="https://img.shields.io/badge/Runtime-Python%203.12-blue.svg" alt="Runtime Python 3.12">
</p>

<p align="center">
  <strong>Protect your enterprise from unsafe AI usage.</strong><br>
  Security layer between your users and AI providers with real-time YARA-based content filtering.
</p>

<p align="center">
  <a href="#quick-start"><strong>Quick Start</strong></a> ·
  <a href="#how-it-works"><strong>How It Works</strong></a> ·
  <a href="#security--compliance"><strong>Security</strong></a> ·
  <a href="#rest-api"><strong>API</strong></a> ·
  <a href="https://regulai.a0.digital"><strong>Website</strong></a>
</p>

<br/>

<p align="center">
  <img src="https://regulai.a0.digital/img/screenshot-home.PNG" width="700" alt="regulAI Dashboard">
</p>

## The Problem

Organizations face critical risks when employees use AI tools — confidential data leaks to external providers, regulated information leaves the perimeter, and there is zero visibility into what is being sent. regulAI acts as a security layer between your users and AI providers, detecting and blocking sensitive information in real time using YARA rules before it reaches external services.

## How It Works

```
User input → YARA on original → Policy / consent → Required masking → Authorized provider
                     Any mandatory denial or failed check → Stop + decision record
```

1. User sends a prompt via the chat interface or API
2. YARA rules engine analyzes the content against all active security rules
3. Authorized content passes through mandatory masking before classification, generation or judging; failures stop the request
4. Decision records preserve destinations, status, verification and known or uncertain costs; operational logs omit message bodies and credentials

## Features

**YARA Rules Engine** — Define custom patterns to detect credit cards, API keys, personal information, and confidential markers. Organize rules into groups with severity levels.

**Policy Enforcement** — Apply configured blocking, consent and destination rules before content reaches an external AI provider. Classification and detection can miss sensitive content; these controls do not guarantee anonymity or regulatory compliance.

**Multi-Provider AI** — Connect OpenAI, Anthropic Claude, DeepSeek, or any OpenAI-compatible endpoint. Each company configures their own API keys and models.

**Decision Records** — Review request status, policy decisions, provider calls and recorded costs from the dashboard. Operational logs omit message bodies and credentials; access to stored conversations is separately authorized.

**File Scanning** — Analyze bounded text, textual PDF, DOCX, XLSX and CSV documents. Coverage checks stop incomplete extraction; images and legacy XLS require a readable supported document.

**Multi-Tenant Architecture** — Independent data isolation per organization with separate rules, users, and configurations.

**Professional Agent** — Execute authorized document and data tasks in private E2B microVMs. The Django service controls tool access, outbound data and inference. The worker requires a separate SDK/runtime installation, an enabled profile and an explicit account grant.

## Quick Start

The local agent installer requires Linux x86-64 Docker with nested KVM and a
Python 3.11+ host launcher. Application and worker containers use Python 3.12.
See [INSTALL.md](INSTALL.md) for hardware requirements and the full procedure.

**This is an import-based installer, not a public first-account setup wizard.**
It requires an operator-provided `regulai-private.json` exported from an existing,
configured installation. The repository contains no private profile, provider
credentials or ready-to-use account export. Without that profile, `install`
stops; cloning this repository alone does not create a working agent account.

If you already have an authorized private profile, keep it outside the checkout
and run:

```powershell
.\setup.cmd install --private-profile "C:\private\regulai-private.json"
```

On Linux: `sh setup.sh install --private-profile /private/regulai-private.json`.
When the installer prints `READY`, open <http://127.0.0.1:8800/login/>. A new
import initializes the `admin` password to `admin`; change it before use and
keep this development installation on loopback. Existing passwords are preserved
on restart. Run `python setup.py start` to start it again and `python setup.py stop`
to stop it while retaining data. Generation uses the configured provider and can
incur API charges; readiness checks make no model calls.

For source review without a private profile or Docker, run
`python -m unittest ops.setup.test_installer ops.setup.test_chat_bundle`.
The [development and offline demo guide](docs/plan-blackhat/arranque-y-demo.md)
documents the separate Django development setup and explicitly simulated demo.
The demo does not validate a live provider or the professional execution runtime.

<details>
<summary><strong>Initial Configuration</strong></summary>

For Django development configuration, follow the [startup and configuration guide](docs/plan-blackhat/arranque-y-demo.md). It preserves existing settings and encryption keys. Global catalogue/Django admin access requires an active staff superuser whose ID is explicitly listed in `PLATFORM_ADMIN_USER_IDS`; company administrators retain company-scoped access. Configure an owned provider, active model metadata, rules and an explicit AI policy before sending. The [example policy](docs/plan-blackhat/ai-config-example.json) starts with no outbound permission and contains no secrets.

</details>

<details>
<summary><strong>Configuración del instalador</strong></summary>

El instalador genera su configuración privada dentro de la VM y cifra las
conexiones importadas con una clave nueva. No requiere crear un `.env` ni editar
`local_settings.py`. Consulta [INSTALL.md](INSTALL.md) para arrancar, detener y
comprobar la instalación.

</details>

## Security & Compliance

YARA rules detect and block sensitive content before it reaches AI providers. Rules support severity levels (Low, Medium, High, Critical) and can be organized into groups.

```yara
rule CreditCardNumber {
    meta:
        description = "Detects credit card patterns"
        severity = "critical"
    strings:
        $visa = /4[0-9]{12}(?:[0-9]{3})?/
        $mastercard = /5[1-5][0-9]{14}/
    condition:
        any of them
}
```

<p align="center">
  <img src="https://regulai.a0.digital/img/screenshot-rules.PNG" width="700" alt="YARA Rules Management">
</p>

**Content Filtering** — Applicable active rules are evaluated before submission. The configured rule action determines whether a match blocks the request, requires confirmation or records an alert.

<p align="center">
  <img src="https://regulai.a0.digital/img/screenshot-alerts.PNG" width="700" alt="Security Alerts Dashboard">
</p>

**Integrated local masking** — CPU detection and irreversible replacement run inside Django, with no masking API call. HTTP masking remains available for existing configurations. Every backend requires company authorization and fails closed on errors. Detection is fallible; see [scope, configuration and observed omissions](docs/plan-blackhat/enmascarado-local.md). The agent also has conversation-scoped encrypted aliases with restricted local document resolution. General restoration of originals in the chat is described in a [proposal](docs/plan-blackhat/plan-tokenizacion-reversible-20261017.md), not delivered as a complete feature in this checkout. An alias alone cannot be used to calculate with its hidden original.

**File Scanning** — Extracted text from supported PDF, DOCX, XLSX, CSV and text files is checked by the shared policy engine, with explicit extraction coverage.

## Chat Interface

<p align="center">
  <img src="https://regulai.a0.digital/img/screenshot-chat.PNG" width="700" alt="Secure AI Chat">
</p>

The chat uses a React/TypeScript island served by Django, with bounded document uploads, authorized conversation history, explicit confirmations, decision receipts and model selection. The remaining management pages use Django templates. Committed chat assets are included in the installer; frontend changes must be rebuilt from `frontend/chat` using its pinned Node/npm versions and lockfile.

- Attach supported text, PDF, DOCX, CSV and XLSX documents
- Inspect coverage and retained citations; agent file continuity depends on authorized retained artifacts and runtime availability
- Switch between AI models within a conversation
- Persistent chat history with easy navigation

## Multi-Provider Support

| Provider | Model configuration | Connector |
|----------|--------|-----------|
| OpenAI | Operator-selected model IDs and capabilities | OpenAI SDK |
| Anthropic | Operator-selected Claude model IDs and capabilities | Anthropic SDK |
| DeepSeek, Groq, local LLMs | Models supported by the configured endpoint | OpenAI-compatible |

Each company configures their own engines with their own API keys. Models are managed per engine.

## REST API

REST API with token authentication for programmatic access. Examples use the local installer's port, `8800`; use your server's actual address for another deployment.

```bash
# Authenticate
curl -X POST http://127.0.0.1:8800/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass"}'

# List conversations
curl http://127.0.0.1:8800/api/conversations/ \
  -H "Authorization: Token YOUR_TOKEN"
```

<details>
<summary><strong>Available Endpoints</strong></summary>

- `/api/conversations/` — Chat conversations
- `/api/engines/` — AI engine catalog
- `/api/company-engines/` — Company engine configurations
- `/api/rules-groups/` — YARA rule groups
- `/api/rules/` — Individual YARA rules
- `/api/alerts/` — Security alerts
- `/api/audit-logs/` — Audit trail
- `/api/profiles/` — Company-scoped user profiles
- `/api/chat/send/` — Shared authorized chat workflow

</details>

Chat requests include a stable UUID `request_id` and `content`, with owned `engine_id`/`model_id` when choosing a manual route. Reuse the same UUID and unchanged content/file when retrying or confirming. A pending confirmation returns a signed `consent_token`; a Boolean confirmation flag cannot authorize a send. See [the shared-flow contract](docs/plan-blackhat/03-flujo-unico-web-api.md).

## Tech Stack

[Django](https://djangoproject.com) · [Django REST Framework](https://django-rest-framework.org) · [YARA](https://virustotal.github.io/yara/) · React/TypeScript · PostgreSQL · Deep Agents · private E2B microVMs · [OpenAI SDK](https://github.com/openai/openai-python) · [Anthropic SDK](https://github.com/anthropics/anthropic-sdk-python) · [Bootstrap 5](https://getbootstrap.com)

## Contributing

See [the project workflow](AGENTS.md) and [local tasks](docs/agents/issue-tracker.md) for contribution guidance.

## License

[BSL (Business Source License)](LICENSE)

For commercial licensing inquiries: denis@a0.digital
