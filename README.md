<p align="center">
  <img src="https://regulai.a0.digital/img/logo-p.png" width="220" alt="regulAI">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Django-5.2-green.svg" alt="Django">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
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
User sends prompt ──▶ YARA Validation ──▶ Approved? ──▶ AI Provider
                                              │
                                              ▼ Blocked
                                        Alert + Audit Log
```

1. User sends a prompt via the chat interface or API
2. YARA rules engine analyzes the content against all active security rules
3. Approved prompts are sent to the AI provider — blocked prompts generate alerts
4. All interactions are logged for compliance and analysis

## Features

**YARA Rules Engine** — Define custom patterns to detect credit cards, API keys, personal information, and confidential markers. Organize rules into groups with severity levels.

**Real-Time Blocking** — Intercept and block prompts containing confidential content before they reach external AI providers.

**Multi-Provider AI** — Connect OpenAI, Anthropic Claude, DeepSeek, or any OpenAI-compatible endpoint. Each company configures their own API keys and models.

**Complete Audit Trail** — Detailed logging of all interactions: who, what, when, and from where. Investigate and resolve security incidents from the dashboard.

**File Scanning** — Analyze uploaded documents (PDF, Word, Excel, images) for sensitive content using the same rule engine.

**Multi-Tenant Architecture** — Independent data isolation per organization with separate rules, users, and configurations.

## Quick Start

```bash
git clone https://github.com/framirez/regulai.git
cd regulai

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
cd regulai

python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open [localhost:8000](http://localhost:8000) and log in with your superuser credentials.

<details>
<summary><strong>Initial Configuration</strong></summary>

1. Access the admin panel at [localhost:8000/admin](http://localhost:8000/admin)
2. Create a **Company** for your organization
3. Add an **AI Engine** (OpenAI, Anthropic, or custom)
4. Link the engine to your company with an **API key**
5. Create **YARA rule groups** and add detection patterns
6. Create user profiles and assign roles

</details>

<details>
<summary><strong>Environment Variables</strong></summary>

Create a `.env` file in the project root:

```env
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
OPENAI_API_KEY=sk-your-openai-key
```

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

**Content Filtering** — Prompts are validated against all active rules before submission. Matches generate alerts and block the request.

<p align="center">
  <img src="https://regulai.a0.digital/img/screenshot-alerts.PNG" width="700" alt="Security Alerts Dashboard">
</p>

**Obfuscation** — Rules with `obfuscate="true"` metadata automatically redact matched content, replacing sensitive data before sending to the AI provider.

**File Scanning** — Uploaded documents (PDF, DOCX, XLSX, images) are scanned for sensitive content using the same rule engine.

## Chat Interface

<p align="center">
  <img src="https://regulai.a0.digital/img/screenshot-chat.PNG" width="700" alt="Secure AI Chat">
</p>

Modern chat UI with file uploads, vision-capable models, conversation history, and on-the-fly model switching.

- Attach images, PDFs, Word documents, and Excel files
- Send images to vision models for analysis
- Switch between AI models within a conversation
- Persistent chat history with easy navigation

## Multi-Provider Support

| Provider | Models | Connector |
|----------|--------|-----------|
| OpenAI | GPT-4o, GPT-4o-mini, GPT-3.5-turbo | OpenAI SDK |
| Anthropic | Claude Sonnet 4, Claude 3.5 Haiku, Claude 3 Opus | Anthropic SDK |
| DeepSeek, Groq, local LLMs | Any compatible model | OpenAI-compatible |

Each company configures their own engines with their own API keys. Models are managed per engine.

## REST API

Complete REST API with token authentication for programmatic access.

```bash
# Authenticate
curl -X POST http://localhost:8000/api/token/ \
  -d '{"username": "user", "password": "pass"}'

# List conversations
curl http://localhost:8000/api/conversations/ \
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
- `/api/prompts/` — Prompt history
- `/api/users/` — User management

</details>

## Tech Stack

[Django](https://djangoproject.com) · [Django REST Framework](https://django-rest-framework.org) · [YARA](https://virustotal.github.io/yara/) · [OpenAI SDK](https://github.com/openai/openai-python) · [Anthropic SDK](https://github.com/anthropics/anthropic-sdk-python) · [Bootstrap 5](https://getbootstrap.com)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[BSL (Business Source License)](LICENSE)

For commercial licensing inquiries: denis@a0.digital
