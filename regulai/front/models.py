from django.db import models
from django.contrib.auth.models import User
from .encrypted_fields import EncryptedCharField, EncryptedTextField


class Company(models.Model):
    """Empresa que usa regulAI."""
    name = models.CharField(max_length=255, unique=True)
    domain = models.CharField(max_length=255, blank=True, null=True)
    system_prompt = models.TextField(
        blank=True, null=True,
        help_text="General context sent to all engines in every conversation."
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Role(models.Model):
    """Roles de usuario (admin, auditor, empleado, etc)."""
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


class Department(models.Model):
    """Departamentos de una empresa."""
    name = models.CharField(max_length=100)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="departments")
    description = models.TextField(blank=True, null=True)
    system_prompt = models.TextField(
        blank=True, null=True,
        help_text="Department-specific context, appended after the company context."
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("name", "company")
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.company.name})"


class Profile(models.Model):
    """Perfil extendido de usuario, vinculado a una empresa."""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="users")
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name="users")
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    default_engine = models.ForeignKey(
        'CompanyEngine',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='default_for_users',
        help_text="Default AI engine for chat"
    )
    default_model = models.ForeignKey(
        'EngineModel',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='default_for_users',
        help_text="Default AI model for chat"
    )
    google_drive_credentials = models.TextField(
        blank=True,
        null=True,
        help_text="Encrypted Google Drive OAuth credentials (JSON)"
    )

    def __str__(self):
        return f"{self.user.username} ({self.company.name})"

    def get_avatar_url(self):
        """Returns the avatar URL or a default image."""
        if self.avatar:
            return self.avatar.url
        return '/static/images/profile/user-1.jpg'

    def get_available_engines(self):
        """Returns active engines available for this user's company."""
        return CompanyEngine.objects.filter(
            company=self.company,
            active=True
        ).select_related('engine')


class RulesGroup(models.Model):
    """Grupo de reglas (colección de YARA rules)."""
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="rules_groups", null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="rules_groups", null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.company:
            scope = self.company.name
        elif self.user:
            scope = self.user.username
        else:
            scope = "Global"
        return f"RulesGroup: {self.name} ({scope})"


class Rule(models.Model):
    """Regla YARA que detecta patrones en prompts/respuestas."""
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    APPLIES_TO_CHOICES = [
        ("prompts", "Prompts"),
        ("files", "Files"),
        ("both", "Both"),
    ]

    ACTION_CHOICES = [
        ("block", "Block"),
        ("consent", "Consent"),
        ("obfuscate", "Obfuscate"),
    ]

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    yara_rule = models.TextField(help_text="Define the YARA rule here")
    rules_group = models.ForeignKey(RulesGroup, on_delete=models.CASCADE, related_name="rules")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="medium")
    applies_to = models.CharField(max_length=20, choices=APPLIES_TO_CHOICES, default="both")
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default="block", help_text="Block stops the message. Consent asks for confirmation. Obfuscate masks sensitive data.")
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # Obfuscation settings (only used when action="obfuscate")
    obfuscate_token = models.CharField(
        max_length=50,
        default="[{name}_{n}]",
        help_text="Token format: {name}=rule name, {n}=counter. Example: [EMAIL_1]"
    )

    def __str__(self):
        return f"Rule: {self.name} ({'Active' if self.active else 'Inactive'})"


class Conversation(models.Model):
    """Conversación que agrupa múltiples mensajes."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="conversations")
    title = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # Obfuscation context: maps tokens to original values (encrypted)
    # Example: {"[EMAIL_1]": "user@example.com", "[DNI_1]": "12345678A"}
    obfuscation_context = EncryptedTextField(
        blank=True,
        null=True,
        help_text="Encrypted JSON mapping obfuscation tokens to original values"
    )

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"Conversation: {self.title or 'Untitled'} ({self.user.username})"

    def get_title(self):
        """Genera un título basado en el primer mensaje si no tiene uno."""
        if self.title:
            return self.title
        first_message = self.messages.first()
        if first_message:
            return first_message.content[:50] + ('...' if len(first_message.content) > 50 else '')
        return 'New Conversation'

    def get_obfuscation_context(self) -> dict:
        """Get the obfuscation context as a dictionary."""
        import json
        if not self.obfuscation_context:
            return {}
        try:
            return json.loads(self.obfuscation_context)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_obfuscation_context(self, context: dict):
        """Set the obfuscation context from a dictionary."""
        import json
        self.obfuscation_context = json.dumps(context) if context else None

    def add_obfuscation_mapping(self, token: str, original: str):
        """Add a single token mapping to the context."""
        context = self.get_obfuscation_context()
        context[token] = original
        self.set_obfuscation_context(context)

    def deobfuscate_text(self, text: str) -> str:
        """Replace all obfuscation tokens with original values."""
        context = self.get_obfuscation_context()
        for token, original in context.items():
            text = text.replace(token, original)
        return text


class Message(models.Model):
    """Mensaje individual en una conversación (usuario o AI)."""
    ROLE_CHOICES = [
        ('user', 'User'),
        ('assistant', 'Assistant'),
        ('system', 'System'),
    ]

    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name="messages")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    blocked = models.BooleanField(default=False)
    tokens_used = models.IntegerField(default=0)
    # File attachment fields (user uploads and AI-generated files)
    file_name = models.CharField(max_length=255, blank=True, null=True)
    file_size = models.IntegerField(default=0)
    response_file = models.FileField(upload_to='chat_responses/', null=True, blank=True)
    # Obfuscation fields
    is_obfuscated = models.BooleanField(default=False)
    obfuscated_entities = models.JSONField(blank=True, null=True)  # List of entity types detected

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"{self.role}: {self.content[:50]}..."


class Prompt(models.Model):
    """Registro de prompts enviados a los LLMs."""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    conversation = models.ForeignKey(Conversation, on_delete=models.SET_NULL, null=True, blank=True, related_name="prompts")
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    model_used = models.CharField(max_length=100, default="gpt-4o-mini")
    filtered = models.BooleanField(default=False)

    # File information (if a file was attached)
    file_name = models.CharField(max_length=255, null=True, blank=True, help_text="Name of attached file")
    file_size = models.IntegerField(null=True, blank=True, help_text="Size of attached file in bytes")
    file_md5 = models.CharField(max_length=32, null=True, blank=True, help_text="MD5 hash of attached file")
    file_sha1 = models.CharField(max_length=40, null=True, blank=True, help_text="SHA1 hash of attached file")
    file_sha256 = models.CharField(max_length=64, null=True, blank=True, help_text="SHA256 hash of attached file")

    def __str__(self):
        return f"Prompt by {self.user.username} at {self.created_at}"


class Response(models.Model):
    """Respuestas recibidas de los LLMs."""
    prompt = models.OneToOneField(Prompt, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    tokens_used = models.IntegerField(default=0)

    def __str__(self):
        return f"Response to Prompt {self.prompt.id}"


class AuditLog(models.Model):
    """Auditoría detallada de la interacción usuario-IA."""
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=100)  # ej: "prompt_sent", "response_received", "alert_triggered"
    details = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.timestamp}] {self.user} - {self.action}"


class Alert(models.Model):
    """Alertas cuando se dispara una regla o se ofusca un prompt."""
    SOURCE_CHOICES = [
        ("rule", "Rule"),
        ("obfuscation", "Obfuscation"),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=True, blank=True)
    prompt = models.ForeignKey(Prompt, on_delete=models.SET_NULL, null=True, blank=True)
    rule = models.ForeignKey(Rule, on_delete=models.SET_NULL, null=True, blank=True)
    severity = models.CharField(max_length=20, choices=[
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ], default="medium")
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default="rule")
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)

    def __str__(self):
        return f"Alert {self.severity} - {self.rule} ({self.user})"


class Engine(models.Model):
    """Catálogo de motores de IA soportados (ej: ChatGPT, DeepSeek, Claude)."""

    CONNECTOR_CHOICES = [
        ('openai', 'OpenAI SDK'),
        ('anthropic', 'Anthropic SDK'),
        ('openai_compatible', 'OpenAI Compatible (Custom URL)'),
    ]

    name = models.CharField(max_length=100, unique=True)
    provider = models.CharField(max_length=100, blank=True, null=True)  # ej: OpenAI, DeepSeek
    connector_type = models.CharField(
        max_length=50,
        choices=CONNECTOR_CHOICES,
        default='openai',
        help_text="SDK/connector to use for API calls"
    )
    description = models.TextField(blank=True, null=True)
    base_url = models.URLField(blank=True, null=True)  # opcional, por si usas un endpoint distinto
    default_model = models.CharField(max_length=100, blank=True, null=True)  # ej: gpt-4o-mini

    def __str__(self):
        return f"{self.provider} - {self.name}"

    def get_available_models(self):
        """Returns all available models for this engine."""
        return self.models.filter(active=True).order_by('order', 'name')


class EngineModel(models.Model):
    """Modelos disponibles para cada Engine (ej: gpt-4o, gpt-4o-mini, gpt-3.5-turbo)."""
    engine = models.ForeignKey(Engine, on_delete=models.CASCADE, related_name="models")
    name = models.CharField(max_length=100)  # Display name: "GPT-4o"
    model_id = models.CharField(max_length=100)  # API model ID: "gpt-4o"
    description = models.TextField(blank=True, null=True)
    supports_vision = models.BooleanField(default=False)  # Can process images
    max_tokens = models.IntegerField(default=4096)
    order = models.IntegerField(default=0)  # For ordering in UI
    active = models.BooleanField(default=True)

    class Meta:
        unique_together = ("engine", "model_id")
        ordering = ["order", "name"]

    def __str__(self):
        return f"{self.engine.name} - {self.name}"


class CompanyEngine(models.Model):
    """Relación Company ↔ Engine con credenciales específicas."""
    company = models.ForeignKey("Company", on_delete=models.CASCADE, related_name="engines")
    engine = models.ForeignKey(Engine, on_delete=models.CASCADE, related_name="companies")
    name = models.CharField(max_length=100, blank=True, help_text="Custom name for this engine (defaults to engine name)")
    api_key = EncryptedCharField(max_length=512, help_text="API key (stored encrypted)")
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.company.name} → {self.display_name}"

    @property
    def display_name(self):
        """Returns custom name if set, otherwise the engine name."""
        return self.name if self.name else self.engine.name


class CompanyToolConfig(models.Model):
    """Configuration for which tools are enabled for a company."""
    company = models.OneToOneField(Company, on_delete=models.CASCADE, related_name="tool_config")

    # Document tools
    enable_documents = models.BooleanField(default=True, help_text="Create Word/PDF documents")
    enable_spreadsheets = models.BooleanField(default=True, help_text="Create Excel/CSV spreadsheets")
    enable_presentations = models.BooleanField(default=True, help_text="Create PowerPoint presentations")
    enable_code_files = models.BooleanField(default=True, help_text="Create code/script files")

    # Data tools
    enable_charts = models.BooleanField(default=True, help_text="Create charts and graphs")
    enable_data_analysis = models.BooleanField(default=True, help_text="Analyze data and statistics")

    # Utility tools
    enable_datetime = models.BooleanField(default=True, help_text="Get current date/time")
    enable_calculator = models.BooleanField(default=True, help_text="Mathematical calculations")
    enable_web_search = models.BooleanField(default=False, help_text="Search the web (may send data to external services)")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Company Tool Configuration"
        verbose_name_plural = "Company Tool Configurations"

    def __str__(self):
        return f"Tool Config for {self.company.name}"

    def get_enabled_tools(self) -> list:
        """Return list of enabled tool names."""
        tools = []
        if self.enable_documents:
            tools.append('create_document')
        if self.enable_spreadsheets:
            tools.append('create_spreadsheet')
        if self.enable_presentations:
            tools.append('create_presentation')
        if self.enable_code_files:
            tools.append('create_code_file')
        if self.enable_charts:
            tools.append('create_chart')
        if self.enable_data_analysis:
            tools.append('analyze_data')
        if self.enable_datetime:
            tools.append('get_current_datetime')
        if self.enable_calculator:
            tools.append('calculate')
        if self.enable_web_search:
            tools.append('web_search')
        return tools