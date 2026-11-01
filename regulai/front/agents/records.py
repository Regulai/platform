"""Private application records. This module is never installed in the executor."""
import uuid
from django.conf import settings
from django.db import models
from front.encrypted_fields import EncryptedTextField


class AgentModelProfile(models.Model):
    company = models.ForeignKey('front.Company', on_delete=models.CASCADE)
    name = models.CharField(max_length=80)
    enabled = models.BooleanField(default=False)
    connection = models.ForeignKey('front.CompanyEngine', on_delete=models.PROTECT)
    model = models.ForeignKey('front.EngineModel', on_delete=models.PROTECT)
    compaction = models.BooleanField(default=True)
    vision = models.BooleanField(default=False)
    tools = models.JSONField(default=list)
    min_group_size = models.PositiveIntegerField(default=3)
    professional = models.BooleanField(default=False)
    limits = models.JSONField(default=dict)
    # Provider credentials never enter bootstrap, graph state or sandbox.
    search_config = EncryptedTextField(default='', blank=True)

    class Meta:
        app_label = 'front'


class AgentAccessGrant(models.Model):
    """Explicit per-account capability grant; migrations grant nobody access."""
    company = models.ForeignKey('front.Company', on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    profile = models.ForeignKey(AgentModelProfile, on_delete=models.PROTECT)
    enabled = models.BooleanField(default=False)
    version = models.PositiveIntegerField(default=1)

    class Meta:
        app_label = 'front'
        constraints = [models.UniqueConstraint(fields=['company', 'user'], name='agent_access_account')]


class AgentExecution(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    prompt = models.OneToOneField('front.Prompt', on_delete=models.CASCADE)
    profile = models.ForeignKey(AgentModelProfile, on_delete=models.PROTECT)
    attempt = models.UUIDField(default=uuid.uuid4)
    token_digest = models.CharField(max_length=64, unique=True)
    authorization_digest = models.CharField(max_length=64)
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=24, default='active')
    active_call = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # Null only for the task-49 integration records. Chat jobs own this lock key.
    conversation = models.ForeignKey('front.Conversation', null=True, on_delete=models.CASCADE)
    claim_id = models.UUIDField(null=True, unique=True)
    worker_id = models.UUIDField(null=True)
    started_at = models.DateTimeField(null=True)
    finished_at = models.DateTimeField(null=True)
    job = models.JSONField(default=dict)

    class Meta:
        app_label = 'front'
        constraints = [models.CheckConstraint(condition=models.Q(status__in=[
            'queued', 'active', 'cancelled', 'outcome_unknown', 'completed', 'interrupted', 'failed']),
            name='agent_execution_status'),
            models.UniqueConstraint(fields=['conversation'], condition=models.Q(
                status__in=['queued', 'active', 'outcome_unknown']), name='agent_one_writer')]


class AgentInference(models.Model):
    execution = models.ForeignKey(AgentExecution, on_delete=models.CASCADE)
    call_id = models.UUIDField()
    attempt = models.UUIDField()
    request_digest = models.CharField(max_length=64)
    status = models.CharField(max_length=24, default='received')
    response = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'front'
        constraints = [models.UniqueConstraint(fields=['execution', 'call_id'], name='agent_unique_inference')]


class ConversationAlias(models.Model):
    company = models.ForeignKey('front.Company', on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    conversation = models.ForeignKey('front.Conversation', on_delete=models.CASCADE)
    kind = models.CharField(max_length=24)
    version = models.PositiveIntegerField(default=1)
    lookup_digest = models.CharField(max_length=64)
    token = models.CharField(max_length=64, unique=True)
    original = EncryptedTextField()

    class Meta:
        app_label = 'front'
        constraints = [models.UniqueConstraint(fields=['company', 'user', 'conversation', 'kind',
            'version', 'lookup_digest'], name='agent_unique_alias')]


class AgentInput(models.Model):
    """Only trusted application code can grant immutable data to an execution."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    execution = models.ForeignKey(AgentExecution, on_delete=models.CASCADE)
    kind = models.CharField(max_length=20)  # csv or model_image (already approved render)
    path = models.CharField(max_length=160)
    original = EncryptedTextField()
    digest = models.CharField(max_length=64)

    class Meta:
        app_label = 'front'
        constraints = [models.UniqueConstraint(fields=['execution', 'path'], name='agent_unique_input')]


class AgentToolResult(models.Model):
    execution = models.ForeignKey(AgentExecution, on_delete=models.CASCADE)
    call_id = models.CharField(max_length=160)
    request_digest = models.CharField(max_length=64)
    view = models.JSONField(default=dict)
    raw = EncryptedTextField()
    protected_view = EncryptedTextField(default='', blank=True)

    class Meta:
        app_label = 'front'
        constraints = [models.UniqueConstraint(fields=['execution', 'call_id'], name='agent_unique_tool_result')]


class AgentOperation(models.Model):
    """Durable intent before any tool effect. Contents stay encrypted."""
    execution = models.ForeignKey(AgentExecution, on_delete=models.CASCADE, related_name='operations')
    call_id = models.CharField(max_length=160)
    name = models.CharField(max_length=64)
    request_digest = models.CharField(max_length=64)
    request = EncryptedTextField()
    result = EncryptedTextField(default='')
    status = models.CharField(max_length=24, default='started')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True)

    class Meta:
        app_label = 'front'
        constraints = [models.UniqueConstraint(fields=['execution', 'call_id'], name='agent_operation_once')]


class AgentEvent(models.Model):
    execution = models.ForeignKey(AgentExecution, on_delete=models.CASCADE, related_name='events')
    kind = models.CharField(max_length=32)
    data = models.JSONField(default=dict)
    event_key = models.CharField(max_length=200, null=True, blank=True)
    public_text = EncryptedTextField(default='', blank=True, null=True)
    attempt_id = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'front'
        ordering = ['id']
        constraints = [models.UniqueConstraint(fields=['execution', 'event_key'],
            condition=models.Q(event_key__isnull=False), name='agent_event_once')]


class AgentSkillInstallation(models.Model):
    """Account-owned pointer. Revocation changes authorization, update does not."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey('front.Company', on_delete=models.CASCADE)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    source_identity = models.CharField(max_length=512)
    alias = models.CharField(max_length=64)
    enabled = models.BooleanField(default=False)
    current_revision = models.ForeignKey('AgentSkillRevision', null=True, on_delete=models.RESTRICT, related_name='+')
    previous_revision = models.ForeignKey('AgentSkillRevision', null=True, on_delete=models.RESTRICT, related_name='+')
    authorization_version = models.PositiveIntegerField(default=1)
    tombstoned_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'front'
        constraints = [
            models.UniqueConstraint(fields=['company', 'owner', 'source_identity'], name='agent_skill_source'),
            models.UniqueConstraint(fields=['company', 'owner', 'alias'],
                condition=models.Q(tombstoned_at__isnull=True), name='agent_skill_alias')]


class AgentSkillRevision(models.Model):
    """Immutable private package, including every resource and its attribution."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    installation = models.ForeignKey(AgentSkillInstallation, on_delete=models.CASCADE, related_name='revisions')
    origin = models.CharField(max_length=2048)
    resolved_commit = models.CharField(max_length=64, blank=True)
    folder_sha256 = models.CharField(max_length=64)
    upstream_sha256 = models.CharField(max_length=64, blank=True)
    manifest = models.JSONField(default=list)
    metadata = models.JSONField(default=dict)
    license = models.TextField()
    attribution = models.TextField(blank=True)
    compatibility = models.JSONField(default=dict)
    bundle = EncryptedTextField()
    adaptation_version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'front'
        constraints = [models.UniqueConstraint(fields=['installation', 'folder_sha256', 'adaptation_version'],
            name='agent_skill_revision')]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError('skill_revision_immutable')
        return super().save(*args, **kwargs)


class AgentSkillInstallOperation(models.Model):
    """Durable intent and fenced promotion; no Prompt or provider is involved."""
    id = models.UUIDField(primary_key=True, editable=False)
    company = models.ForeignKey('front.Company', on_delete=models.CASCADE)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    action = models.CharField(max_length=16)
    payload_digest = models.CharField(max_length=64)
    authorization_digest = models.CharField(max_length=64)
    state = models.CharField(max_length=16, default='validating')
    phase = models.CharField(max_length=32, default='validating')
    claim = models.UUIDField(default=uuid.uuid4)
    version = models.PositiveIntegerField(default=1)
    lease_expires_at = models.DateTimeField()
    result_revision = models.ForeignKey(AgentSkillRevision, null=True, on_delete=models.RESTRICT)
    error_code = models.CharField(max_length=80, blank=True)
    bytes_received = models.PositiveBigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'front'
        constraints = [models.CheckConstraint(condition=models.Q(state__in=[
            'downloading', 'validating', 'installed', 'failed']), name='agent_skill_install_state')]


class AgentArtifact(models.Model):
    """Private immutable candidates/revisions; only verified bytes are downloadable."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    execution = models.ForeignKey(AgentExecution, on_delete=models.CASCADE, related_name='artifacts')
    logical_id = models.UUIDField(default=uuid.uuid4)
    revision = models.PositiveIntegerField()
    base = models.ForeignKey('self', null=True, on_delete=models.RESTRICT)
    source = models.ForeignKey(AgentInput, on_delete=models.RESTRICT)
    operation_id = models.UUIDField()
    status = models.CharField(max_length=12, default='draft')
    content = EncryptedTextField()
    sha256 = models.CharField(max_length=64)
    format = models.CharField(max_length=8, default='xlsx')
    filename = EncryptedTextField(default='', blank=True)
    size_bytes = models.PositiveBigIntegerField(null=True)
    # Private document, rendered PDF and PNGs. Never model/tool-result content.
    render_bundle = EncryptedTextField(default='')
    verification = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'front'
        constraints = [models.UniqueConstraint(fields=['logical_id', 'revision'], name='agent_revision'),
            models.UniqueConstraint(fields=['execution', 'operation_id'], name='agent_artifact_operation'),
            models.CheckConstraint(condition=models.Q(status__in=['draft', 'verified']), name='agent_artifact_status')]


class AgentDocumentConnection(models.Model):
    """Administrator provisioned, per-person Drive grant. Never executor state."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey('front.Company', on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    enabled = models.BooleanField(default=False)
    write_enabled = models.BooleanField(default=False)
    version = models.PositiveIntegerField(default=1)
    # token, permission identity and direct folder allowlist; no shared credentials.
    private_config = EncryptedTextField()
    expires_at = models.DateTimeField()

    class Meta:
        app_label = 'front'
        constraints = [models.UniqueConstraint(fields=['company', 'user'], name='agent_document_account')]


class AgentDocumentReference(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connection = models.ForeignKey(AgentDocumentConnection, on_delete=models.CASCADE)
    original_id = EncryptedTextField()
    binding = models.CharField(max_length=64)
    expires_at = models.DateTimeField()

    class Meta:
        app_label = 'front'


class AgentExport(models.Model):
    """Regulay owns approval and effect ledger; checkpoints never grant access."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    execution = models.OneToOneField(AgentExecution, on_delete=models.CASCADE, related_name='export')
    artifact = models.ForeignKey(AgentArtifact, on_delete=models.RESTRICT)
    connection = models.ForeignKey(AgentDocumentConnection, on_delete=models.PROTECT)
    call = models.JSONField()
    proposal = EncryptedTextField()
    binding = models.CharField(max_length=64)
    status = models.CharField(max_length=24, default='pending')
    expires_at = models.DateTimeField()
    approved_at = models.DateTimeField(null=True)
    remote_id = EncryptedTextField(default='')
    intent_at = models.DateTimeField(null=True)
    finished_at = models.DateTimeField(null=True)

    class Meta:
        app_label = 'front'
        constraints = [models.CheckConstraint(condition=models.Q(status__in=[
            'pending', 'approved', 'rejected', 'intent', 'uncertain', 'completed']), name='agent_export_status')]
