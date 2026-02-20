from django.contrib import admin
from .models import Company, Engine, EngineModel, CompanyEngine, Profile, Role, Department, RulesGroup, Rule, Prompt, Response, AuditLog, Alert, ObfuscationConfig


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ("name", "domain", "created_at")
    search_fields = ("name", "domain")
    ordering = ("name",)


class EngineModelInline(admin.TabularInline):
    """Inline para gestionar modelos dentro del Engine."""
    model = EngineModel
    extra = 1
    fields = ("name", "model_id", "supports_vision", "max_tokens", "order", "active")


@admin.register(Engine)
class EngineAdmin(admin.ModelAdmin):
    list_display = ("name", "provider", "connector_type", "default_model", "models_count")
    list_filter = ("connector_type", "provider")
    search_fields = ("name", "provider")
    ordering = ("provider", "name")
    inlines = [EngineModelInline]
    fieldsets = (
        (None, {
            'fields': ('name', 'provider', 'description')
        }),
        ('Connection Settings', {
            'fields': ('connector_type', 'base_url', 'default_model'),
            'description': 'Configure which SDK to use and optional custom endpoint'
        }),
    )

    def models_count(self, obj):
        return obj.models.filter(active=True).count()
    models_count.short_description = "Active Models"


@admin.register(EngineModel)
class EngineModelAdmin(admin.ModelAdmin):
    list_display = ("name", "engine", "model_id", "supports_vision", "max_tokens", "order", "active")
    list_filter = ("engine", "supports_vision", "active")
    search_fields = ("name", "model_id", "engine__name")
    ordering = ("engine", "order", "name")


@admin.register(CompanyEngine)
class CompanyEngineAdmin(admin.ModelAdmin):
    list_display = ("company", "engine", "masked_api_key", "active", "created_at")
    list_filter = ("active", "engine__provider")
    search_fields = ("company__name", "engine__name")

    def masked_api_key(self, obj):
        """Muestra solo el inicio y final del token para seguridad."""
        if obj.api_key:
            return obj.api_key[:6] + "..." + obj.api_key[-4:]
        return "(no key)"
    masked_api_key.short_description = "API Key"


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "company", "role", "department")
    list_filter = ("company", "role")
    search_fields = ("user__username", "company__name")


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "description")
    search_fields = ("name",)


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ("name", "company", "created_at")
    list_filter = ("company",)
    search_fields = ("name", "company__name")


@admin.register(RulesGroup)
class RulesGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "company", "user", "created_at")
    list_filter = ("company",)
    search_fields = ("name", "company__name", "user__username")


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ("name", "rules_group", "action", "active", "created_at")
    list_filter = ("active", "action", "rules_group__company")
    search_fields = ("name", "description")
    ordering = ("-created_at",)


@admin.register(Prompt)
class PromptAdmin(admin.ModelAdmin):
    list_display = ("user", "model_used", "created_at", "filtered")
    list_filter = ("model_used", "filtered")
    search_fields = ("user__username", "content")
    ordering = ("-created_at",)


@admin.register(Response)
class ResponseAdmin(admin.ModelAdmin):
    list_display = ("prompt", "created_at", "tokens_used")
    ordering = ("-created_at",)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("user", "action", "timestamp")
    list_filter = ("action",)
    search_fields = ("user__username", "details")
    ordering = ("-timestamp",)


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("user", "company", "rule", "severity", "source", "created_at", "resolved")
    list_filter = ("severity", "resolved", "source", "company")
    search_fields = ("description", "rule__name", "user__username", "company__name")
    ordering = ("-created_at",)


@admin.register(ObfuscationConfig)
class ObfuscationConfigAdmin(admin.ModelAdmin):
    list_display = ("name", "company", "api_url", "detect", "active", "created_at")
    list_filter = ("active", "detect", "company")
    search_fields = ("name", "company__name", "api_url")
    ordering = ("-created_at",)
