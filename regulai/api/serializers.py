from rest_framework import serializers
from django.contrib.auth.models import User
from django.db.models import Q
from django.urls import reverse
from django.core.exceptions import ValidationError as DjangoValidationError
from front.file_security import validate_avatar_upload
from front.models import (
    Company, Role, Department, Profile, RulesGroup, Rule,
    Conversation, Message, Prompt, Response, AuditLog, Alert,
    Engine, EngineModel, CompanyEngine
)


class CompanyScopedSerializer(serializers.ModelSerializer):
    """Writable tenant relations are resolved only inside the actor's company."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        profile = getattr(getattr(request, 'user', None), 'profile', None)
        self.actor_company_id = profile.company_id if profile is not None else None
        if 'company' in self.fields:
            self.fields['company'].queryset = Company.objects.filter(pk=self.actor_company_id)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        company = attrs.get('company', getattr(self.instance, 'company', None))
        if company is None or company.pk != self.actor_company_id:
            raise serializers.ValidationError({'company': 'Use your current company.'})
        return attrs


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active']
        read_only_fields = ['id']


class CompanySerializer(serializers.ModelSerializer):
    """Serializer for Company model."""
    class Meta:
        model = Company
        fields = ['id', 'name', 'domain', 'created_at']
        read_only_fields = ['id', 'created_at']


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for Role model."""
    class Meta:
        model = Role
        fields = ['id', 'name', 'description']
        read_only_fields = ['id']


class DepartmentSerializer(CompanyScopedSerializer):
    """Serializer for Department model."""
    company_name = serializers.CharField(source='company.name', read_only=True)

    class Meta:
        model = Department
        fields = ['id', 'name', 'company', 'company_name', 'description', 'created_at']
        read_only_fields = ['id', 'created_at']


class EngineModelSerializer(serializers.ModelSerializer):
    """Serializer for EngineModel."""
    engine_name = serializers.CharField(source='engine.name', read_only=True)

    class Meta:
        model = EngineModel
        fields = [
            'id', 'engine', 'engine_name', 'name', 'model_id',
            'description', 'supports_vision', 'max_tokens', 'order', 'active'
        ]
        read_only_fields = ['id']


class EngineSerializer(serializers.ModelSerializer):
    """Serializer for Engine model."""
    models = EngineModelSerializer(many=True, read_only=True)

    class Meta:
        model = Engine
        fields = [
            'id', 'name', 'provider', 'connector_type',
            'description', 'base_url', 'default_model', 'models'
        ]
        read_only_fields = ['id']


class CompanyEngineSerializer(CompanyScopedSerializer):
    """Serializer for CompanyEngine model."""
    engine_name = serializers.CharField(source='engine.name', read_only=True)
    engine_provider = serializers.CharField(source='engine.provider', read_only=True)
    available_models = EngineModelSerializer(source='engine.models', many=True, read_only=True)

    class Meta:
        model = CompanyEngine
        fields = [
            'id', 'company', 'engine', 'engine_name', 'engine_provider',
            'name', 'api_key', 'active', 'created_at', 'available_models', 'display_name'
        ]
        read_only_fields = ['id', 'created_at', 'display_name']
        extra_kwargs = {
            'api_key': {'write_only': True}
        }


class ProfileSerializer(CompanyScopedSerializer):
    """Serializer for Profile model."""
    user = UserSerializer(read_only=True)
    company_name = serializers.CharField(source='company.name', read_only=True)
    role_name = serializers.CharField(source='role.name', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True)
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = [
            'id', 'user', 'company', 'company_name', 'role', 'role_name',
            'department', 'department_name', 'avatar', 'avatar_url',
            'default_engine', 'default_model'
        ]
        read_only_fields = ['id']

    def get_avatar_url(self, obj):
        return obj.get_avatar_url()

    def validate_avatar(self, value):
        if value is not None:
            try:
                validate_avatar_upload(value)
            except DjangoValidationError as error:
                raise serializers.ValidationError(error.messages) from None
            value.seek(0)
        return value

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['department'].queryset = Department.objects.filter(company_id=self.actor_company_id)
        self.fields['default_engine'].queryset = CompanyEngine.objects.filter(
            company_id=self.actor_company_id, active=True)
        self.fields['default_model'].queryset = EngineModel.objects.filter(
            engine__companies__company_id=self.actor_company_id,
            engine__companies__active=True, active=True).distinct()

    def validate(self, attrs):
        attrs = super().validate(attrs)
        department = attrs.get('department', getattr(self.instance, 'department', None))
        if department is not None and department.company_id != self.actor_company_id:
            raise serializers.ValidationError({'department': 'Use a department in your company.'})
        engine = attrs.get('default_engine', getattr(self.instance, 'default_engine', None))
        model = attrs.get('default_model', getattr(self.instance, 'default_model', None))
        if engine is not None and (engine.company_id != self.actor_company_id or not engine.active):
            raise serializers.ValidationError({'default_engine': 'Use an active engine in your company.'})
        if model is not None and (engine is None or model.engine_id != engine.engine_id or not model.active):
            raise serializers.ValidationError({'default_model': 'Use an active model for the selected engine.'})
        return attrs


class RuleSerializer(serializers.ModelSerializer):
    """Serializer for Rule model."""
    rules_group_name = serializers.CharField(source='rules_group.name', read_only=True)

    class Meta:
        model = Rule
        fields = [
            'id', 'name', 'description', 'yara_rule', 'rules_group',
            'rules_group_name', 'severity', 'applies_to', 'action', 'active', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        actor = getattr(request, 'user', None)
        profile = getattr(actor, 'profile', None)
        self.fields['rules_group'].queryset = RulesGroup.objects.filter(
            company_id=profile.company_id if profile else None).filter(
                Q(user__isnull=True) | Q(user=actor)) if profile else RulesGroup.objects.none()


class RulesGroupSerializer(CompanyScopedSerializer):
    """Serializer for RulesGroup model."""
    rules = RuleSerializer(many=True, read_only=True)
    rules_count = serializers.SerializerMethodField()

    class Meta:
        model = RulesGroup
        fields = [
            'id', 'name', 'description', 'company', 'user',
            'created_at', 'rules', 'rules_count'
        ]
        read_only_fields = ['id', 'created_at']

    def get_rules_count(self, obj):
        return obj.rules.count()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        actor = getattr(self.context.get('request'), 'user', None)
        self.fields['user'].queryset = User.objects.filter(pk=getattr(actor, 'pk', None))


class MessageSerializer(serializers.ModelSerializer):
    """Serializer for Message model."""
    response_file = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            'id', 'conversation', 'role', 'content', 'created_at',
            'blocked', 'tokens_used', 'file_name', 'file_size', 'response_file'
        ]
        read_only_fields = fields

    def get_response_file(self, obj):
        return reverse('front:chat_download_file', args=[obj.pk]) if obj.response_file else None


class ConversationSerializer(serializers.ModelSerializer):
    """Serializer for Conversation model."""
    messages = MessageSerializer(many=True, read_only=True)
    user_username = serializers.CharField(source='user.username', read_only=True)
    messages_count = serializers.SerializerMethodField()
    display_title = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = [
            'id', 'user', 'user_username', 'title', 'display_title',
            'created_at', 'updated_at', 'messages', 'messages_count'
        ]
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']

    def get_messages_count(self, obj):
        return obj.messages.count()

    def get_display_title(self, obj):
        return obj.get_title()


class ConversationListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing conversations without messages."""
    user_username = serializers.CharField(source='user.username', read_only=True)
    messages_count = serializers.SerializerMethodField()
    display_title = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = [
            'id', 'user', 'user_username', 'title', 'display_title',
            'created_at', 'updated_at', 'messages_count'
        ]
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']

    def get_messages_count(self, obj):
        return obj.messages.count()

    def get_display_title(self, obj):
        return obj.get_title()


class PromptSerializer(serializers.ModelSerializer):
    """Serializer for Prompt model."""
    user_username = serializers.CharField(source='user.username', read_only=True)
    historical = serializers.BooleanField(read_only=True)

    class Meta:
        model = Prompt
        fields = [
            'id', 'user', 'user_username', 'conversation',
            'content', 'created_at', 'model_used', 'filtered', 'historical'
        ]
        read_only_fields = fields


class ResponseSerializer(serializers.ModelSerializer):
    """Serializer for Response model."""
    prompt_content = serializers.CharField(source='prompt.content', read_only=True)

    class Meta:
        model = Response
        fields = [
            'id', 'prompt', 'prompt_content', 'content',
            'created_at', 'tokens_used'
        ]
        read_only_fields = fields


class AlertSerializer(serializers.ModelSerializer):
    """Serializer for Alert model."""
    user_username = serializers.CharField(source='user.username', read_only=True)
    company_name = serializers.CharField(source='company.name', read_only=True)
    rule_name = serializers.CharField(source='rule.name', read_only=True)

    class Meta:
        model = Alert
        fields = [
            'id', 'user', 'user_username', 'company', 'company_name',
            'prompt', 'rule', 'rule_name', 'severity', 'description',
            'created_at', 'resolved'
        ]
        read_only_fields = fields


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model."""
    user_username = serializers.CharField(source='user.username', read_only=True)
    historical = serializers.BooleanField(read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'user_username', 'action',
            'details', 'timestamp', 'historical'
        ]
        read_only_fields = ['id', 'timestamp']


# Chat-specific serializers for the main application flow
class ChatMessageCreateSerializer(serializers.Serializer):
    """Serializer for creating a new chat message."""
    conversation_id = serializers.IntegerField(required=False, allow_null=True)
    content = serializers.CharField(required=True)
    engine_id = serializers.IntegerField(required=False, allow_null=True)
    model_id = serializers.IntegerField(required=False, allow_null=True)
    file_name = serializers.CharField(required=False, allow_blank=True)
    file_content = serializers.CharField(required=False, allow_blank=True)


class ChatResponseSerializer(serializers.Serializer):
    """Serializer for chat response."""
    conversation_id = serializers.IntegerField()
    message = MessageSerializer()
    response = MessageSerializer()
    alerts = AlertSerializer(many=True, required=False)
