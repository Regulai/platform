from rest_framework import mixins, viewsets, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.pagination import PageNumberPagination
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db.models import Q
from rest_framework.authtoken.models import Token

from front.models import (
    Company, Role, Department, Profile, RulesGroup, Rule,
    Conversation, Message, Prompt, Response as ResponseModel, AuditLog, Alert,
    Engine, EngineModel, CompanyEngine
)
from front.views import log_action
from front.access import actor_company, authorized_conversations, company_audit_scope
from front.rate_limit import login_rate_limit, chat_rate_limit
from rest_framework.permissions import SAFE_METHODS
from .permissions import IsCompanyAdmin, IsSecurityStaff
from .serializers import (
    UserSerializer, CompanySerializer, RoleSerializer, DepartmentSerializer,
    ProfileSerializer, RulesGroupSerializer, RuleSerializer,
    ConversationSerializer, ConversationListSerializer, MessageSerializer,
    PromptSerializer, ResponseSerializer, AuditLogSerializer, AlertSerializer,
    EngineSerializer, EngineModelSerializer, CompanyEngineSerializer,
    ChatMessageCreateSerializer, ChatResponseSerializer
)

def visible_groups(user):
    company = actor_company(user)
    return RulesGroup.objects.filter(
        (Q(company=company) & (Q(user__isnull=True) | Q(user=user)))
        | Q(company__isnull=True, user__isnull=True)
        | Q(company__isnull=True, user=user)).order_by('pk')


class CompanyConfigViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        classes = self.permission_classes if self.request.method in SAFE_METHODS else [IsAuthenticated, IsCompanyAdmin]
        return [permission() for permission in classes]


class CompanyRulesViewSet(CompanyConfigViewSet):
    def get_permissions(self):
        classes = [IsAuthenticated] if self.request.method in SAFE_METHODS else [IsAuthenticated, IsSecurityStaff]
        return [permission() for permission in classes]


# ==================== AUTHENTICATION ====================

@api_view(['POST'])
@permission_classes([])
@login_rate_limit
def api_login(request):
    """API endpoint for user login. Returns auth token (rate limited to 5 per minute)."""
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({
            'error': 'Please provide both username and password'
        }, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)

    if user is not None:
        token, created = Token.objects.get_or_create(user=user)

        # Log login action
        log_action(user, 'api_login', {
            'username': user.username,
            'token_created': created
        }, request)

        # Get user profile data
        profile_data = None
        if hasattr(user, 'profile'):
            profile_data = ProfileSerializer(user.profile).data

        return Response({
            'token': token.key,
            'user': UserSerializer(user).data,
            'profile': profile_data
        })
    else:
        log_action(None, 'api_login_failed', {
            'username': username
        }, request)
        return Response({
            'error': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
def api_logout(request):
    """API endpoint for user logout. Deletes auth token."""
    if request.user.is_authenticated:
        Token.objects.filter(user=request.user).delete()
        log_action(request.user, 'api_logout', {}, request)
        return Response({'message': 'Successfully logged out'})
    return Response({'error': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['GET'])
def api_me(request):
    """Get current user profile information."""
    if not request.user.is_authenticated:
        return Response({'error': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    profile_data = None
    if hasattr(request.user, 'profile'):
        profile_data = ProfileSerializer(request.user.profile).data

    return Response({
        'user': UserSerializer(request.user).data,
        'profile': profile_data
    })


# ==================== VIEWSETS ====================

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class CompanyViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin,
                     mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """ViewSet for Company model."""
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated, IsCompanyAdmin]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        return Company.objects.filter(pk=actor_company(self.request.user).pk).order_by('pk')


class RoleViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for Role model."""
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination


class DepartmentViewSet(CompanyConfigViewSet):
    """ViewSet for Department model."""
    serializer_class = DepartmentSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter departments by user's company."""
        user_company = actor_company(self.request.user)
        return Department.objects.filter(company=user_company)


class ProfileViewSet(CompanyConfigViewSet):
    """ViewSet for Profile model."""
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    http_method_names = ['get', 'put', 'patch', 'delete', 'head', 'options']

    def perform_update(self, serializer):
        from front.access import protect_operator
        protect_operator(self.request.user, serializer.instance.user_id)
        serializer.save()

    def perform_destroy(self, instance):
        from front.access import protect_operator
        protect_operator(self.request.user, instance.user_id)
        instance.delete()

    def get_queryset(self):
        """Filter profiles by user's company."""
        user_company = actor_company(self.request.user)
        return Profile.objects.filter(company=user_company).select_related('user', 'company', 'role', 'department')


class EngineViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for Engine model (read-only for regular users)."""
    queryset = Engine.objects.all()
    serializer_class = EngineSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination


class CompanyEngineViewSet(CompanyConfigViewSet):
    """ViewSet for CompanyEngine model."""
    serializer_class = CompanyEngineSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter engines by user's company."""
        user_company = actor_company(self.request.user)
        queryset = CompanyEngine.objects.filter(company=user_company)
        if not self.request.user.is_superuser:
            queryset = queryset.filter(active=True)
        return queryset.select_related('engine', 'company').prefetch_related('engine__models')

    @action(detail=True, methods=['get'])
    def models(self, request, pk=None):
        """Get available models for a specific company engine."""
        company_engine = self.get_object()
        models = company_engine.engine.get_available_models()
        serializer = EngineModelSerializer(models, many=True)
        return Response(serializer.data)


class RulesGroupViewSet(CompanyRulesViewSet):
    """ViewSet for RulesGroup model."""
    serializer_class = RulesGroupSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter rules groups by user's company."""
        queryset = visible_groups(self.request.user)
        if self.request.method not in SAFE_METHODS:
            queryset = queryset.filter(company=actor_company(self.request.user))
        return queryset.prefetch_related('rules')


class RuleViewSet(CompanyRulesViewSet):
    """ViewSet for Rule model."""
    serializer_class = RuleSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter rules by user's company."""
        groups = visible_groups(self.request.user)
        if self.request.method not in SAFE_METHODS:
            groups = groups.filter(company=actor_company(self.request.user))
        return Rule.objects.filter(rules_group__in=groups).select_related('rules_group')


class ConversationViewSet(viewsets.ModelViewSet):
    """ViewSet for Conversation model."""
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter conversations by current user."""
        actor_company(self.request.user)
        return authorized_conversations(self.request.user).prefetch_related('messages')

    def get_serializer_class(self):
        """Use lightweight serializer for list view."""
        if self.action == 'list':
            return ConversationListSerializer
        return ConversationSerializer

    def perform_create(self, serializer):
        """Set user when creating conversation."""
        actor_company(self.request.user)
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['get'])
    def messages(self, request, pk=None):
        """Get all messages for a conversation."""
        conversation = self.get_object()
        messages = conversation.messages.all()
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)


class MessageViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for Message model (read-only)."""
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter messages by user's conversations."""
        actor_company(self.request.user)
        return Message.objects.filter(conversation__in=authorized_conversations(self.request.user)).select_related('conversation')


class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for Alert model."""
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated, IsSecurityStaff]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter alerts by user's company."""
        user_company = actor_company(self.request.user)
        return Alert.objects.filter(company=user_company).select_related('user', 'company', 'rule', 'prompt')

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Mark an alert as resolved."""
        alert = self.get_object()
        alert.resolved = True
        alert.save()

        log_action(request.user, 'alert_resolved', {
            'alert_id': alert.id,
            'severity': alert.severity
        }, request)

        serializer = self.get_serializer(alert)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def unresolved(self, request):
        """Get all unresolved alerts."""
        alerts = self.get_queryset().filter(resolved=False)

        page = self.paginate_queryset(alerts)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(alerts, many=True)
        return Response(serializer.data)


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for AuditLog model (read-only)."""
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter audit logs by user's company."""
        user_company = actor_company(self.request.user)
        return AuditLog.objects.filter(company_audit_scope(user_company)).select_related('user').order_by('-timestamp', '-pk')


# ==================== CHAT API ====================

@api_view(['POST'])
@chat_rate_limit
def chat_send_message(request):
    from front.chat_service import send_chat_message
    command = {key: request.data.get(key) for key in (
        'content', 'conversation_id', 'engine_id', 'model_id', 'request_id', 'consent_token', 'action',
        'mode', 'artifact_id', 'base_revision', 'document_reference', 'export_name', 'inference_profile', 'skills')}
    command['content'] = command['content'] or ''
    command['file'] = request.FILES.get('file')
    result = send_chat_message(request.user, command)
    return Response(result.data, status=result.http_status,
        headers={'Retry-After': '5'} if result.http_status == 429 else None)


@api_view(['GET'])
def dashboard_stats(request):
    """Get dashboard statistics for the current user's company."""
    user_company = actor_company(request.user)

    stats = {
        'total_prompts': Prompt.objects.filter(company=user_company).count(),
        'blocked_prompts': Prompt.objects.filter(company=user_company, filtered=True).count(),
        'active_rules': Rule.objects.filter(
            rules_group__in=visible_groups(request.user),
            active=True
        ).count(),
        'pending_alerts': Alert.objects.filter(company=user_company, resolved=False).count(),
        'total_conversations': authorized_conversations(request.user).count(),
    }

    # Add admin-specific stats
    if request.user.is_superuser:
        stats['total_users'] = Profile.objects.filter(company=user_company).count()
        stats['total_departments'] = Department.objects.filter(company=user_company).count()
        stats['active_engines'] = CompanyEngine.objects.filter(company=user_company, active=True).count()

    return Response(stats)

