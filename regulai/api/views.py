from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.pagination import PageNumberPagination
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db.models import Q, Count
from rest_framework.authtoken.models import Token
from django.shortcuts import get_object_or_404
import hashlib
import base64
import io

from front.models import (
    Company, Role, Department, Profile, RulesGroup, Rule,
    Conversation, Message, Prompt, Response as ResponseModel, AuditLog, Alert,
    Engine, EngineModel, CompanyEngine
)
from front.connectors import get_connector, ChatMessage
from front.views import validate_prompt, log_action, get_user_company
from front.rate_limit import rate_limit, login_rate_limit, chat_rate_limit
from .serializers import (
    UserSerializer, CompanySerializer, RoleSerializer, DepartmentSerializer,
    ProfileSerializer, RulesGroupSerializer, RuleSerializer,
    ConversationSerializer, ConversationListSerializer, MessageSerializer,
    PromptSerializer, ResponseSerializer, AuditLogSerializer, AlertSerializer,
    EngineSerializer, EngineModelSerializer, CompanyEngineSerializer,
    ChatMessageCreateSerializer, ChatResponseSerializer
)

# Import file processors
try:
    import PyPDF2
    import docx
    import openpyxl
    import pytesseract
    from PIL import Image
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False


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


class CompanyViewSet(viewsets.ModelViewSet):
    """ViewSet for Company model."""
    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    pagination_class = StandardResultsSetPagination


class RoleViewSet(viewsets.ModelViewSet):
    """ViewSet for Role model."""
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination


class DepartmentViewSet(viewsets.ModelViewSet):
    """ViewSet for Department model."""
    serializer_class = DepartmentSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter departments by user's company."""
        user_company = get_user_company(self.request.user)
        return Department.objects.filter(company=user_company)


class ProfileViewSet(viewsets.ModelViewSet):
    """ViewSet for Profile model."""
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter profiles by user's company."""
        user_company = get_user_company(self.request.user)
        return Profile.objects.filter(company=user_company).select_related('user', 'company', 'role', 'department')


class EngineViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for Engine model (read-only for regular users)."""
    queryset = Engine.objects.all()
    serializer_class = EngineSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination


class CompanyEngineViewSet(viewsets.ModelViewSet):
    """ViewSet for CompanyEngine model."""
    serializer_class = CompanyEngineSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter engines by user's company."""
        user_company = get_user_company(self.request.user)
        return CompanyEngine.objects.filter(
            company=user_company,
            active=True
        ).select_related('engine', 'company').prefetch_related('engine__models')

    @action(detail=True, methods=['get'])
    def models(self, request, pk=None):
        """Get available models for a specific company engine."""
        company_engine = self.get_object()
        models = company_engine.engine.get_available_models()
        serializer = EngineModelSerializer(models, many=True)
        return Response(serializer.data)


class RulesGroupViewSet(viewsets.ModelViewSet):
    """ViewSet for RulesGroup model."""
    serializer_class = RulesGroupSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter rules groups by user's company."""
        user_company = get_user_company(self.request.user)
        return RulesGroup.objects.filter(
            Q(company=user_company) | Q(company__isnull=True)
        ).prefetch_related('rules')


class RuleViewSet(viewsets.ModelViewSet):
    """ViewSet for Rule model."""
    serializer_class = RuleSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter rules by user's company."""
        user_company = get_user_company(self.request.user)
        return Rule.objects.filter(
            Q(rules_group__company=user_company) | Q(rules_group__company__isnull=True)
        ).select_related('rules_group')


class ConversationViewSet(viewsets.ModelViewSet):
    """ViewSet for Conversation model."""
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter conversations by current user."""
        return Conversation.objects.filter(user=self.request.user).prefetch_related('messages')

    def get_serializer_class(self):
        """Use lightweight serializer for list view."""
        if self.action == 'list':
            return ConversationListSerializer
        return ConversationSerializer

    def perform_create(self, serializer):
        """Set user when creating conversation."""
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
        return Message.objects.filter(conversation__user=self.request.user).select_related('conversation')


class AlertViewSet(viewsets.ModelViewSet):
    """ViewSet for Alert model."""
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """Filter alerts by user's company."""
        user_company = get_user_company(self.request.user)
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
        user_company = get_user_company(request.user)
        alerts = Alert.objects.filter(company=user_company, resolved=False).select_related('user', 'company', 'rule', 'prompt')

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
        user_company = get_user_company(self.request.user)
        return AuditLog.objects.filter(user__profile__company=user_company).select_related('user')


# ==================== CHAT API ====================

@api_view(['POST'])
@chat_rate_limit
def chat_send_message(request):
    """
    API endpoint for sending chat messages (rate limited to 30 per minute).
    Handles message validation, AI response generation, and rule checking.
    """
    user = request.user

    # Ensure Profile and Company exist
    if not hasattr(user, 'profile'):
        default_company, _ = Company.objects.get_or_create(name="Default Company")
        Profile.objects.create(user=user, company=default_company)
        user.refresh_from_db()

    profile = user.profile
    company = profile.company

    # Get request data
    conversation_id = request.data.get('conversation_id')
    prompt_text = request.data.get('content', '').strip()
    engine_id = request.data.get('engine_id')
    model_id = request.data.get('model_id')

    # Get or create conversation
    conversation = None
    if conversation_id:
        conversation = get_object_or_404(Conversation, id=conversation_id, user=user)

    # Determine which engine to use
    available_engines = CompanyEngine.objects.filter(
        company=profile.company,
        active=True
    ).select_related('engine').prefetch_related('engine__models')

    current_engine = None
    if engine_id:
        current_engine = available_engines.filter(id=engine_id).first()
    elif profile.default_engine:
        current_engine = available_engines.filter(id=profile.default_engine.id).first()
    else:
        current_engine = available_engines.first()

    if not current_engine:
        return Response({
            'error': 'No AI engine configured. Please contact your administrator.'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Determine which model to use
    current_model = None
    if current_engine:
        available_models = current_engine.engine.models.filter(active=True)

        if model_id:
            current_model = available_models.filter(id=model_id).first()
        elif profile.default_model and profile.default_model.engine_id == current_engine.engine_id:
            current_model = available_models.filter(id=profile.default_model.id).first()
        else:
            current_model = available_models.first()

    # Get API settings
    api_key = current_engine.api_key
    base_url = current_engine.engine.base_url if current_engine.engine.base_url else None
    model_name = current_model.model_id if current_model else current_engine.engine.default_model
    connector_type = current_engine.engine.connector_type or "openai"

    if not api_key or api_key.strip() == '':
        return Response({
            'error': 'No API key configured for the selected AI engine.',
            'engine_name': current_engine.name
        }, status=status.HTTP_400_BAD_REQUEST)

    if not prompt_text:
        return Response({
            'error': 'Please enter a message.'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Create new conversation if needed
    if not conversation:
        title = prompt_text[:50]
        conversation = Conversation.objects.create(
            user=user,
            title=title + ('...' if len(title) == 50 else '')
        )

    # Create user message
    user_message = Message.objects.create(
        conversation=conversation,
        role='user',
        content=prompt_text
    )

    # Create prompt for audit/tracking
    prompt_obj = Prompt.objects.create(
        user=user,
        conversation=conversation,
        content=prompt_text,
        model_used=model_name
    )

    # Validate prompt against rules
    blocked = False
    blocked_rules_data = []
    alerts_data = []

    try:
        prompt_matches, prompt_matched_rules = validate_prompt(user, prompt_text, prompt_obj, None, 'prompts')

        # Simple blocking logic: all matched rules block the message
        if prompt_matched_rules:
            # Create alerts for all matched rules
            for rule_data in prompt_matched_rules:
                try:
                    from front.models import Rule
                    rule = Rule.objects.get(id=rule_data['id'])

                    alert_description = (
                        f"Prompt blocked by rule '{rule.name}'. "
                        f"The message was not sent to the LLM."
                    )

                    Alert.objects.create(
                        user=user,
                        company=company,
                        prompt=prompt_obj,
                        rule=rule,
                        severity=rule_data.get('severity', 'medium'),
                        description=alert_description
                    )

                    log_action(user, 'blocking_alert_created', {
                        'rule_name': rule.name,
                        'severity': rule_data.get('severity', 'medium'),
                        'prompt_id': prompt_obj.id,
                        'conversation_id': conversation.id
                    }, request)

                except Rule.DoesNotExist:
                    import logging
                    logging.warning(f"Rule {rule_data.get('name', 'unknown')} not found for alert creation")

            # Mark as blocked
            prompt_obj.filtered = True
            prompt_obj.save()
            user_message.blocked = True
            user_message.save()
            blocked = True
            blocked_rules_data = [{'name': r['name'], 'severity': r['severity'], 'description': r['description']} for r in prompt_matched_rules]

    except Exception as validation_error:
        import logging
        logging.error(f"Error validating prompt: {validation_error}")

    # Log the action
    log_action(user, 'api_prompt_sent', {
        'prompt_id': prompt_obj.id,
        'conversation_id': conversation.id,
        'content_length': len(prompt_text),
        'blocked': blocked,
        'engine': current_engine.display_name,
        'model': model_name
    }, request)

    response_data = {
        'success': True,
        'conversation_id': conversation.id,
        'blocked': blocked,
        'blocked_rules': blocked_rules_data,
        'user_message': MessageSerializer(user_message).data
    }

    # Only send to LLM if not blocked
    if not blocked:
        try:
            # Create connector
            connector = get_connector(connector_type, api_key, base_url)

            # Build messages history for context
            chat_messages = []
            for msg in conversation.messages.exclude(id=user_message.id):
                if msg.role in ['user', 'assistant']:
                    chat_messages.append(ChatMessage(
                        role=msg.role,
                        content=msg.content
                    ))

            # Add current message
            chat_messages.append(ChatMessage(
                role="user",
                content=prompt_text
            ))

            # Use connector to send message
            ai_response = connector.chat(
                messages=chat_messages,
                model=model_name,
                max_tokens=1000,
                temperature=0.6,
            )

            # Save assistant response as message
            assistant_message = Message.objects.create(
                conversation=conversation,
                role='assistant',
                content=ai_response.content,
                tokens_used=ai_response.tokens_used
            )

            # Save Response object for tracking
            ResponseModel.objects.create(
                prompt=prompt_obj,
                content=ai_response.content,
                tokens_used=ai_response.tokens_used
            )

            response_data['assistant_message'] = MessageSerializer(assistant_message).data

            log_action(user, 'api_response_received', {
                'prompt_id': prompt_obj.id,
                'conversation_id': conversation.id,
                'tokens_used': ai_response.tokens_used
            }, request)

        except Exception as e:
            import logging
            logging.error(f"Error generating AI response: {e}")
            response_data['error'] = str(e)
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response(response_data)


@api_view(['GET'])
def dashboard_stats(request):
    """Get dashboard statistics for the current user's company."""
    user_company = get_user_company(request.user)

    stats = {
        'total_prompts': Prompt.objects.filter(user__profile__company=user_company).count(),
        'blocked_prompts': Prompt.objects.filter(user__profile__company=user_company, filtered=True).count(),
        'active_rules': Rule.objects.filter(
            Q(rules_group__company=user_company) | Q(rules_group__company__isnull=True),
            active=True
        ).count(),
        'pending_alerts': Alert.objects.filter(company=user_company, resolved=False).count(),
        'total_conversations': Conversation.objects.filter(user__profile__company=user_company).count(),
    }

    # Add admin-specific stats
    if request.user.is_superuser:
        stats['total_users'] = Profile.objects.filter(company=user_company).count()
        stats['total_departments'] = Department.objects.filter(company=user_company).count()
        stats['active_engines'] = CompanyEngine.objects.filter(company=user_company, active=True).count()

    return Response(stats)

