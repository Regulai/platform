from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create router for viewsets
router = DefaultRouter()
router.register(r'companies', views.CompanyViewSet, basename='company')
router.register(r'roles', views.RoleViewSet, basename='role')
router.register(r'departments', views.DepartmentViewSet, basename='department')
router.register(r'profiles', views.ProfileViewSet, basename='profile')
router.register(r'engines', views.EngineViewSet, basename='engine')
router.register(r'company-engines', views.CompanyEngineViewSet, basename='company-engine')
router.register(r'rules-groups', views.RulesGroupViewSet, basename='rules-group')
router.register(r'rules', views.RuleViewSet, basename='rule')
router.register(r'conversations', views.ConversationViewSet, basename='conversation')
router.register(r'messages', views.MessageViewSet, basename='message')
router.register(r'alerts', views.AlertViewSet, basename='alert')
router.register(r'audit-logs', views.AuditLogViewSet, basename='audit-log')

app_name = 'api'

urlpatterns = [
    # Authentication endpoints
    path('auth/login/', views.api_login, name='login'),
    path('auth/logout/', views.api_logout, name='logout'),
    path('auth/me/', views.api_me, name='me'),

    # Chat endpoints
    path('chat/send/', views.chat_send_message, name='chat-send'),

    # Dashboard endpoints
    path('dashboard/stats/', views.dashboard_stats, name='dashboard-stats'),

    # Include router URLs
    path('', include(router.urls)),
]
