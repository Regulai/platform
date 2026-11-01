from django.urls import path
from .ai_connections import ai_connections
from .agents import views as agent_views
from .agents import skill_views
from .agents import artifact_preview
from .chat_ui import request_receipt, request_evidence, request_stream, request_cancel
from .policy_simulator import policy_simulator, policy_simulator_activate
from .views import (
    home_view, login_view, logout_view, signup_view, profile_view,
    chat_view, chat_new, chat_delete, chat_send_message, chat_download_file, chat_select_engine, chat_select_model, dashboard_view,
    rulesgroups_list, rulesgroup_detail, rulesgroup_create, rulesgroup_edit, rulesgroup_delete,
    rulesgroup_activate_all, rulesgroup_deactivate_all,
    rules_list, rule_detail, rule_create, rule_edit, rule_delete, rule_toggle,
    rules_community_list, rule_community_configure, rule_community_activate, rules_community_sync,
    alerts_list, alert_detail, alert_resolve, alert_unresolve, alert_delete, alerts_resolve_all,
    auditlogs_list, auditlog_detail, auditlog_delete, auditlogs_clear,
    prompts_list, prompt_detail,
    users_list, user_create, user_edit, user_delete,
    company_settings,
    departments_list, department_create, department_edit, department_delete,
    engines_list, engine_create, engine_edit, engine_delete, engine_toggle,
    model_create, model_edit, model_toggle, model_delete,
    obfuscation_list, obfuscation_create, obfuscation_edit, obfuscation_delete, obfuscation_toggle,
)

app_name = 'front'

urlpatterns = [
    path('chat/agent/artifacts/<uuid:artifact_id>/preview/', artifact_preview.preview, name='agent_artifact_preview'),
    path('skills/', skill_views.library, name='skills_library'),
    path('skills/conversations/<int:conversation_id>/preference/', skill_views.preference, name='skill_preference'),
    path('skills/catalog/<slug:candidate>/', skill_views.detail, name='skill_detail'),
    path('skills/import/inspect/', skill_views.inspect_package, name='skill_inspect'),
    path('skills/installations/', skill_views.installations, name='skill_install'),
    path('skills/installations/<uuid:installation_id>/', skill_views.installed_detail, name='skill_installed_detail'),
    path('skills/operations/<uuid:operation_id>/', skill_views.operation, name='skill_operation'),
    path('skills/installations/<uuid:installation_id>/update/', skill_views.installations, name='skill_update'),
    path('skills/installations/<uuid:installation_id>/<str:action>/', skill_views.mutate, name='skill_mutate'),
    path('internal/agents/sandbox-cleanup/', agent_views.worker_sandbox_cleanup, name='agent_sandbox_cleanup'),
    path('chat/agent/exports/<uuid:export_id>/decision/', agent_views.export_decision, name='agent_export_decision'),
    path('chat/agent/runs/<uuid:run_id>/recover-export/', agent_views.export_recovery, name='agent_export_recovery'),
    path('chat/agent/documents/search/', agent_views.document_search, name='agent_document_search'),
    path('internal/agents/inference/', agent_views.inference, name='agent_inference'),
    path('internal/agents/tool-results/', agent_views.result, name='agent_tool_result'),
    path('internal/agents/authorize-tool/', agent_views.authorize, name='agent_authorize_tool'),
    path('internal/agents/claim/', agent_views.worker_claim, name='agent_worker_claim'),
    path('internal/agents/checkpoints/', agent_views.worker_checkpoints, name='agent_worker_checkpoints'),
    path('internal/agents/run/<str:operation>/', agent_views.execution_operation, name='agent_execution_operation'),
    path('chat/agent/runs/<uuid:run_id>/', agent_views.run_status, name='agent_run_status'),
    path('chat/agent/runs/<uuid:run_id>/events/', agent_views.events, name='agent_events'),
    path('chat/agent/runs/<uuid:run_id>/cancel/', agent_views.cancel_run, name='agent_cancel'),
    path('chat/agent/runs/<uuid:run_id>/resume/', agent_views.resume_run, name='agent_resume'),
    path('chat/agent/runs/<uuid:run_id>/operations/<int:operation_id>/', agent_views.operation_details, name='agent_operation_details'),
    path('chat/agent/artifacts/<uuid:artifact_id>/download/', agent_views.download, name='agent_download'),
    path('chat/agent/artifacts/<uuid:artifact_id>/pages/<int:number>/', agent_views.document_page, name='agent_document_page'),
    path('chat/agent/artifacts/<uuid:artifact_id>/review/', agent_views.document_review, name='agent_document_review'),
    # Home
    path("", home_view, name="home"),

    # Auth & Profile
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("signup/", signup_view, name="signup"),
    path("profile/", profile_view, name="profile"),

    # Dashboard & Chat
    path("dashboard/", dashboard_view, name="dashboard"),
    path("policies/simulator/", policy_simulator, name="policy_simulator"),
    path("policies/simulator/activate/", policy_simulator_activate, name="policy_simulator_activate"),
    path("index", chat_view, name="index"),
    path("chat/", chat_view, name="chat"),
    path("chat/new/", chat_new, name="chat_new"),
    path("chat/send/", chat_send_message, name="chat_send"),
    path("chat/requests/<uuid:request_id>/receipt/", request_receipt, name="chat_request_receipt"),
    path("chat/requests/<uuid:request_id>/evidence/", request_evidence, name="chat_request_evidence"),
    path("chat/requests/<uuid:request_id>/stream/", request_stream, name="chat_request_stream"),
    path("chat/requests/<uuid:request_id>/cancel/", request_cancel, name="chat_request_cancel"),
    path("chat/select-engine/", chat_select_engine, name="chat_select_engine"),
    path("chat/select-model/", chat_select_model, name="chat_select_model"),
    path("chat/<int:conversation_id>/send/", chat_send_message, name="chat_send_conversation"),
    path("chat/<int:conversation_id>/", chat_view, name="chat_conversation"),
    path("chat/<int:conversation_id>/delete/", chat_delete, name="chat_delete"),
    path("chat/download/<int:message_id>/", chat_download_file, name="chat_download_file"),

    # Rules Groups
    path("rules/groups/", rulesgroups_list, name="rulesgroups_list"),
    path("rules/groups/create/", rulesgroup_create, name="rulesgroup_create"),
    path("rules/groups/<int:pk>/", rulesgroup_detail, name="rulesgroup_detail"),
    path("rules/groups/<int:pk>/edit/", rulesgroup_edit, name="rulesgroup_edit"),
    path("rules/groups/<int:pk>/delete/", rulesgroup_delete, name="rulesgroup_delete"),
    path("rules/groups/<int:pk>/activate-all/", rulesgroup_activate_all, name="rulesgroup_activate_all"),
    path("rules/groups/<int:pk>/deactivate-all/", rulesgroup_deactivate_all, name="rulesgroup_deactivate_all"),

    # Rules
    path("rules/", rules_list, name="rules_list"),
    path("rules/create/", rule_create, name="rule_create"),
    path("rules/<int:pk>/", rule_detail, name="rule_detail"),
    path("rules/<int:pk>/edit/", rule_edit, name="rule_edit"),
    path("rules/<int:pk>/delete/", rule_delete, name="rule_delete"),
    path("rules/<int:pk>/toggle/", rule_toggle, name="rule_toggle"),

    # Rules Community
    path("rules/community/", rules_community_list, name="rules_community_list"),
    path("rules/community/sync/", rules_community_sync, name="rules_community_sync"),
    path("rules/community/<int:pk>/configure/", rule_community_configure, name="rule_community_configure"),
    path("rules/community/<int:pk>/activate/", rule_community_activate, name="rule_community_activate"),

    # Alerts
    path("alerts/", alerts_list, name="alerts_list"),
    path("alerts/resolve-all/", alerts_resolve_all, name="alerts_resolve_all"),
    path("alerts/<int:pk>/", alert_detail, name="alert_detail"),
    path("alerts/<int:pk>/resolve/", alert_resolve, name="alert_resolve"),
    path("alerts/<int:pk>/unresolve/", alert_unresolve, name="alert_unresolve"),
    path("alerts/<int:pk>/delete/", alert_delete, name="alert_delete"),

    # Audit Logs (Settings - Admin only)
    path("settings/audit-logs/", auditlogs_list, name="auditlogs_list"),
    path("settings/audit-logs/clear/", auditlogs_clear, name="auditlogs_clear"),
    path("settings/audit-logs/<int:pk>/", auditlog_detail, name="auditlog_detail"),
    path("settings/audit-logs/<int:pk>/delete/", auditlog_delete, name="auditlog_delete"),

    # Prompts
    path("prompts/", prompts_list, name="prompts_list"),
    path("prompts/<int:pk>/", prompt_detail, name="prompt_detail"),

    # User Management (Settings)
    path("settings/users/", users_list, name="users_list"),
    path("settings/users/create/", user_create, name="user_create"),
    path("settings/users/<int:pk>/edit/", user_edit, name="user_edit"),
    path("settings/users/<int:pk>/delete/", user_delete, name="user_delete"),

    # Company Settings
    path("settings/company/", company_settings, name="company_settings"),
    path("settings/ai/", ai_connections, name="ai_connections"),

    # Department Management (Settings)
    path("settings/departments/", departments_list, name="departments_list"),
    path("settings/departments/create/", department_create, name="department_create"),
    path("settings/departments/<int:pk>/edit/", department_edit, name="department_edit"),
    path("settings/departments/<int:pk>/delete/", department_delete, name="department_delete"),

    # Engine Management (Settings)
    path("settings/engines/", engines_list, name="engines_list"),
    path("settings/engines/create/", engine_create, name="engine_create"),
    path("settings/engines/<int:pk>/edit/", engine_edit, name="engine_edit"),
    path("settings/engines/<int:pk>/delete/", engine_delete, name="engine_delete"),
    path("settings/engines/<int:pk>/toggle/", engine_toggle, name="engine_toggle"),

    # Engine Models Management
    path("settings/engines/<int:engine_pk>/models/create/", model_create, name="model_create"),
    path("settings/models/<int:pk>/edit/", model_edit, name="model_edit"),
    path("settings/models/<int:pk>/toggle/", model_toggle, name="model_toggle"),
    path("settings/models/<int:pk>/delete/", model_delete, name="model_delete"),

    # Obfuscation
    path("obfuscation/", obfuscation_list, name="obfuscation_list"),
    path("obfuscation/create/", obfuscation_create, name="obfuscation_create"),
    path("obfuscation/<int:pk>/edit/", obfuscation_edit, name="obfuscation_edit"),
    path("obfuscation/<int:pk>/delete/", obfuscation_delete, name="obfuscation_delete"),
    path("obfuscation/<int:pk>/toggle/", obfuscation_toggle, name="obfuscation_toggle"),
]
