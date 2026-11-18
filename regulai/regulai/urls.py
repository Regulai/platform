"""
URL configuration for regulai project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

# Use rate-limited admin site (AUTH-05)
from regulai.admin import rate_limited_admin_site, setup_admin

# Setup admin after apps are loaded
try:
    setup_admin()
except Exception:
    pass  # Will be set up on first request if import fails during startup


urlpatterns = [
    path('admin/', rate_limited_admin_site.urls),
    path('api/', include('api.urls')),
    path("", include("front.urls")),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
