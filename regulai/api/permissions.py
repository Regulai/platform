from rest_framework import permissions


class IsSecurityStaff(permissions.BasePermission):
    """
    Permission to check if user is staff or superuser.
    Used for security-related endpoints (alerts, audit logs, etc.)
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser)


class IsCompanyAdmin(permissions.BasePermission):
    """
    Permission to check if user is a superuser (company admin).
    Used for admin-level operations.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner
        return obj.user == request.user


class IsSameCompany(permissions.BasePermission):
    """
    Permission to check if the user belongs to the same company as the object.
    """
    def has_object_permission(self, request, view, obj):
        if not hasattr(request.user, 'profile'):
            return False

        user_company = request.user.profile.company

        # Check different model types
        if hasattr(obj, 'company'):
            return obj.company == user_company
        elif hasattr(obj, 'user') and hasattr(obj.user, 'profile'):
            return obj.user.profile.company == user_company

        return False


class CanManageRules(permissions.BasePermission):
    """
    Permission for users who can manage rules (staff or superuser).
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Staff and superusers can manage rules
        if request.user.is_staff or request.user.is_superuser:
            return True

        return False

    def has_object_permission(self, request, view, obj):
        # Allow read for all authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True

        # Only staff/superuser can modify
        return request.user.is_staff or request.user.is_superuser
