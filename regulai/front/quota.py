from django.utils import timezone
from front.models import Prompt, Message


def get_current_month_range():
    """Return (start_of_month, now) for filtering current month usage."""
    now = timezone.now()
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return start_of_month, now


def get_company_prompt_count(company):
    start, now = get_current_month_range()
    return Prompt.objects.filter(
        user__profile__company=company,
        created_at__gte=start,
        created_at__lte=now,
    ).count()


def get_company_file_count(company):
    start, now = get_current_month_range()
    return Message.objects.filter(
        conversation__user__profile__company=company,
        role='user',
        file_name__isnull=False,
        created_at__gte=start,
        created_at__lte=now,
    ).exclude(file_name='').count()


def get_department_prompt_count(department):
    start, now = get_current_month_range()
    return Prompt.objects.filter(
        user__profile__department=department,
        created_at__gte=start,
        created_at__lte=now,
    ).count()


def get_department_file_count(department):
    start, now = get_current_month_range()
    return Message.objects.filter(
        conversation__user__profile__department=department,
        role='user',
        file_name__isnull=False,
        created_at__gte=start,
        created_at__lte=now,
    ).exclude(file_name='').count()


def get_usage_info(profile):
    """Full usage info with dual-layer checks: company + department."""
    company = profile.company
    department = profile.department

    company_prompt_count = get_company_prompt_count(company)
    company_file_count = get_company_file_count(company)

    company_prompt_limit = company.monthly_prompt_limit
    company_file_limit = company.monthly_file_limit
    max_file_size_mb = company.max_file_size_mb

    dept_prompt_limit = None
    dept_file_limit = None
    dept_prompt_count = 0
    dept_file_count = 0

    if department:
        dept_prompt_limit = department.monthly_prompt_limit
        dept_file_limit = department.monthly_file_limit
        if dept_prompt_limit is not None:
            dept_prompt_count = get_department_prompt_count(department)
        if dept_file_limit is not None:
            dept_file_count = get_department_file_count(department)

    # Blocked if company limit hit OR department limit hit
    prompt_blocked_company = company_prompt_limit > 0 and company_prompt_count >= company_prompt_limit
    prompt_blocked_dept = dept_prompt_limit is not None and dept_prompt_limit > 0 and dept_prompt_count >= dept_prompt_limit
    file_blocked_company = company_file_limit > 0 and company_file_count >= company_file_limit
    file_blocked_dept = dept_file_limit is not None and dept_file_limit > 0 and dept_file_count >= dept_file_limit

    return {
        # Company level
        'company_prompt_limit': company_prompt_limit,
        'company_file_limit': company_file_limit,
        'company_prompt_count': company_prompt_count,
        'company_file_count': company_file_count,
        'company_prompts_unlimited': company_prompt_limit == 0,
        'company_files_unlimited': company_file_limit == 0,
        # Department level
        'dept_prompt_limit': dept_prompt_limit,
        'dept_file_limit': dept_file_limit,
        'dept_prompt_count': dept_prompt_count,
        'dept_file_count': dept_file_count,
        'has_dept_prompt_limit': dept_prompt_limit is not None,
        'has_dept_file_limit': dept_file_limit is not None,
        # Block flags (either layer can block)
        'prompt_blocked': prompt_blocked_company or prompt_blocked_dept,
        'file_blocked': file_blocked_company or file_blocked_dept,
        'prompt_blocked_reason': 'company' if prompt_blocked_company else ('department' if prompt_blocked_dept else None),
        'file_blocked_reason': 'company' if file_blocked_company else ('department' if file_blocked_dept else None),
        # File size
        'max_file_size_mb': max_file_size_mb,
    }


def check_prompt_allowed(profile):
    """Quick check: can this user send a prompt? Returns (allowed, message)."""
    info = get_usage_info(profile)
    if info['prompt_blocked']:
        if info['prompt_blocked_reason'] == 'company':
            return False, f"Company monthly prompt limit reached ({info['company_prompt_count']}/{info['company_prompt_limit']}). Resets on the 1st of next month."
        else:
            return False, f"Department monthly prompt limit reached ({info['dept_prompt_count']}/{info['dept_prompt_limit']}). Resets on the 1st of next month."
    return True, ""


def check_file_allowed(profile):
    """Quick check: can this user attach a file? Returns (allowed, message)."""
    info = get_usage_info(profile)
    if info['file_blocked']:
        if info['file_blocked_reason'] == 'company':
            return False, f"Company monthly file limit reached ({info['company_file_count']}/{info['company_file_limit']}). Resets on the 1st of next month."
        else:
            return False, f"Department monthly file limit reached ({info['dept_file_count']}/{info['dept_file_limit']}). Resets on the 1st of next month."
    return True, ""


def check_file_size(profile, file_size_bytes):
    """Check if a file exceeds the company max file size. Returns (allowed, message)."""
    max_mb = profile.company.max_file_size_mb
    file_size_mb = file_size_bytes / (1024 * 1024)
    if file_size_mb > max_mb:
        return False, f"File size ({file_size_mb:.1f} MB) exceeds the maximum allowed ({max_mb} MB)."
    return True, ""
