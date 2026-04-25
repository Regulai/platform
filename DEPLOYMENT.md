# Deploying regulAI on Railway

Step-by-step guide to get your own instance of regulAI running on [Railway](https://railway.app) in minutes.

## Step 1 — Create a project on Railway

1. Create an account at [railway.app](https://railway.app)
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Connect your GitHub account
5. Search and select `Regulai/platform`
6. Select the `main` branch

> **Tip:** Railway automatically detects that it's a Python/Django project and configures the build.

## Step 2 — Configure environment variables

Go to your service in Railway → **Variables**, and add the following:

| Variable | Value | Description |
|---|---|---|
| `SECRET_KEY` | *(generate one)* | Django secret key. Generate with: `python -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `DEBUG` | `False` | Always `False` in production |
| `ALLOWED_HOSTS` | `*.up.railway.app` | Allowed domains |
| `CSRF_TRUSTED_ORIGINS` | `https://your-app.up.railway.app` | Trusted CSRF origins |
| `ALLOW_REGISTRATION` | `True` | Enable public registration (to create first user) |

## Step 3 — Create admin user

You have two options:

### Option A — From the web (with registration enabled)

With `ALLOW_REGISTRATION=True`, a **Signup** link appears on the Login page:

1. Go to `your-app.up.railway.app`
2. On the Login page, click the **Signup** link
3. Create your account
4. Promote to admin from Railway console:

```bash
railway run python manage.py shell
```

```python
from django.contrib.auth.models import User
u = User.objects.first()
u.is_staff = True
u.is_superuser = True
u.save()
```

### Option B — From the console (without registration)

Use Railway's console to create the admin user directly:

```bash
railway run python manage.py createsuperuser
```

Enter username, email and password when prompted. The user is created directly as superadmin.

> **Tip:** Option B doesn't require `ALLOW_REGISTRATION=True`. The user is created directly as superadmin.

## Step 4 — Disable public registration

Once your admin user is created, disable public registration by changing the variable in Railway:

```
ALLOW_REGISTRATION = False
```

This hides the Signup link on the Login page. Only existing users will be able to access the platform.

### Recommended flow

```
ALLOW_REGISTRATION=True → Create user → Promote to admin → ALLOW_REGISTRATION=False
```

## Step 5 — Automatic deployments

Every push to `main` triggers an automatic deployment. Railway handles:

1. **Build** — Installs Python dependencies from `requirements.txt`
2. **Migrate** — Applies Django database migrations
3. **Collect static** — Gathers static files with WhiteNoise
4. **Deploy** — Starts Gunicorn as the WSGI server

The `railway.toml` file controls the entire process:

```toml
[build]
builder = "NIXPACKS"

[deploy]
startCommand = "cd regulai && python manage.py migrate --noinput && python manage.py collectstatic --noinput && gunicorn regulai.wsgi:application --bind 0.0.0.0:$PORT --workers 2"
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 3
```

## Environment variables reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | Yes | *(insecure default)* | Django secret key for cryptographic signing |
| `DEBUG` | No | `False` | Enable debug mode |
| `ALLOWED_HOSTS` | No | `*` | Comma-separated list of allowed hosts |
| `CSRF_TRUSTED_ORIGINS` | No | `https://*.up.railway.app` | Comma-separated list of trusted CSRF origins |
| `ALLOW_REGISTRATION` | No | `True` | Enable/disable public user registration |
| `CORS_EXTRA_ORIGINS` | No | *(empty)* | Additional CORS origins (comma-separated) |
