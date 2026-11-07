from django.db import migrations, models
from django.db.models import F


def infer_company(apps, schema_editor):
    Prompt = apps.get_model('front', 'Prompt')
    Profile = apps.get_model('front', 'Profile')
    alias = schema_editor.connection.alias
    last_pk = 0
    while True:
        rows = list(Prompt.objects.using(alias).only('pk', 'user_id').filter(company__isnull=True, pk__gt=last_pk)
            .order_by('pk')[:1000])
        if not rows:
            break
        last_pk = rows[-1].pk
        companies = dict(Profile.objects.using(alias).filter(user_id__in={row.user_id for row in rows})
            .values_list('user_id', 'company_id'))
        inferred = []
        for row in rows:
            if row.user_id in companies:
                row.company_id = row.historical_company_id = companies[row.user_id]
                inferred.append(row)
        Prompt.objects.using(alias).bulk_update(inferred, ['company', 'historical_company_id'], batch_size=1000)


def restore_company(apps, schema_editor):
    Prompt = apps.get_model('front', 'Prompt')
    rows = Prompt.objects.using(schema_editor.connection.alias)
    while True:
        ids = list(rows.filter(historical_company_id__isnull=False, company_id=F('historical_company_id'))
            .order_by('pk').values_list('pk', flat=True)[:1000])
        if not ids:
            break
        rows.filter(pk__in=ids).update(company=None)


class Migration(migrations.Migration):
    dependencies = [('front', '0030_enginemodel_reasoning')]
    operations = [
        migrations.AddField(model_name='prompt', name='historical_company_id',
            field=models.PositiveBigIntegerField(null=True, blank=True, editable=False)),
        migrations.RunPython(infer_company, restore_company),
    ]
