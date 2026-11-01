from django.db import migrations, models
from django.core.validators import MinValueValidator
import front.models


class Migration(migrations.Migration):
    dependencies = [('front', '0028_auditlog_company')]

    operations = [
        migrations.AlterField(model_name='enginemodel', name='input_price',
            field=models.DecimalField(max_digits=18, decimal_places=8, null=True, blank=True,
                validators=[MinValueValidator(0), front.models.validate_price_per_million],
                help_text='USD per million input tokens; 0 means free, blank means unknown.')),
        migrations.AlterField(model_name='enginemodel', name='output_price',
            field=models.DecimalField(max_digits=18, decimal_places=8, null=True, blank=True,
                validators=[MinValueValidator(0), front.models.validate_price_per_million],
                help_text='USD per million output tokens; 0 means free, blank means unknown.')),
    ]
