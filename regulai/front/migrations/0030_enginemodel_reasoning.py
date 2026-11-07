from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('front', '0029_model_price_units')]
    operations = [migrations.AddField(model_name='enginemodel', name='reasoning',
        field=models.BooleanField(default=False))]
