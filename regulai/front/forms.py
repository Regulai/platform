from django import forms

from .models import ObfuscationConfig


class ObfuscationConfigForm(forms.ModelForm):
    class Meta:
        model = ObfuscationConfig
        fields = ['name', 'backend', 'api_url', 'detect', 'language', 'active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Company privacy detector'}),
            'backend': forms.Select(attrs={'class': 'form-select'}),
            'api_url': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://pasteguard.example'}),
            'detect': forms.Select(attrs={'class': 'form-select'}),
            'language': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'es / en'}),
            'active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:
            self.initial['backend'] = 'local'
