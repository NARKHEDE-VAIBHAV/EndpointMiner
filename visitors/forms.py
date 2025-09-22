from django import forms
from .models import Visitor

class VisitorForm(forms.ModelForm):
    class Meta:
        model = Visitor
        fields = ['first_name', 'middle_name', 'last_name', 'mobile', 'num_people', 'address']
        widgets = {
            'address': forms.Textarea(attrs={'rows':3}),
        }
