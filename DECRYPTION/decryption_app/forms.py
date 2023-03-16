from django import forms

file_choices=((0,'Cipher Text'), (1,'Image File'), (2,'Log File'), (3,'ZIP File'))

class Wru(forms.Form):
    options = forms.ChoiceField(choices=file_choices, widget=forms.RadioSelect(attrs={'size': '40'}))