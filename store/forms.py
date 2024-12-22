from django import forms

class ForgotPasswordForm(forms.Form):
    email_or_mobile = forms.CharField(label='Email or Mobile Number', max_length=255)