import pyotp

from django import forms
from django.contrib.auth.models import User


class OTPForm(forms.Form):
    token = forms.CharField(label='Token', strip=True)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request')  # Fail if not present, dev error
        self.user_cache = None
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()

        user_pk = self.request.session.get('user_pk', None)
        if not user_pk:
            raise forms.ValidationError('Login session expired. Please try again.',
                                        code='expired')

        user = User.objects.get(pk=user_pk)
        if not user.profile.otp_secret:
            raise forms.ValidationError('MFA not enabled for this user. Please try again.',
                                        code='mfa-disabled')

        totp = pyotp.TOTP(user.profile.otp_secret)
        token_valid = totp.verify(cleaned_data['token'], valid_window=2)
        if not token_valid:
            raise forms.ValidationError('Invalid MFA token. Please try again.',
                                        code='invalid-token')

        self.user_cache = user
        return cleaned_data

    def get_user(self):
        return self.user_cache


class ProfileForm(forms.Form):
    mfa_enabled = forms.BooleanField(label='Enable MFA', required=False)
