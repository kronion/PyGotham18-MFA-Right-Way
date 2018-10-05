import pyotp

from django.contrib.auth import login, REDIRECT_FIELD_NAME
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import LoginView
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils.http import is_safe_url
from django.views.generic.edit import FormView

from users.forms import OTPForm, ProfileForm


class MaybeLoginView(LoginView):
    """
    Slightly modified version of Django's built-in LoginView. Redirects client
    to the OTPView if MFA is enabled on the user attempting to authenticate.
    """

    template_name = 'auth/login.html'

    def form_valid(self, form):
        user = form.get_user()

        # If the OTP secret is non-empty, we take it to mean that MFA is enabled
        if user.profile.otp_secret:
            # Store user pk in the AnonymousUser's session so that we can later
            # find the correct MFA token in the next step
            self.request.session['user_pk'] = user.pk

            next_url = self.get_redirect_url()
            query_string = '?{}={}'.format(self.redirect_field_name, next_url) if next_url else ''
            return redirect('{}{}'.format(reverse('token'), query_string))
        else:
            login(self.request, user)

        return super().form_valid(form)


class OTPView(FormView):
    """
    Manages requests associated with the OTPForm. Note that the form is
    responsible for determining if an OTP is valid, but this class handles
    the actual Django `login()`.
    """

    form_class = OTPForm
    success_url = reverse_lazy('index')
    template_name = 'auth/otp.html'

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['request'] = self.request
        return kwargs

    def form_valid(self, form):
        user = form.get_user()
        login(self.request, user)
        return super().form_valid(form)

    def form_invalid(self, form):
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(self. request, error)
        return redirect(reverse('login'))


class ProfileView(FormView):
    """
    Manages requests associated with the ProfileForm.
    """

    form_class = ProfileForm
    template_name = 'users/profile.html'

    def form_valid(self, form):
        user = self.request.user
        mfa_enabled = form.cleaned_data['mfa_enabled']

        secret = pyotp.random_base32() if mfa_enabled else ''
        user.profile.otp_secret = secret
        user.profile.save()

        secret_url = self.get_secret_url()

        return self.render_to_response(self.get_context_data(form=form, secret_url=secret_url))

    def get_context_data(self, **kwargs):
        user = self.request.user
        if 'secret_url' not in kwargs:
            kwargs['secret_url'] = self.get_secret_url()
        return super().get_context_data(**kwargs)

    def get_initial(self):
        user = self.request.user
        initial = super().get_initial()
        initial['mfa_enabled'] = True if user.profile.otp_secret else False
        return initial

    def get_secret_url(self):
        user = self.request.user
        otp_secret = user.profile.otp_secret

        secret_url = ''
        if otp_secret:
            secret_url = pyotp.TOTP(otp_secret)\
                    .provisioning_uri(user.username, issuer_name="PyGotham MFA Example")
        return secret_url
