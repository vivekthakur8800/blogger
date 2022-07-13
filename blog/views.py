from tokenize import group
from django.shortcuts import render,HttpResponseRedirect,HttpResponse
from blog.forms import postform, signupform,contactform
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate,login,logout
from blog.models import post
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.contrib.auth.forms import PasswordChangeForm,PasswordResetForm
from django.contrib import messages
# Create your views here.

# homepage
def home(request):
    posts=post.objects.all()
    return render(request,'blog/home.html',{'posts':posts})

# aboutpage
def about(request):
    return render(request,'blog/about.html')

def dashboard(request):
    print("request data: ", request.user)
    print("request data: ", request.user.id)
    if request.user.is_superuser:
        # posts=post.objects.filter(user=request.user.id)
        posts=post.objects.all()
        print("posts: ", posts)
        return render(request,'blog/dashboard.html',{'posts':posts,'name':request.user.first_name,'name2':request.user.last_name})
    if request.user.is_authenticated:
        # posts=post.objects.all()
        posts=post.objects.filter(user=request.user.id)
        print("posts: ", posts)
        return render(request,'blog/dashboard.html',{'posts':posts,'name':request.user.first_name,'name2':request.user.last_name})
    else:
        return HttpResponseRedirect('/login/')

# signup
def signup(request):
    if request.method=='POST':
        fm=signupform(request.POST)
        if fm.is_valid:
            user=fm.save()
            group=Group.objects.get(name='Author')
            user.groups.add(group)
            fm=signupform()
            messages.success(request,'congrats successfully signup')
    else:
        fm=signupform()
    return render(request,'blog/signup.html',{'form':fm})

# login
def userlogin(request):
    if not request.user.is_authenticated:
        if request.method=='POST':
            fm=AuthenticationForm(request=request,data=request.POST)
            if fm.is_valid():
                uname=fm.cleaned_data['username']
                upass=fm.cleaned_data['password']
                user=authenticate(username=uname,password=upass)
                if user is not None:
                    login(request,user)
                    messages.success(request,'congrats successfully Login')
                    return HttpResponseRedirect('/dashboard/')
        else:
            fm=AuthenticationForm()
        return render(request,'blog/login.html',{'form':fm})
    else:
        return HttpResponseRedirect('/dashboard/')

# Logout
def userlogout(request):
    logout(request)
    return HttpResponseRedirect('/login/')

# add post
def addpost(request):
    if request.user.is_authenticated:
        if request.method=='POST':
            fm=postform(request.POST)
            if fm.is_valid():
                user=fm.cleaned_data['user']
                title=fm.cleaned_data['title']
                disc=fm.cleaned_data['disc']
                # print('user_id: ',request.user.id)
                # print('user2: ',user.id)
                if request.user.id==user.id:
                    pst=post(user=user,title=title,disc=disc)
                    pst.save()
                    fm=postform()
                else:
                    messages.success(request,'Incorrect User')
                    return HttpResponseRedirect('/addpost/')
        else:
            fm=postform()
        return render(request,'blog/addpost.html',{'form':fm})
    else:
        return HttpResponseRedirect('/login/')

# Update post
def updatepost(request,id):
    if request.user.is_authenticated:
        if request.method=='POST':
            pi=post.objects.get(pk=id)
            fm=postform(request.POST,instance=pi)
            if fm.is_valid():
                fm.save()
                return HttpResponseRedirect('/dashboard/')
        else:
            pi=post.objects.get(pk=id)
            fm=postform(instance=pi)
        return render(request,'blog/updatepost.html',{'form':fm})
    else:
        return HttpResponseRedirect('/login/')

# delete post
def deletepost(request,id):
    if request.user.is_authenticated:
        if request.method=='POST':
            pi=post.objects.get(pk=id)
            pi.delete()
        return HttpResponseRedirect('/dashboard/')
    else:
        return HttpResponseRedirect('/login/')
#contact
def contact(request):
    if request.method=='POST':
        fm=contactform(request.POST)
        if fm.is_valid():
            fm.save()
            messages.success(request,'your data has been successfully submitted')
            fm=contactform()
    else:
        fm=contactform()
    return render(request,'blog/contact.html',{'form':fm})

#search
def search(request):
    query=request.GET['query']
    posts=post.objects.filter(title__icontains=query)|post.objects.filter(disc__icontains=query)|post.objects.filter(user__username=query)|post.objects.filter(title__startswith=query)|post.objects.filter(disc__startswith=query)
    return render(request,'blog/home.html',{'posts':posts})


from urllib.parse import urlparse, urlunparse

from django.conf import settings

# Avoid shadowing the login() and logout() views below.
from django.contrib.auth import REDIRECT_FIELD_NAME, get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http import HttpResponseRedirect, QueryDict
from django.shortcuts import resolve_url
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
UserModel = get_user_model()

class PasswordContextMixin:
    extra_context = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({"title": self.title, **(self.extra_context or {})})
        return context

class PasswordResetView(PasswordContextMixin, FormView):
    email_template_name = "registration/password_reset_email.html"
    extra_email_context = None
    form_class = PasswordResetForm
    from_email = None
    html_email_template_name = None
    subject_template_name = "registration/password_reset_subject.txt"
    success_url = reverse_lazy("password_reset_done")
    template_name = "blog/resetpassword.html"
    title = _("Password reset")
    token_generator = default_token_generator

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def form_valid(self, form):
        opts = {
            "use_https": self.request.is_secure(),
            "token_generator": self.token_generator,
            "from_email": self.from_email,
            "email_template_name": self.email_template_name,
            "subject_template_name": self.subject_template_name,
            "request": self.request,
            "html_email_template_name": self.html_email_template_name,
            "extra_email_context": self.extra_email_context,
        }
        form.save(**opts)
        return super().form_valid(form)


INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"


class PasswordResetDoneView(PasswordContextMixin, TemplateView):
    template_name = "blog/resetdone.html"
    title = _("Password reset sent")


class PasswordResetConfirmView(PasswordContextMixin, FormView):
    form_class = SetPasswordForm
    post_reset_login = False
    post_reset_login_backend = None
    reset_url_token = "set-password"
    success_url = reverse_lazy("password_reset_complete")
    template_name = "blog/resetconfirm.html"
    title = _("Enter new password")
    token_generator = default_token_generator

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        if "uidb64" not in kwargs or "token" not in kwargs:
            raise ImproperlyConfigured(
                "The URL path must contain 'uidb64' and 'token' parameters."
            )

        self.validlink = False
        self.user = self.get_user(kwargs["uidb64"])

        if self.user is not None:
            token = kwargs["token"]
            if token == self.reset_url_token:
                session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(
                        token, self.reset_url_token
                    )
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            UserModel.DoesNotExist,
            ValidationError,
        ):
            user = None
        return user

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.user
        return kwargs

    def form_valid(self, form):
        user = form.save()
        del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        if self.post_reset_login:
            auth_login(self.request, user, self.post_reset_login_backend)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.validlink:
            context["validlink"] = True
        else:
            context.update(
                {
                    "form": None,
                    "title": _("Password reset unsuccessful"),
                    "validlink": False,
                }
            )
        return context


class PasswordResetCompleteView(PasswordContextMixin, TemplateView):
    template_name = "blog/resetcomplete.html"
    title = _("Password reset complete")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["login_url"] = resolve_url(settings.LOGIN_URL)
        return context


class PasswordChangeView(PasswordContextMixin, FormView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy("password_change_done")
    template_name = "registration/password_change_form.html"
    title = _("Password change")

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        # Updating the password logs out all other sessions for the user
        # except the current one.
        update_session_auth_hash(self.request, form.user)
        return super().form_valid(form)


class PasswordChangeDoneView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_change_done.html"
    title = _("Password change successful")

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
