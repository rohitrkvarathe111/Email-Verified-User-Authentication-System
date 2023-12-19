from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from InternPortal import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import authenticate, login, logout
from . tokens import generate_token
# Create your views here.



def home(request):
    user = request.user
    username = user.username if user.username else None
    company_name = user.company_name if hasattr(user, 'company_name') else None
    
    return render(request, "home.html", {'username': username, 'company_name': company_name})

def signup(request):
    if request.method == "POST":
        username = request.POST["username"]
        fname = request.POST["fname"]
        lname = request.POST["lname"]
        email = request.POST["email"]
        pass1 = request.POST["pass1"]
        pass2 = request.POST["pass2"]

        if User.objects.filter(username=username):
            messages.error(request, "Username already exist! Please try some other username.")
            return redirect('home')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email Already Registered!!")
            return redirect('home')
        
        if len(username)>20:
            messages.error(request, "Username must be under 20 charcters!!")
            return redirect('home')
        
        if pass1 != pass2:
            messages.error(request, "Passwords didn't matched!!")
            return redirect('home')
        
        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect('home')
        
        myuser = User.objects.create_user(username, email, pass1)
        myuser.fname = fname
        myuser.lname = lname
        # myuser.is_active = False
        myuser.is_active = False
        myuser.save()
        messages.success(request, "Your Account has been created succesfully!! Please check your email to confirm your email address in order to activate your account.")
        
# Welcome Email setup
        subject = "Welcome to Internship Portal Login!!"
        message = "Hello " + myuser.fname + "!! \n" + "Welcome to Intern Portal!! \nThank you for visiting our website\n. We have also sent you a confirmation email, please confirm your email address. \n\nThanking You\nRohit Varathe"        
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)
        
        # Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email @ Intern Portal Login!!"
        message2 = render_to_string('users/email_confirmation.html',{
            
            'name': myuser.fname,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
        email_subject,
        message2,
        settings.EMAIL_HOST_USER,
        [myuser.email],
        )
        send_mail(email_subject, message2, from_email, to_list, fail_silently=True)
        
        return redirect('signin')
        
        
    return render(request, "usersignup.html")


def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')
    
def signin(request):
    if request.method == "POST":
        username = request.POST["username"]
        pass1 = request.POST["pass1"]
        user = authenticate(username=username, password=pass1)
        if user is not None:
            login(request, user)
            username = user.username
            return render(request,"home.html", {'username' : username})

        else:
            messages.error(request, "Bad Credentials!")
            return redirect("signin")
    return render(request, "userlogin.html")

def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect("home")






#====================================================================================================
# Assuming you have already imported the necessary modules and classes

def company_signup(request):
    if request.method == "POST":
        company_name = request.POST["company_name"]
        company_id = request.POST["company_id"]
        company_email = request.POST["company_email"]
        pass1 = request.POST["pass1"]
        pass2 = request.POST["pass2"]

        if User.objects.filter(username=company_id):
            messages.error(request, "Company ID already exists! Please choose a different one.")
            return redirect('home')

        if User.objects.filter(email=company_email).exists():
            messages.error(request, "Company Email Already Registered!!")
            return redirect('home')

        if len(company_id) > 20:
            messages.error(request, "Company ID must be under 20 characters!!")
            return redirect('home')

        if pass1 != pass2:
            messages.error(request, "Passwords didn't match!!")
            return redirect('home')

        if not company_id.isalnum():
            messages.error(request, "Company ID must be Alpha-Numeric!!")
            return redirect('home')

        # Additional validations can be added here...

        # Create a new company user
        user = User.objects.create_user(company_id, company_email, pass1)
        user.company_name = company_name
        user.save()

        # Send verification email
        subject = "Welcome to InternShip Portal Login!!"
        message = f"Hello {user.company_name}!!\nWelcome to our InternShip Portal!\nThank you for registering on our website. " \
                f"We have also sent you a confirmation email, please confirm your email address.\n\nThanking You\nYour Company Name"
        from_email = settings.EMAIL_HOST_USER
        to_list = [user.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email @ Company Portal Login!!"
        message2 = render_to_string('users/email_confirmation.html', {
            'name': user.company_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [user.email],
        )
        email.send(fail_silently=True)
        
        # ...

        messages.success(request, "Company Account created successfully! Please check your email to confirm your email address.")

        return redirect('company-signin')

    return render(request, "company_signup.html")




def company_activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        company_user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        company_user = None

    if company_user is not None and generate_token.check_token(company_user, token):
        company_user.is_active = True
        company_user.save()
        login(request, company_user)
        messages.success(request, "Company Account has been activated!!")
        return redirect('company_signin')
    else:
        return render(request, 'activation_failed.html')

def company_signin(request):
    if request.method == "POST":
        company_email = request.POST["company_email"]
        pass1 = request.POST["pass1"]
        user = authenticate(username=company_email, password=pass1)

        if user is not None:
            login(request, user)
            return render(request, "home.html", {'company_email': company_email})

        else:
            messages.error(request, "Bad Credentials!")
            return redirect("company-signin")

    return render(request, "company_signin.html")

# Other views...
















