import json
from .models import State
import datetime
from .models import * 
from .utils import cookieCart, cartData, guestOrder
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth.models import User
from .models import Customer
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from .models import Customer, Order
from .models import State
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import authenticate
from django.shortcuts import render, redirect
import random
from django.core.mail import send_mail
from django.conf import settings
from .models import Customer
from .forms import ForgotPasswordForm



states_of_india = [
	'Andhra Pradesh', 'Arunachal Pradesh', 'Assam', 'Bihar', 'Chhattisgarh',
	'Goa', 'Gujarat', 'Haryana', 'Himachal Pradesh', 'Jammu and Kashmir',
	'Jharkhand', 'Karnataka', 'Kerala', 'Madhya Pradesh', 'Maharashtra',
	'Manipur', 'Meghalaya', 'Mizoram', 'Nagaland', 'Odisha', 'Punjab',
	'Rajasthan', 'Sikkim', 'Tamil Nadu', 'Telangana', 'Tripura', 'Uttarakhand',
	'Uttar Pradesh', 'West Bengal', 'Andaman and Nicobar Islands', 'Chandigarh',
	'Dadra and Nagar Haveli', 'Daman and Diu', 'Delhi', 'Lakshadweep', 'Puducherry'
]

def populate_states():
	for state in states_of_india:
		State.objects.get_or_create(name=state)

def register(request):
	populate_states()
	states = State.objects.all()
	if request.method == 'POST':
		username = request.POST['username']
		email = request.POST['email']
		password = request.POST['password']
		name = request.POST['name']
		mobile = request.POST['mobile']
		address = request.POST['address']
		city = request.POST['city']
		zipcode = request.POST['zipcode']
		state = request.POST['state']

		# Check if the username is already taken
		if User.objects.filter(username=username).exists():
			messages.error(request, 'Username is already taken. Please choose a different one.')
			return render(request, 'store/register.html')  # Return here if username exists
		
		if User.objects.filter(email=email).exists():
			messages.error(request, 'Email already Exists..')
			return render(request, 'store/register.html')  # Return here if email exists

		if Customer.objects.filter(mobile=mobile).exists():
			messages.error(request, 'Mobile number already exists. Please use a different one.')
			return render(request, 'store/register.html')
		# Create user
		user = User.objects.create_user(username=username, email=email, password=password)
		user.save()

		# Create customer profile
		customer = Customer(user=user, name=name, email=email, mobile=mobile, address=address, city=city, zipcode=zipcode, state=state)
		customer.save()

		messages.success(request, 'Registration successful! You can now log in.')
		return redirect('login')  # Redirect to login page after successful registration

	return render(request, 'store/register.html', {'states': states})

def login_view(request):
	if request.method == 'POST':
		username_or_email = request.POST.get('username')
		password = request.POST.get('password')
		
		# Check if the username_or_email is an email
		if '@' in username_or_email:
			try:
				user = User.objects.get(email=username_or_email)
				username = user.username
			except User.DoesNotExist:
				error_message = "Invalid email or password. Try again."
				return render(request, 'store/login.html', {'error_message': error_message})
		else:
			username = username_or_email
		
		user = authenticate(request, username=username, password=password)
		
		if user is not None:
			login(request, user)
			return redirect('dashboard')  # Change 'home' to your desired URL name
		else:
			error_message = "Invalid username or password. Try again."
			return render(request, 'store/login.html', {'error_message': error_message})
	
	return render(request, 'store/login.html')

@login_required
def dashboard(request):
	context = {
		'user': request.user,
		'orders': None,
		'customer': None,
	}

	if request.user.is_authenticated:
		try:
			# Retrieve the customer profile
			customer = request.user.customer  # Assuming you have a OneToOne relationship with User
			context['customer'] = customer
			
			# Retrieve orders for the customer
			orders = Order.objects.filter(customer=customer)
			order_details = []

			for order in orders:
				order_items = OrderItem.objects.filter(order=order)
				order_info = {
					'order': order,
					'items': order_items,
				}
				order_details.append(order_info)

			context['orders'] = order_details
		except Customer.DoesNotExist:
			# Handle the case where the customer profile does not exist
			context['customer'] = None

	return render(request, 'store/dashboard.html', context)

@login_required
def change_password(request):
	if request.method == 'POST':
		old_password = request.POST.get('old_password')
		new_password = request.POST.get('new_password')
		confirm_password = request.POST.get('confirm_password')

		user = authenticate(username=request.user.username, password=old_password)

		if user is not None:
			if new_password == confirm_password:
				user.set_password(new_password)
				user.save()
				update_session_auth_hash(request, user)  # Important!
				messages.success(request, 'Your password has been changed successfully.')
				logout(request) 
				return redirect('login')  # Redirect to a success page
			else:
				pass
		else:
			pass

	return render(request, 'dashboard')

def user_logout(request):
	logout(request)  # Log out the user
	messages.success(request, 'You have been logged out successfully.')
	return redirect('login') 

def store(request):
	data = cartData(request)

	cartItems = data['cartItems']
	order = data['order']
	items = data['items']

	products = Product.objects.all()
	context = {'products':products, 'cartItems':cartItems}
	return render(request, 'store/store.html', context)


def cart(request):
	data = cartData(request)

	cartItems = data['cartItems']
	order = data['order']
	items = data['items']

	context = {'items':items, 'order':order, 'cartItems':cartItems}
	return render(request, 'store/cart.html', context)

def checkout(request):
	data = cartData(request)
	
	cartItems = data['cartItems']
	order = data['order']
	items = data['items']

	context = {'items':items, 'order':order, 'cartItems':cartItems}
	return render(request, 'store/checkout.html', context)

def updateItem(request):
	data = json.loads(request.body)
	productId = data['productId']
	action = data['action']
	print('Action:', action)
	print('Product:', productId)

	customer = request.user.customer
	product = Product.objects.get(id=productId)
	order, created = Order.objects.get_or_create(customer=customer, complete=False)

	orderItem, created = OrderItem.objects.get_or_create(order=order, product=product)

	if action == 'add':
		orderItem.quantity = (orderItem.quantity + 1)
	elif action == 'remove':
		orderItem.quantity = (orderItem.quantity - 1)

	orderItem.save()

	if orderItem.quantity <= 0:
		orderItem.delete()

	return JsonResponse('Item was added', safe=False)

def processOrder(request):
	transaction_id = datetime.datetime.now().timestamp()
	data = json.loads(request.body)

	if request.user.is_authenticated:
		customer = request.user.customer
		order, created = Order.objects.get_or_create(customer=customer, complete=False)
	else:
		customer, order = guestOrder(request, data)

	total = float(data['form']['total'])
	order.transaction_id = transaction_id

	if total == order.get_cart_total:
		order.complete = True
	order.save()

	if order.shipping == True:
		ShippingAddress.objects.create(
		customer=customer,
		order=order,
		address=data['shipping']['address'],
		city=data['shipping']['city'],
		state=data['shipping']['state'],
		zipcode=data['shipping']['zipcode'],
		)

	return JsonResponse('Payment submitted..', safe=False)

def send_otp(email_or_mobile):
    otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
    # Here you can implement the logic to send the OTP via email or SMS
    # For email
    try:
        customer = Customer.objects.get(email=email_or_mobile)
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp}',
            settings.DEFAULT_FROM_EMAIL,
            [customer.email],
            fail_silently=False,
        )
        return otp
    except Customer.DoesNotExist:
        return None

def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email_or_mobile = form.cleaned_data['email_or_mobile']
            otp = send_otp(email_or_mobile)
            if otp:
                request.session['otp'] = otp  # Store OTP in session for verification
                request.session['email_or_mobile'] = email_or_mobile  # Store email/mobile for later use
                messages.success(request, 'OTP has been sent to your email/mobile.')
                return redirect('verify_otp')  # Redirect to OTP verification page
            else:
                messages.error(request, 'No account found with this email/mobile.')
    else:
        form = ForgotPasswordForm()
    return render(request, 'store/forgot_password.html', {'form': form})

def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        if entered_otp == str(request.session.get('otp')):
            # OTP is correct, proceed to reset password
            return redirect('reset_password')  # Redirect to reset password page
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
    return render(request, 'store/verify_otp.html')

def reset_password(request):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        email_or_mobile = request.session.get('email_or_mobile')
        try:
            customer = Customer.objects.get(email=email_or_mobile)
            user = customer.user
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Your password has been reset successfully.')
            return redirect('login')  # Redirect to login page
        except Customer.DoesNotExist:
            messages.error(request, 'User  not found.')
    return render(request, 'store/reset_password.html')