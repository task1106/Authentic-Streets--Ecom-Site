from django.urls import path
from .views import login_view
from . import views
from .views import register,user_logout
from .views import dashboard,change_password
from .views import forgot_password, verify_otp, reset_password

urlpatterns = [
	#Leave as empty string for base url
	path('', views.store, name="store"),
	path('cart/', views.cart, name="cart"),
	path('checkout/', views.checkout, name="checkout"),
	path('register/', register, name='register'),
	path('login/', login_view, name='login'),
	path('update_item/', views.updateItem, name="update_item"),
	path('process_order/', views.processOrder, name="process_order"),
	path('dashboard/', dashboard, name='dashboard'),
	path('change-password/', change_password, name='change_password'),
	path('logout/', user_logout, name='logout'),
	 path('forgot_password/', forgot_password, name='forgot_password'),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('reset_password/', reset_password, name='reset_password'),
]