from django.urls import path
from .views import homePageView, addView, mailView, deleteMessageView

urlpatterns = [
    path('', homePageView, name='home'),
    path('add/', addView, name='add'),
    path('mail/', mailView, name='mail'),
    path('delete/<int:message_id>/', deleteMessageView, name='delete_message'),
]
