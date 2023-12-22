from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .models import Message, Mail
from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt

# FLAW 1: Insufficient Logging & Monitoring

# Here is an example of the Insufficient Logging & Monitoring flaw. 
# We added clear logging to all the user actions in the application.
# Now all the messages the users send and delete are logged to a file named app.log where I the admin can see if any suspicious activity is occuring. 
# With secure and clear logging we can provide visibility into what's happening within the application.
# Especially regarding sensitive operations like user actions and content. 

# Here is how we want to implement the logging into our application

# import logging

# logger = logging.getLogger(__name__)

# file_handler = logging.FileHandler('app.log')
# formatter = logging.Formatter('%(asctime)s - %(message)s')
# file_handler.setFormatter(formatter)

# logger.addHandler(file_handler)
# logger.setLevel(logging.CRITICAL)

# With this we create a file named app.log where we log the created and deleted messages.



@csrf_exempt
def mailView(request):
    Mail.objects.create(content=request.body.decode('utf-8'))
    return HttpResponse('')


@login_required
@csrf_exempt
def addView(request):
    target = User.objects.get(username=request.POST.get('to'))

	# Add this line to fix flaw 1
    # logger.critical('%s send a message to %s with content: %s', request.user.username, target, request.POST.get('content'))
    
    Message.objects.create(source=request.user, target=target, content=request.POST.get('content'))
    return redirect('/')


# FLAW 2: Insufficient access control in homePageView
@login_required
@csrf_exempt # To fix flaw 4 remove this
def homePageView(request):
    messages = Message.objects.all() 
    users = User.objects.exclude(pk=request.user.id)
    return render(request, 'pages/index.html', {'msgs': messages, 'users': users})


	# Here is an example of the Broken Access Control flaw. In the homePageView function we fetch all the messages without checking if the user has permission.
	# We can change this by implementing stricter access controls. We should fetch only messages where the user is the sender or the receiver.
	# We can do this by altering the 'messages' variable to filter and fetch only the messages where the message sender is the user or the message target is the user.
	# The 'messages' variable should look like this:

	# messages = Message.objects.filter(Q(source=request.user) | Q(target=request.user))

	# The rest of the code remains unchanged. The allowed messaged are displayed with this change. This was an example of the Broken Access Control flaw.
	# Here is how the code should look like to avoid this flaw:


# @login_required
# def homePageView(request):
#     messages = Message.objects.filter(Q(source=request.user) | Q(target=request.user))
#     users = User.objects.exclude(pk=request.user.id) 
#     return render(request, 'pages/index.html', {'msgs': messages, 'users': users})




# FLAW 3: Vulnerability to XSS attacks

# Now our application is safe from the Broken Access Control flaw, but it is still vulnerable to XSS attacks. 
# We can fix this flaw by using Django's utilities library to escape HTML content within the message before rendering it on the page.
# We can access the escape function by importing it like this:

# from django.utils.html import escape

# We also have to add a for loop into the function where the loop makes sure written messages HTML content is escaped before displaying and storing it. 
# We also added a sanitized_messages array where we store the messages after escaping them and return them to the application. 
# The messages and users variables stay untouched. 
# Now the all the messages are displayed as plain text even if they have code executable code in them. And like this we prevent XSS attacks.
# This was an example of the Cross-Site Scripting flaw. Here is how the code should look like after implementing protection for both flaws 2 and 3:

# from django.utils.html import escape

# @login_required
# def homePageView(request):
#     messages = Message.objects.filter(Q(source=request.user) | Q(target=request.user))
#     sanitized_messages = []

#     for msg in messages:
#         msg.content = escape(msg.content)
#         sanitized_messages.append(msg)

#     users = User.objects.exclude(pk=request.user.id) 
#     return render(request, 'pages/index.html', {'msgs': sanitized_messages, 'users': users})



from django.shortcuts import redirect, get_object_or_404

@login_required
@csrf_exempt # To fix flaw 4 remove this
def deleteMessageView(request, message_id):
    message = get_object_or_404(Message, pk=message_id)

    if request.user == message.source or request.user == message.target:

		# Add these lines to fix flaw 1
        # target_username = message.target.username
        # message_content = message.content
        # logger.critical('%s deleted a message to %s with content: %s', request.user.username, target_username, message_content)

        message.delete()

    return redirect('home')




# FLAW 4: CSRF-tokens

# CSRF tokens, although not explicitly listed in the OWASP Top 10, play a crucial role in web application security. 
# Frameworks like Django enforce CSRF protection by default for POST methods. 
# This mechanism helps prevent Cross-Site Request Forgery (CSRF) attacks, ensuring that requests originate from trusted sources.

# Using @csrf_exempt in Django views poses a security risk by bypassing this built-in CSRF protection.
# When a view is marked as exempt from CSRF checks, it allows requests to be processed without requiring the CSRF token, 
# opening the door to potential CSRF attacks.

# To fix this issue and ensure proper CSRF protection:

# Avoid Using @csrf_exempt and remove the @csrf_exempt decorator from views whenever possible. 
# Only exempt views from CSRF protection when absolutely necessary.

# So in our application, to fix the flaw we need to delete the @csrf_exempt tokens from the mailView, addView, homePageView and the deleteMessageView views.