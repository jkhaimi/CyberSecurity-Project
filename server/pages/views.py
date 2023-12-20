from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .models import Message, Mail
from django.db.models import Q
import json

def mailView(request):
    Mail.objects.create(content=request.body.decode('utf-8'))
    print(request.body.decode('utf-8'))
    return HttpResponse('')


# Flaw 1: Injection
@login_required
def addView(request):
    target = User.objects.get(username=request.POST.get('to'))
    Message.objects.create(source=request.user, target=target, content=request.POST.get('content'))
    return redirect('/')

	# Here is an example of the Injection flaw. In the addView function is vulnerable to injection attacks. 
	# The attacker would attempt to inject malicious SQL code through the request.POST.get('to') parameter. 
	# In the case of SQL injection, the attacker might use a payload that alters the intended SQL query's behavior.
	# The attacker can use an attack payload like this:

	# curl -X POST locahost:8000/addView -d "to=' OR 1=1 -- " -d "content=I`Content to be injected"

	# The payload tricks the query to always evaluate to true with the '1=1' snippet.
	# The payload injected into the to parameter could result in a query that retrieves unintended data or performs unintended operations,
	# because it tricks the SQL query to behave unexpectedly due to the injected SQL code.

	# To fix this security flaw the code should look like this:

# @login_required
# def addView(request):
#     username = request.POST.get('to')
#     if username is not None:
#         try:
#             target = User.objects.get(username=username)
#             Message.objects.create(source=request.user, target=target, content=request.POST.get('content'))
#         except User.DoesNotExist:
#             pass
#     return redirect('/')

# Here we use parameterized queries through Django's ORM (object-relational mapping layer). 
# The key difference lies in how the user input is handled and processed. 
# The secure code validates and handles the input before using it in the query, 
# while the original code directly uses the input without explicit validation, 
# It doesn't directly inject the raw username into the query. Instead, it validates the input and then utilizes it in a safe manner, 
# reducing the risk of a SQL injection.




# FLAW 2: Insufficient access control in homePageView
@login_required
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
def deleteMessageView(request, message_id):
    message = get_object_or_404(Message, pk=message_id)

    if request.user == message.source or request.user == message.target:
        message.delete()

    return redirect('home')

# FLAW 4: Insufficient Logging and Monitoring

# Currently, our application lacks logging and monitoring for security events.
# Weak monitoring makes it harder to detect and respond to security incidents or unauthorized access attempts.
# To improve, we will implement comprehensive logging mechanisms:

# 1. Log important security-related events, like authentication failures, access control violations, or critical operations.
# 2. Implement logging libraries or Django's built-in logging mechanisms to record these events.
# 3. Regularly review logs, set up alerts for suspicious activities, and establish incident response procedures.

import logging

logger = logging.getLogger('security_logger')
logger.info('Authentication success/failure')
logger.warning('Access control violation detected')

# Note: The example above represents basic logging; adjust and extend it based on your application's needs and security requirements.

# ... (existing code)