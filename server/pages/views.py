from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .models import Message, Mail
from django.db.models import Q
import json

# FLAW 1-1: No input validation in mailView, leading to potential injection
def mailView(request):
    Mail.objects.create(content=request.body.decode('utf-8'))  # Vulnerable to injection attacks
    print(request.body.decode('utf-8'))
    return HttpResponse('')

	# The solution to this flaw is to sanitize and validate the received content before storing it. 
	# We can do this by adding a length limit to the content. 
	# We can do this for example adding a new variable named sanitized_content before we create the Mail objects.
	# Which would look like this: 

	# sanitized_content = request.body.decode('utf-8')[:255]

	# In the line we add a length limit to the content with the [:255] part, which limits the length to 255 charecters.
	# After that we create the message or the Mail.Object normally with this line:

	# Mail.objects.create(content=sanitized_content)

	# And then we can print it and return it. This was an example of the injection flaw.
	# Here is what the code should look like to avoid possible injections:

# def mailView(request):
#     sanitized_content = request.body.decode('utf-8')[:255]
#     Mail.objects.create(content=sanitized_content)
#     print(sanitized_content)
#     return HttpResponse('')




# FLAW 1-2: Lack of input validation and sanitation in addView
@login_required
def addView(request):
    target = User.objects.get(username=request.POST.get('to'))
    Message.objects.create(source=request.user, target=target, content=request.POST.get('content'))
    return redirect('/')

		# Here is another example of the injection flaw. In the addView function there is no validation for the 'to' and 'content' parameters. 
		# The solution to this flaw is to validate and sanitize the parameters in question before processing.
		# This can be done for example with variables that look like this:

		# target_username = request.POST.get('to')
		# content = request.POST.get('content')

		# After this we add a if sentence to check if the 'to' user exists and we validate the content length like in the example before.
		# If the 'to' user exists and the content length is acceptable, then we create the message and return it.
		# This was the second part of the example of the injection flaw. Here is what the code should look like to avoid the possible injenctions:


# @login_required
# def addView(request):
#     target_username = request.POST.get('to')
#     content = request.POST.get('content')
    
#     if target_username and len(content) <= 255:
#         try:
#             target = User.objects.get(username=target_username)
#             Message.objects.create(source=request.user, target=target, content=content)
#         except User.DoesNotExist:
#             pass 
#     return redirect('/')




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
