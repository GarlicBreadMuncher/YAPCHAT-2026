Finalised project files are located in the 'home' folder. Ignore other files.




____________________READ_ME.txt CONTENTS:____________________


INSTALL FLASK: type "pip install flask" into the Pycharm (or other IDE terminal)

INSTALL CRYPTOGRAPHY: type "pip install cryptography" into terminal

in ENCRYPTION_KEY = (generated encryption key)



____________________INSTRUCTIONS____________________

IN terminal run:

from cryptography.fernet import Fernet
print(Fernet.generate_key())

Then copy and paste the outputted key into (generated encryption key)

____________________Hosting via local wifi network____________________
IN MAIN.PY host= YOUR IPV4 ADDRESS.
(IN CMD PROMT TYPE "ipconfig" replace, COPY AND PASTE YOUR IPV4 INTO THE host (socketio.run(app, host='IPV4 ADDRESS HERE', port=5000, debug=True) *OR* check under your wifi router or adapter)

you may also potentially need to edit your windows (or other) firewall on ur pc to allow port 5000 through it.
If this is the case:

Step 1. Open the Start menu and search for:
'Windows Defender Firewall with Advanced Security'
Step 2. Click Inbound Rules on the left side
Step 3. Click New Rule on the right side
Step 4. Select Port → click Next
Step 5. Select TCP, then type 5000 in the specific port box → click Next
Step 6. Select Allow the connection → click Next
Step 7. Make sure Private and Public are both ticked → click Next
Step 8. Give it a name like YapChat → click Finish



___________small info_____________

- if users wish to make it so the users sessions arent invalidated every time the server restarts, simply change "secrets.token_hex(16)" to a random string (e.g. "ASNJKDn7897823nsi@!@!#38i901890")
