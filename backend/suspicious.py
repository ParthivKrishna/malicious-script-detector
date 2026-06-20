import os
import base64

payload = base64.b64decode("SGVsbG8=")

eval("print('test')")

os.system("whoami")