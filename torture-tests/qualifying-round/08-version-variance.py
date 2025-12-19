# Mixed Python 2/3 features to force version-aware parsing and semantics
from __future__ import print_function

def divide(a, b):
    return a / b  # integer vs float division depends on interpreter

result = divide(3, 2)

print('py3-style print keeps working, but beware of version semantics')
if result == 1:
    print("Python 2 integer division branch (3/2 == 1)")
else:
    print("Python 3 true division branch (3/2 == 1.5)")

encoded = b'\xff'
if isinstance(encoded, str):
    print("Python 2: bytes are str")
else:
    print("Python 3: bytes are distinct from str")
