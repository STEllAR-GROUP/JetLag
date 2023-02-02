from typing import Callable

import sys

def not_colored(a : str,_ : str)->str:
    return a

installed = None

colored : Callable[[str,str],str]
try:
    from termcolor import colored as colored_
    colored = colored_
    installed = True
except:
    colored = not_colored
    installed = False

if hasattr(sys.stdout,"isatty"):
    is_tty = sys.stdout.isatty()
else:
    is_tty = False

is_jupyter = type(sys.stdout).__name__ == 'OutStream' and  type(sys.stdout).__module__ == 'ipykernel.iostream'
if (not is_tty) and (not is_jupyter):
    colored = not_colored

if __name__ == "__main__":
    if installed:
        print(colored("Colored was installed","green"))
    else:
        print("Colored was NOT installed")
