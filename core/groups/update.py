import asyncio
import sys
from core.features.update import update_script

def run(args):
    # In your argument handler:
    if args.update:
        if asyncio.run(update_script()):
            sys.exit(0)
        else:
            sys.exit(1)
