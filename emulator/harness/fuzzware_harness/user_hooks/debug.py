import logging

def stop(uc):
    uc.specifics.context.print_context()
    input("...")

def breakpoint(uc):
    import ipdb
    ipdb.set_trace()
