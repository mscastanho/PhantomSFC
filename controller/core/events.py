# Based on code from BPFabric project - https://github.com/UofG-netlab/BPFabric.git
_handlers = {}

def set_event_handler(opcode):
    def set_event_handler_decorator(func):
        _handlers.setdefault(opcode, []).append(func)
        return func
    return set_event_handler_decorator
