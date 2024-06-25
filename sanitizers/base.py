class Sanitizer:
    def __init__(self, project):
        self.project = project

    def install_hooks(self):
        raise NotImplementedError("Subclasses should implement this!")

    def mem_read_hook(self, state):
        pass

    def mem_write_hook(self, state):
        pass

class HookDispatcher:
    def __init__(self):
        self.mem_read_hooks = []
        self.mem_write_hooks = []

    def register_mem_read_hook(self, hook):
        self.mem_read_hooks.append(hook)

    def register_mem_write_hook(self, hook):
        self.mem_write_hooks.append(hook)

    def mem_read_dispatcher(self, state):
        for hook in self.mem_read_hooks:
            hook(state)

    def mem_write_dispatcher(self, state):
        for hook in self.mem_write_hooks:
            hook(state)

