import importlib

class BasePlugin:
    def __init__(self, args):
        self.validate_args(args)

    def validate_args(self, args):
        pass


class Plugins:
    def __init__(self, plugin_dict, plugin_dir="pidtree_bcc.plugins"):
        """ `plugin_dict` is a dict where the keys are plugin names and
        the value for each key is a nother dict of kwargs. Each key must
        match a `.py` file in the plugin directory and the kwargs will
        be validated on initialization of the plugin """
        self._plugins = []
        for plugin_name, plugin_args in plugin_dict.items():
            if not plugin_args.get("enabled", False):
                next
            plugin_classname = plugin_name.capitalize()
            import_line = ".".join([plugin_dir, plugin_name])
            try:
                module = importlib.import_module(import_line)
                plugin = getattr(module, plugin_classname)(plugin_args)
                self._plugins.append(plugin)
            except ImportError as e:
                raise RuntimeError("Could not import {import_line}: {e}".format(
                    import_line=import_line,
                    e=e,
                ))
            except AttributeError as e:
                raise RuntimeError("Could not find class {plugin_classname} in module {import_line}: {e}".format(
                    plugin_classname=plugin_classname,
                    import_line=import_line,
                    e=e,
                ))

    def plugins(self):
        return self._plugins
