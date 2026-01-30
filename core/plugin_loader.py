import importlib
import pkgutil
import logging
from plugins.base import Plugin

logger = logging.getLogger(__name__)

def load_plugins():
    """
    Auto-discovers and loads all plugins in the plugins/ folder that inherit from Plugin.
    Returns a list of plugin instances.
    """
    loaded_plugins = []
    package = "plugins"

    try:
        import plugins  # Ensure package exists
    except ImportError:
        logger.warning("No plugins package found.")
        return loaded_plugins

    # Iterate over all modules in the plugins folder
    for loader, module_name, is_pkg in pkgutil.iter_modules(plugins.__path__):
        try:
            module = importlib.import_module(f"{package}.{module_name}")
        except Exception as e:
            logger.error(f"Failed to import plugin module {module_name}: {e}")
            continue

        # Search for classes that inherit from Plugin
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, Plugin) and attr is not Plugin:
                try:
                    loaded_plugins.append(attr())
                    logger.debug(f"Loaded plugin: {attr.__name__}")
                except Exception as e:
                    logger.error(f"Failed to initialize plugin {attr.__name__}: {e}")

    logger.info(f"Total plugins loaded: {len(loaded_plugins)}")
    return loaded_plugins
