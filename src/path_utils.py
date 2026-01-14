import sys
import os
import platform

def get_app_name():
    return "SovereignGuard"

def get_project_root():
    """Returns the absolute path to the project root directory."""
    # Since this file is in src/, the root is one level up
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_data_dir():
    """
    Returns the persistent data directory for the application.
    Prioritizes the local 'data/' directory if it exists, otherwise use OS standard.
    """
    local_data = os.path.join(get_project_root(), "data")
    if os.path.exists(local_data):
        return local_data
        
    if platform.system() == "Darwin":
        home = os.path.expanduser("~")
        base_dir = os.path.join(home, "Library", "Application Support", get_app_name())
    else:
        base_dir = os.path.join(os.path.expanduser("~"), ".sovereign_guard")
        
    if not os.path.exists(base_dir):
        os.makedirs(base_dir, exist_ok=True)
    return base_dir

def get_log_dir():
    """
    Returns the log directory.
    Prioritizes the local 'logs/' directory if it exists.
    """
    local_logs = os.path.join(get_project_root(), "logs")
    if os.path.exists(local_logs):
        return local_logs

    if platform.system() == "Darwin":
        home = os.path.expanduser("~")
        base_dir = os.path.join(home, "Library", "Logs", get_app_name())
    else:
        base_dir = os.path.join(get_data_dir(), "logs")

    if not os.path.exists(base_dir):
        os.makedirs(base_dir, exist_ok=True)
    return base_dir

def get_run_dir():
    """Returns the runtime directory for PIDs and locks."""
    run_dir = os.path.join(get_project_root(), "run")
    if not os.path.exists(run_dir):
        os.makedirs(run_dir, exist_ok=True)
    return run_dir

def get_config_file(filename):
    """Returns path to a config file. Looks in root for .env, otherwise in data dir."""
    if filename == ".env.sovereign":
        root_env = os.path.join(get_project_root(), filename)
        if os.path.exists(root_env):
            return root_env
            
    return os.path.join(get_data_dir(), filename)

def get_secret():
    """Reads the sovereign secret from the env file."""
    env_file = get_config_file(".env.sovereign")
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                if line.startswith('SOVEREIGN_SECRET='):
                    return line.split('=', 1)[1].strip()
    return None

def get_log_file(filename):
    """Returns path to a log file in the log dir"""
    return os.path.join(get_log_dir(), filename)

def get_run_file(filename):
    """Returns path to a file in the run dir (PIDs, etc)"""
    return os.path.join(get_run_dir(), filename)

