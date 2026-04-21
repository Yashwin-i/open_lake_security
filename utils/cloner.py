import os
import shutil
from git import Repo

def clone_repo(repo_url, target_dir="temp_repo"):
    """
    Clones a GitHub repository to a temporary directory.
    If the directory exists, it cleans it first.
    """
    if os.path.exists(target_dir):
        # We need to handle permissions on Windows sometimes when deleting read-only git files
        def handle_remove_readonly(func, path, exc):
            os.chmod(path, 0o777)
            func(path)
        shutil.rmtree(target_dir, onerror=handle_remove_readonly)
    
    print(f"[*] Cloning {repo_url}...")
    Repo.clone_from(repo_url, target_dir)
    print(f"[+] Successfully cloned to {target_dir}")
    return target_dir