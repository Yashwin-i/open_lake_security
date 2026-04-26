"""
Utility module for cloning git repositories.

This module provides functionality to clone remote repositories to a local directory,
ensuring clean temporary spaces for security scanning.
"""
import os
import shutil
from git import Repo

def clone_repo(repo_url, target_dir="temp_repo"):
    """
    Clones a GitHub repository to a temporary directory.
    If the target directory exists, it is cleaned prior to cloning.

    Args:
        repo_url (str): The URL of the repository to clone.
        target_dir (str, optional): The directory where the repository will be cloned. Defaults to "temp_repo".

    Returns:
        str: The path to the cloned repository directory.
    """
    if os.path.exists(target_dir):
        # We need to handle permissions on Windows sometimes when deleting read-only git files
        def handle_remove_readonly(func, path, exc):
            """Helper function to remove read-only files during cleanup."""
            os.chmod(path, 0o777)
            func(path)
        shutil.rmtree(target_dir, onerror=handle_remove_readonly)
    
    print(f"[*] Cloning {repo_url}...")
    Repo.clone_from(repo_url, target_dir)
    print(f"[+] Successfully cloned to {target_dir}")
    return target_dir
