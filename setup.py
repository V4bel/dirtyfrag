import os
import subprocess
import importlib.util
import shutil
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop

current_dir = os.path.dirname(os.path.abspath(__file__))
about_path = os.path.join(current_dir, "dirtyfrag", "__about__.py")

# Securely load the metadata file using importlib
spec = importlib.util.spec_from_file_location("dirtyfrag_about", about_path)
about = importlib.util.module_from_spec(spec)
spec.loader.exec_module(about)


def compile_and_prepare_exploits(cmd_instance):
    """Compiles the C exploit and copies external scripts into the active build directory."""
    # current_dir represents the static source root directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Get the dynamic target directory where setuptools is staging files for installation/wheel
    # If in editable/develop mode, fall back to the source directory root
    if hasattr(cmd_instance, 'build_lib') and cmd_instance.build_lib:
        target_package_root = os.path.join(cmd_instance.build_lib, "dirtyfrag")
    else:
        target_package_root = os.path.join(current_dir, "dirtyfrag")
        
    source_path = os.path.join(current_dir, "exp.c")
    bin_dir = os.path.join(target_package_root, "bin")
    output_path = os.path.join(bin_dir, "dirtyfrag")
    
    # Ensure the installation target subdirectory structure exists
    os.makedirs(bin_dir, exist_ok=True)
    
    print(f"[*] Compiling {source_path} to staging path: {output_path}...")
    compile_cmd = ["gcc", "-O2", source_path, "-o", output_path]
    
    try:
        subprocess.check_call(compile_cmd)
        print("[+] Native C binary compiled and staged successfully.")
    except Exception as e:
        print(f"[-] Compilation failed: {e}. Ensure 'gcc' is installed.")
        raise e

    # Stage copy_fail_exp.py into the dynamic active target directory
    copyfail_src = os.path.join(current_dir, "copy_fail_exp.py")
    copyfail_dst = os.path.join(target_package_root, "copy_fail_exp.py")
    
    if os.path.exists(copyfail_src):
        print(f"[*] Copying {copyfail_src} into dynamic package distribution path...")
        shutil.copyfile(copyfail_src, copyfail_dst)

class CustomInstallCommand(install):
    def run(self):
        compile_and_prepare_exploits(self)
        super().run()

class CustomDevelopCommand(develop):
    def run(self):
        compile_and_prepare_exploits(self)
        super().run()

setup(
    name="dirtyfrag",
    version=about.__version__,
    description="Multi-method Linux Kernel Exploit Framework Wrapper",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "dirtyfrag=dirtyfrag.__main__:main",
        ],
    },
    cmdclass={
        "install": CustomInstallCommand,
        "develop": CustomDevelopCommand,
    },
    package_data={
        "dirtyfrag": ["bin/dirtyfrag"],
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: C",
    ],
)