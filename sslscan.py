import subprocess
import sys

def run_sslscan(target_host):
    try:
        # Run the sslscan command and capture the output
        command = f"sslscan {target_host}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

        # Check if the command was successful
        if result.returncode == 0:
            # Print the output
            print("SSL/TLS scan results for", target_host)
            print(result.stdout)
        else:
            print("Error running sslscan. Exit code:", result.returncode)
            print("Error message:", result.stderr)
    except FileNotFoundError:
        print("sslscan command not found. Make sure sslscan is installed and in your system's PATH.")

if __name__ == "__main__":
    target_host = sys.argv[1]
    run_sslscan(target_host)
