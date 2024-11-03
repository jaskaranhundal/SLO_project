import os
import re
import subprocess

def find_imports(directory="."):
    """Scan Python files to find imported modules."""
    imports = set()
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                with open(os.path.join(root, file), "r") as f:
                    for line in f:
                        # Use regex to find imports
                        match = re.match(r'^\s*(import|from) ([\w\.]+)', line)
                        if match:
                            imports.add(match.group(2).split(".")[0])
    return imports

def get_version(package_name):
    """Get the version of a package using pip show."""
    try:
        result = subprocess.run(
            ["pip", "show", package_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.stdout:
            for line in result.stdout.splitlines():
                if line.startswith("Version:"):
                    return line.split(": ")[1]
    except Exception as e:
        print(f"Could not determine version for {package_name}: {e}")
    return None

def write_requirements(imports):
    """Write detected imports to requirements.txt with versions."""
    with open("requirements.txt", "w") as req_file:
        for package in imports:
            version = get_version(package)
            if version:
                req_file.write(f"{package}=={version}\n")
            else:
                print(f"Warning: {package} not found or has no version information.")

# Run the script
detected_imports = find_imports()
write_requirements(detected_imports)
print("requirements.txt created with detected packages.")
