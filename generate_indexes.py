import os
import json

def generate_index(folder, output_file):
    # Get list of subdirectories (countries or categories)
    subdirs = [d for d in os.listdir(folder) if os.path.isdir(os.path.join(folder, d))]
    subdirs.sort()  # Sort alphabetically
    with open(output_file, 'w') as f:
        json.dump(subdirs, f, indent=2)

# Generate indexes
generate_index('LiveTV', 'LiveTV/index.json')
