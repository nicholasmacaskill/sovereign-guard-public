
import os
import hashlib
import platform
import json
from datetime import datetime

# Files that define the "Soul" of Sovereign Guard
PROTECTED_EXTENSIONS = ('.py', '.swift', '.sh', '.md')
EXCLUDE_DIRS = ('venv', '.git', '__pycache__', 'build', 'dist', 'sovereign_test_restore')

def generate_fingerprint(root_dir="."):
    """
    Generates a single SHA-256 fingerprint for the entire proprietary codebase.
    This hash can be published to a public ledger (Solana/Bitcoin) to prove
    date of creation and authorship.
    """
    file_hashes = {}
    
    for root, dirs, files in os.walk(root_dir):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        
        for file in files:
            if file.endswith(PROTECTED_EXTENSIONS):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, root_dir)
                
                try:
                    with open(file_path, 'rb') as f:
                        file_content = f.read()
                        file_hash = hashlib.sha256(file_content).hexdigest()
                        file_hashes[rel_path] = file_hash
                except Exception as e:
                    print(f"Skipping {rel_path}: {e}")

    # Deterministic sort for consistent master hashing
    sorted_paths = sorted(file_hashes.keys())
    master_vessel = ""
    for path in sorted_paths:
        master_vessel += f"{path}:{file_hashes[path]}|"
    
    master_fingerprint = hashlib.sha256(master_vessel.encode('utf-8')).hexdigest()
    return master_fingerprint, len(file_hashes)

def print_proof_instruction(fingerprint, file_count):
    """
    Provides the user with instructions on how to publish this fingerprint.
    """
    print("\n" + "="*60)
    print("💎 SOVEREIGN GUARD: PROJECT FINGERPRINT")
    print("="*60)
    print(f"Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Files:      {file_count} proprietary assets scanned")
    print(f"Fingerprint: {fingerprint}")
    print("="*60)
    
    print("\n🚀 THE ZERO-COST PROOF (SOLANA DEVNET) - RECOMMENDED")
    print("This anchors your code to a permanent ledger at ZERO cost.")
    print("-" * 60)
    print("1. Get free tokens:  solana airdrop 1 --url devnet")
    print(f"2. Anchor the hash: solana memo \"SG_V1:{fingerprint}\" --url devnet")
    
    print("\n🚀 THE SOCIAL PROOF (LINKEDIN / GIST / BLOG) - FASTEST")
    print("Post this string on any platform with a timestamp to create a public record.")
    print("-" * 60)
    print(f"I just anchored Sovereign Guard v1.0 Fingerprint: {fingerprint}")

    print("\n🚀 THE GITHUB PROOF (AUTOMATIC)")
    print("-" * 60)
    print("Your GPG-signed commits act as a legal record. GitHub's timestamped")
    print("logs verify you possessed this specific codebase at this exact time.")
    print("="*60 + "\n")

if __name__ == "__main__":
    fingerprint, count = generate_fingerprint()
    print_proof_instruction(fingerprint, count)
