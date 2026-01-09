import os
import shutil
import re
import sys

# Configuration: Lists of variables to empty out in specific files
REDACTIONS = {
    "src/sovereign_engine/patterns.py": [
        "DEFAULT_SAFE_LIST", "SAFE_BROWSER_PATHS", "TRUSTED_NETWORKS", "TRUSTED_DOMAINS",
        "REVERSE_SHELL_PORTS", "SHELL_PROCESSES", "TARGET_PROCESS_NAMES", "CRITICAL_FLAGS",
        "SUSPICIOUS_FLAGS", "PERSISTENCE_PATHS", "VAULT_PATHS", "TRUSTED_VAULT_ACCESSORS",
        "DEBUG_PORTS", "TRUSTED_BROWSER_PARENTS", "THREAT_PATTERNS", "STRICT_MODE_THREATS",
        "CLIPBOARD_WHITELIST"
    ],
    "src/sovereign_engine/scanners.py": [
        "TYPOSQUAT_DB", "EXTENSION_PATHS", "RISKY_PERMISSIONS", 
        "MULTIMEDIA_WHITELIST", "SCREEN_SHARING_AGENTS"
    ]
}

def redact_file(file_path, var_names):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    # Backup the original file safely
    backup_path = file_path + ".bak"
    if not os.path.exists(backup_path):
        shutil.copy(file_path, backup_path)
        print(f"Backed up {os.path.basename(file_path)} -> {os.path.basename(backup_path)}")

    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    new_lines = []
    i = 0
    vars_redacted = 0
    
    while i < len(lines):
        line = lines[i]
        replaced = False
        
        for var in var_names:
            # Look for: VAR_NAME = [ or VAR_NAME = {
            # We assume the assignment happens at the start of the line (allowing for indentation)
            escaped_var = re.escape(var)
            # Use concatenation to avoid f-string/regex brace conflicts
            pattern = r"^(\s*" + escaped_var + r"\s*=\s*)([\[\{])"
            match = re.search(pattern, line)
            
            if match:
                prefix = match.group(1)   # e.g. "    DEFAULT_SAFE_LIST = "
                open_char = match.group(2) # e.g. "["
                close_char = ']' if open_char == '[' else '}'
                
                # Start scanning for the matching closing bracket
                # We start from the character *after* the opening bracket
                start_col = match.end(2) 
                
                found_end = False
                end_line_idx = -1
                end_col_idx = -1
                
                count = 1 # We found one open bracket
                in_quote = False
                q_char = None
                
                current_line_idx = i
                col_ptr = start_col
                
                while current_line_idx < len(lines):
                    l_txt = lines[current_line_idx]
                    
                    while col_ptr < len(l_txt):
                        char = l_txt[col_ptr]
                        
                        # Handle quotes to ignore brackets inside strings
                        if char in ('"', "'"):
                            # Check for escape
                            is_escaped = False
                            bk_idx = col_ptr - 1
                            while bk_idx >= 0 and l_txt[bk_idx] == '\\':
                                is_escaped = not is_escaped
                                bk_idx -= 1
                            
                            if not is_escaped:
                                if not in_quote:
                                    in_quote = True
                                    q_char = char
                                elif char == q_char:
                                    in_quote = False
                        
                        if not in_quote:
                            if char == '#':
                                # Comment, stop processing this line
                                break
                            
                            if char == open_char:
                                count += 1
                            elif char == close_char:
                                count -= 1
                                if count == 0:
                                    found_end = True
                                    end_line_idx = current_line_idx
                                    end_col_idx = col_ptr
                                    break
                                    
                        col_ptr += 1
                    
                    if found_end:
                        break
                    
                    current_line_idx += 1
                    col_ptr = 0 # Reset col pointer for next line
                
                if found_end:
                    # Found the end of the block. Replace it.
                    # Preserve anything after the closing bracket on the same line (e.g. comments)
                    remainder = lines[end_line_idx][end_col_idx+1:]
                    
                    # Construct the new line
                    replacement_line = f"{prefix}{open_char}{close_char}{remainder}"
                    new_lines.append(replacement_line)
                    
                    print(f"  [REDACTED] {var}")
                    
                    # Advance the main loop past the consumed lines
                    i = end_line_idx + 1
                    replaced = True
                    vars_redacted += 1
                    break
                else:
                    print(f"  [WARNING] Could not find end of block for {var} (started line {i+1})")
        
        if not replaced:
            new_lines.append(line)
            i += 1
            
    if vars_redacted > 0:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        print(f"Finished {os.path.basename(file_path)}: {vars_redacted} variables redacted.")
    else:
        print(f"Finished {os.path.basename(file_path)}: No targets found locally.")

def main():
    # Base dir is the project root (assuming this script is in /tools)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    
    print("Starting Privacy Redaction...")
    print(f"Project Root: {project_root}")
    
    for relative_path, targets in REDACTIONS.items():
        full_path = os.path.join(project_root, relative_path)
        redact_file(full_path, targets)
        
    print("Redaction complete.")

if __name__ == '__main__':
    main()
