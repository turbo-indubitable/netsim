import os
import ast

def get_imports_from_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
        tree = ast.parse(file.read(), filename=filepath)
        return {
            node.names[0].name.split('.')[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
        }.union({
            node.module.split('.')[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        })

all_imports = set()
for root, _, files in os.walk("netsim"):
    for f in files:
        if f.endswith(".py"):
            all_imports |= get_imports_from_file(os.path.join(root, f))

# filter stdlib (rough, not perfect)
stdlib = {"os", "sys", "typing", "math", "json", "re", "time", "datetime", "logging", "subprocess"}
third_party = sorted([imp for imp in all_imports if imp not in stdlib])
print("\n".join(third_party))
