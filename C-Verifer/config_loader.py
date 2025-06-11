# cverifier/config_loader.py
import json
import sys
import traceback

def load_json_file(file_path, error_context="file"):
    # print(f"Attempting to load JSON from: {file_path}")
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        # print(f"Successfully loaded JSON from: {file_path}")
        return data
    except FileNotFoundError:
        print(f"Error: {error_context.capitalize()} '{file_path}' not found.", file=sys.stderr)
        raise
    except json.JSONDecodeError as e:
        print(f"Error: Could not decode JSON from {error_context} '{file_path}'. Error: {e}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"An unexpected error occurred loading {error_context} '{file_path}': {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        raise

def load_aws_config_data(file_path):
    """Loads the main AWS configuration data (roles, identity pools)."""
    return load_json_file(file_path, error_context="AWS config data")

def load_policy_document_from_file(file_path, policy_name="policy"):
    """
    Loads a policy document file.
    A policy document can be a single JSON object with "Statement"
    or a list of such statements (which we'll wrap in a standard document structure).
    It can also be a list of policy objects, each with PolicyDocument.
    """
    # print(f"Loading policy '{policy_name}' from: {file_path}")
    try:
        data = load_json_file(file_path, error_context=f"{policy_name} policy document")
        
        # The policy evaluators expect a list of policy documents like
        # [{'Version': '...', 'Statement': [...]}]
        # or [{'PolicyName': 'x', 'PolicyDocument': {'Version': ..., 'Statement': [...]}}]

        if isinstance(data, dict) and 'Statement' in data : # Single policy document
            return [data]
        elif isinstance(data, list):
            # Could be a list of statements, or list of policy objects
            is_list_of_statements = all(isinstance(stmt, dict) and ('Action' in stmt or 'Resource' in stmt or 'Effect' in stmt) for stmt in data)
            if is_list_of_statements:
                 # print(f"Wrapping list of statements from '{file_path}' into a single policy document.")
                 return [{'Version': '2012-10-17', 'Statement': data}] # Wrap statements in a doc
            
            # Check if it's a list of policy documents or items containing policy documents
            processed_list = []
            for item in data:
                if isinstance(item, dict) and 'PolicyDocument' in item and isinstance(item['PolicyDocument'], dict):
                    processed_list.append(item['PolicyDocument']) # Extract the document
                elif isinstance(item, dict) and 'Statement' in item:
                    processed_list.append(item) # It's already a document
                else:
                    print(f"Warning: Item in policy file '{file_path}' for '{policy_name}' is not a recognized policy document structure: {item}", file=sys.stderr)
            if processed_list:
                return processed_list

        print(f"Error: Policy file '{file_path}' for '{policy_name}' content is not in expected format. Returning empty list.", file=sys.stderr)
        return []
    except FileNotFoundError: # Already handled by load_json_file, but for safety
        print(f"Error: {policy_name.capitalize()} policy file '{file_path}' not found. Assuming empty policy.", file=sys.stderr)
        return []
    except Exception as e: # Catch other errors from load_json_file or here
        print(f"An error occurred processing policy file '{file_path}' for '{policy_name}': {e}. Assuming empty policy.", file=sys.stderr)
        return []