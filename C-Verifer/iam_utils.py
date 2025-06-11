# cverifier/iam_utils.py
import re

def aws_wildcard_to_regex(pattern_str):
    """Converts an AWS IAM wildcard pattern to a regex pattern string."""
    escaped_pattern = re.escape(pattern_str)
    regex_pattern = escaped_pattern.replace(r'\*', '.*').replace(r'\?', '.')
    return f"^{regex_pattern}$"

def _do_individual_patterns_overlap(pattern1_str, pattern2_str):
    
    if not isinstance(pattern1_str, str) or not isinstance(pattern2_str, str):
        return False 
    if pattern1_str == pattern2_str:
        return True
    if pattern1_str == "*": 
        return True 
    if pattern2_str == "*": 
        return True

    if item_matches_pattern(pattern1_str, pattern2_str):
        return True
    if item_matches_pattern(pattern2_str, pattern1_str):
        return True
        
    return False

def item_matches_pattern(item_str, policy_pattern_str):
    """
    Checks if an item string (potentially with wildcards, acting as a 'request')
    is satisfied by a policy pattern string (which can also contain AWS wildcards).
    This means item_str must be "covered" by policy_pattern_str.
    """
    if policy_pattern_str == "*":
        return True
    if item_str == "*": # Request for "*" is only covered if policy is also "*"
        return policy_pattern_str == "*"

    policy_regex = aws_wildcard_to_regex(policy_pattern_str)
    return bool(re.fullmatch(policy_regex, item_str))

def get_statement_permission_elements(statement, element_type):
    """Helper to get Action or Resource list from a statement, always returns a list."""
    elements = statement.get(element_type, [])
    processed_elements = []

    if isinstance(elements, str):
        if element_type == 'Action':
            processed_elements.append(elements.lower())
        else:
            processed_elements.append(elements)
    elif isinstance(elements, list):
        for elem in elements:
            if isinstance(elem, str):
                if element_type == 'Action':
                    processed_elements.append(elem.lower())
                else:
                    processed_elements.append(elem)
    
    return processed_elements

def check_permission_on_policies(requested_action, requested_resource, policy_documents):
    """
    Checks if a requested_action on a requested_resource is allowed by a list of policy_documents.
    Returns 'ALLOW' or 'DENY'. Conditions are IGNORED in this simplified version.
    """
    # Ensure policy_documents is a list of valid policy document structures
    valid_policy_documents = []
    for doc_item in policy_documents:
        if isinstance(doc_item, dict) and 'PolicyDocument' in doc_item:
            doc_content = doc_item['PolicyDocument']
            if isinstance(doc_content, dict) and 'Statement' in doc_content:
                valid_policy_documents.append(doc_content)
        elif isinstance(doc_item, dict) and 'Statement' in doc_item: # Already a direct policy doc
             valid_policy_documents.append(doc_item)

    # Phase 1: Check for explicit Deny
    for doc in valid_policy_documents:
        if not isinstance(doc, dict) or 'Statement' not in doc:
            continue
        for stmt in doc.get('Statement', []):
            if not isinstance(stmt, dict): continue
            effect = stmt.get('Effect')
            if effect == 'Deny':
                actions_in_stmt = get_statement_permission_elements(stmt, 'Action')
                not_actions_in_stmt = get_statement_permission_elements(stmt, 'NotAction')
                
                action_match = False
                if not_actions_in_stmt:
                    action_match = not any(item_matches_pattern(requested_action, pol_act) for pol_act in not_actions_in_stmt)
                elif actions_in_stmt:
                    action_match = any(item_matches_pattern(requested_action, pol_act) for pol_act in actions_in_stmt)
                
                if not action_match: continue

                resources_in_stmt = get_statement_permission_elements(stmt, 'Resource')
                not_resources_in_stmt = get_statement_permission_elements(stmt, 'NotResource')

                resource_match = False
                if not_resources_in_stmt:
                    resource_match = not any(item_matches_pattern(requested_resource, pol_res) for pol_res in not_resources_in_stmt)
                elif resources_in_stmt:
                    resource_match = any(item_matches_pattern(requested_resource, pol_res) for pol_res in resources_in_stmt)
                
                if resource_match:
                    return 'DENY'
    
    # Phase 2: Check for explicit Allow
    for doc in valid_policy_documents:
        if not isinstance(doc, dict) or 'Statement' not in doc:
            continue
        for stmt in doc.get('Statement', []):
            if not isinstance(stmt, dict): continue
            effect = stmt.get('Effect')
            if effect == 'Allow':
                actions_in_stmt = get_statement_permission_elements(stmt, 'Action')
                not_actions_in_stmt = get_statement_permission_elements(stmt, 'NotAction')

                action_match = False
                if not_actions_in_stmt:
                    action_match = not any(item_matches_pattern(requested_action, pol_act) for pol_act in not_actions_in_stmt)
                elif actions_in_stmt:
                    action_match = any(item_matches_pattern(requested_action, pol_act) for pol_act in actions_in_stmt)

                if not action_match: continue

                resources_in_stmt = get_statement_permission_elements(stmt, 'Resource')
                not_resources_in_stmt = get_statement_permission_elements(stmt, 'NotResource')
                
                resource_match = False
                if not_resources_in_stmt:
                    resource_match = not any(item_matches_pattern(requested_resource, pol_res) for pol_res in not_resources_in_stmt)
                elif resources_in_stmt:
                    resource_match = any(item_matches_pattern(requested_resource, pol_res) for pol_res in resources_in_stmt)

                if resource_match:
                    return 'ALLOW'
    return 'DENY' # Default deny

def get_cleaned_policy_documents_from_role_data(role_permission_data):
    """
    Extracts and cleans policy documents from role data structure.
    Role_permission_data can be a list of items, where each item might be
    a full policy document or an object containing a 'PolicyDocument' field.
    """
    actual_policy_docs = []
    if not role_permission_data:
        return []
    for item in role_permission_data:
        if not isinstance(item, dict):
            continue
        policy_doc_to_add = None
        if 'PolicyDocument' in item: # Structure like {'PolicyName': 'name', 'PolicyDocument': { ... }}
            potential_doc = item.get('PolicyDocument')
            if isinstance(potential_doc, dict) and 'Statement' in potential_doc and 'Version' in potential_doc:
                policy_doc_to_add = potential_doc
        elif 'Statement' in item and 'Version' in item: # Direct policy document
            policy_doc_to_add = item
        
        if policy_doc_to_add:
            actual_policy_docs.append(policy_doc_to_add)
    return actual_policy_docs