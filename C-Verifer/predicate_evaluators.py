# cverifier/predicate_evaluators.py
import re
from .iam_utils import get_statement_permission_elements, aws_wildcard_to_regex
from .policy_analyzer import evaluate_is_subset_of_permissions as policy_is_subset_simple
from .policy_analyzer import evaluate_is_subset_of_permissions_with_conditions as policy_is_subset_with_conditions
from .policy_analyzer import evaluate_has_intersection as policy_has_intersection

# Predicate 1: AllowsAssumeRole(TP, CP)
def eval_AllowsAssumeRole(trust_policy_doc, pool_id):
    if not isinstance(trust_policy_doc, dict) or 'Statement' not in trust_policy_doc:
        return False
    assume_action = 'sts:assumerolewithwebidentity'
    cognito_federated_principal = "cognito-identity.amazonaws.com"
    aud_condition_key = 'cognito-identity.amazonaws.com:aud'

    for statement in trust_policy_doc.get('Statement', []):
        if not isinstance(statement, dict) or statement.get('Effect') != 'Allow':
            continue
        
        stmt_actions = get_statement_permission_elements(statement, 'Action')
        action_match = assume_action in stmt_actions or "*" in stmt_actions
        if not action_match: continue
        
        stmt_principal = statement.get('Principal')
        principal_match = False
        if isinstance(stmt_principal, dict):
            if stmt_principal.get('Federated') == cognito_federated_principal or stmt_principal.get('Federated') == "*":
                principal_match = True
        elif stmt_principal == "*": # Principal: "*" implies any principal, including federated ones
             principal_match = True
        if not principal_match: continue
        
        conditions = statement.get('Condition')
        aud_condition_met = False
        if not conditions: # No conditions means it's less restrictive
            aud_condition_met = True
        else:
            aud_key_is_present = False
            for op_type, kv_map in conditions.items():
                if aud_condition_key in kv_map:
                    aud_key_is_present = True
                    allowed_auds = kv_map[aud_condition_key]
                    if not isinstance(allowed_auds, list): allowed_auds = [allowed_auds]
                    
                    if 'StringEquals' in op_type and pool_id in allowed_auds:
                        aud_condition_met = True; break
                    elif 'StringLike' in op_type:
                        # Ensure patterns are strings before regex conversion
                        valid_patterns = [p for p in allowed_auds if isinstance(p, str)]
                        if any(re.fullmatch(aws_wildcard_to_regex(pat), pool_id) for pat in valid_patterns):
                            aud_condition_met = True; break
            # If Condition block exists but doesn't specify the cognito-identity:aud key,
            # it means it doesn't restrict based on pool ID for this specific key.
            # This logic depends on how strictly you interpret "permits the Cognito Identity Pool CP".
            # Typically, if Federated Principal is cognito-identity, an aud check is expected.
            # If no aud key, it might be too broad or intended for other conditions.
            # For this predicate, we require the aud condition to match or be absent IF principal is cognito.
            if not aud_key_is_present and principal_match : aud_condition_met = True


        if aud_condition_met: return True
    return False

# Predicate 2: ClassicFlowEnabled(CF) (where CF is Cognito Pool Config)
def eval_ClassicFlowEnabled(pool_config):
    if not isinstance(pool_config, dict): return False
    # In AWS Cognito, "AllowClassicFlow" is the typical key for enabling basic (developer authenticated) flow.
    return pool_config.get('AllowClassicFlow', False) 

# Predicate 3: SpecifiedRoleInConfig(CF, R) (CF is Pool Config, R is Role ARN)
def eval_SpecifiedRoleInConfig(pool_config, role_arn_to_check):
    if not isinstance(pool_config, dict): return False
    unauth_role = pool_config.get('UnauthenticatedRoleArn')
    auth_role = pool_config.get('AuthenticatedRoleArn')
    
    # Roles can be specified directly at the top level of pool config or within 'Roles' map
    roles_map = pool_config.get('Roles', {}) # For { "authenticated": "arn:...", "unauthenticated": "arn:..."}
    
    if role_arn_to_check:
        if role_arn_to_check == unauth_role or role_arn_to_check == auth_role:
            return True
        if role_arn_to_check == roles_map.get('unauthenticated') or role_arn_to_check == roles_map.get('authenticated'):
            return True
    return False

# Helper for HasWideTrustPolicy
def _trust_policy_allows_amr(trust_policy_doc, pool_id, amr_to_check):
    if not isinstance(trust_policy_doc, dict) or 'Statement' not in trust_policy_doc:
        return False
    assume_action = 'sts:assumerolewithwebidentity'
    cognito_federated_principal = "cognito-identity.amazonaws.com"
    aud_condition_key = 'cognito-identity.amazonaws.com:aud'
    amr_condition_key = 'cognito-identity.amazonaws.com:amr'

    for statement in trust_policy_doc.get('Statement', []):
        if not isinstance(statement, dict) or statement.get('Effect') != 'Allow':
            continue
        
        stmt_actions = get_statement_permission_elements(statement, 'Action')
        action_match = assume_action in stmt_actions or "*" in stmt_actions
        if not action_match: continue

        stmt_principal = statement.get('Principal')
        principal_match = False
        if isinstance(stmt_principal, dict):
            if stmt_principal.get('Federated') == cognito_federated_principal or stmt_principal.get('Federated') == "*":
                principal_match = True
        elif stmt_principal == "*":
            principal_match = True
        if not principal_match: continue
        
        conditions = statement.get('Condition')
        aud_met = False
        # If no conditions, it's broader, so aud is considered met for this principal.
        if not conditions: aud_met = True
        else:
            aud_key_present = False
            for op, kv in conditions.items():
                if aud_condition_key in kv:
                    aud_key_present = True
                    vals = kv[aud_condition_key]
                    if not isinstance(vals, list): vals = [vals]
                    if 'StringEquals' in op and pool_id in vals: aud_met = True; break
                    if 'StringLike' in op:
                        valid_patterns = [p for p in vals if isinstance(p, str)]
                        if any(re.fullmatch(aws_wildcard_to_regex(p), pool_id) for p in valid_patterns): aud_met = True; break
            if not aud_key_present: aud_met = True # No AUD restriction means it passes for any pool w.r.t AUD.
        if not aud_met: continue

        amr_met = False
        # If no conditions, it's broader, so amr is considered met.
        if not conditions: amr_met = True
        else:
            amr_key_present = False
            for op, kv in conditions.items():
                if amr_condition_key in kv:
                    amr_key_present = True
                    pats = kv[amr_condition_key] # These are the allowed AMRs in policy
                    if not isinstance(pats, list): pats = [pats]
                    
                    # We are checking if the amr_to_check (e.g., "authenticated" or "unauthenticated")
                    # is permitted by the policy's AMR conditions.
                    if 'StringEquals' in op:
                        if amr_to_check in pats or "*" in pats: amr_met = True; break
                    if 'ForAnyValue:StringLike' in op or 'StringLike' in op : # AWS uses ForAnyValue:StringLike for AMR
                        valid_patterns = [p for p in pats if isinstance(p, str)]
                        if any(re.fullmatch(aws_wildcard_to_regex(p_policy), amr_to_check) for p_policy in valid_patterns) or \
                           any(p_policy == "*" for p_policy in valid_patterns):
                           amr_met = True; break
            if not amr_key_present: amr_met = True # No AMR restriction means it passes for any AMR.
        if not amr_met: continue
        
        if aud_met and amr_met: return True # Found a statement that allows it
    return False


# Predicate 4: HasWideTrustPolicy(TP, CP)
def eval_HasWideTrustPolicy(trust_policy_doc, pool_id):
    """
    Holds if the trust policy TP permits both anonymous identities and 
    authenticated identities, originating from the Cognito Identity Pool CP, to assume said role.
    """
    allows_auth = _trust_policy_allows_amr(trust_policy_doc, pool_id, "authenticated")
    allows_unauth = _trust_policy_allows_amr(trust_policy_doc, pool_id, "unauthenticated")
    return allows_auth and allows_unauth

# --- MODIFICATION START: This function now acts as a router ---
# Predicate 5: IsSubsetOfPermissions(P1, P2)
def eval_IsSubsetOfPermissions(p1_permission_docs, p2_boundary_docs, check_condition=False):
    """ 
    Wrapper for policy_analyzer functions.
    If check_condition is True, it uses the advanced Z3-based method.
    Otherwise, it uses the faster, simpler method.
    """
    if check_condition:
        # Call the new, more precise method that handles Condition blocks
        return policy_is_subset_with_conditions(p1_permission_docs, p2_boundary_docs)
    else:
        # Call the original, faster method
        return policy_is_subset_simple(p1_permission_docs, p2_boundary_docs)
# --- MODIFICATION END ---

# Predicate 6: HasIntersection(P1, P2)
def eval_HasIntersection(p1_permission_docs, p2_target_docs):
    """ Wrapper for policy_analyzer function """
    return policy_has_intersection(p1_permission_docs, p2_target_docs)