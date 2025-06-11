# cverifier/policy_analyzer.py
# --- Imports for FSM-based checker ---
from interegular import parse_pattern, FSM
import re
import ipaddress
import sys
from z3 import (Solver, String, StringVal, Int, IntVal, Real, RealVal, Bool, 
                BoolVal, And, Or, Not, If, sat, unsat, unknown, 
                Re, Range, Star, Concat, InRe, BitVec, BitVecVal, UGE, ULE)
from typing import Dict, Any, List, Optional
from .iam_utils import get_statement_permission_elements, check_permission_on_policies, get_cleaned_policy_documents_from_role_data,_do_individual_patterns_overlap

# ==============================================================================
#  METHOD 2 FOR SUBSET CHECK (Z3-BASED)
# ==============================================================================
class IAMPolicyComparer:
    """
    Uses the Z3 SMT solver to compare IAM policies with Action, Resource, and Condition blocks.
    This version includes a timeout for the solver.
    """
    def __init__(self, timeout_ms: int = 5000):
        self.request_action = String('request_action')
        self.request_resource = String('request_resource')
        self.z3_vars = {
            'request_action': self.request_action,
            'request_resource': self.request_resource
        }
        self.ANY_CHAR_RE = Range(' ', '~')
        self.KEY_TYPE_MAP = {"aws:SourceIp": "ipaddress"}
        self.timeout = timeout_ms

    def _get_z3_var(self, key: str):
        if key in self.z3_vars: return self.z3_vars[key]
        key_type = self.KEY_TYPE_MAP.get(key, 'string')
        if key_type == 'ipaddress': var = BitVec(key, 32)
        else: var = String(key)
        self.z3_vars[key] = var
        return var

    def _wildcard_to_z3_re(self, pattern: str) -> Re:
        if not isinstance(pattern, str):
            pattern = str(pattern)
        if not pattern: return Re("")
        
        iam_var_re = r'\$\{[^}]+\}'
        wildcard_re = r'([*?])'
        full_pattern_re = f'({iam_var_re}|{wildcard_re})'
        chunks = re.split(full_pattern_re, pattern)
        
        z3_re_parts = []
        for chunk in chunks:
            if not chunk: continue
            
            if re.fullmatch(iam_var_re, chunk) or chunk == '*':
                z3_re_parts.append(Star(self.ANY_CHAR_RE))
            elif chunk == '?':
                z3_re_parts.append(self.ANY_CHAR_RE)
            else:
                escaped_chunk = re.escape(chunk)
                z3_re_parts.append(Re(escaped_chunk))
                
        if not z3_re_parts: return Re("")
        if len(z3_re_parts) == 1: return z3_re_parts[0]
        return Concat(*z3_re_parts)

    def _cidr_to_z3_constraint(self, z3_var, cidr_str, is_negated=False):
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            start_addr, end_addr = int(net.network_address), int(net.broadcast_address)
            constraint = And(UGE(z3_var, start_addr), ULE(z3_var, end_addr))
            return Not(constraint) if is_negated else constraint
        except ValueError: return BoolVal(False)

    def _translate_condition(self, condition_block: Dict[str, Any]) -> BoolVal:
        if not condition_block: return BoolVal(True)
        all_op_constraints = []
        for op, key_value_map in condition_block.items():
            op_base = op.replace("IfExists", "")
            for key, values in key_value_map.items():
                if not isinstance(values, list): values = [values]
                if not values: continue
                
                z3_var = self._get_z3_var(key)
                value_constraints = []
                for v in values:
                    v_str = str(v)
                    constraint = BoolVal(False)
                    if op_base == "StringEquals": constraint = (z3_var == StringVal(v_str))
                    elif op_base == "StringNotEquals": constraint = Not(z3_var == StringVal(v_str))
                    elif op_base == "StringLike": constraint = InRe(z3_var, self._wildcard_to_z3_re(v_str))
                    elif op_base == "StringNotLike": constraint = Not(InRe(z3_var, self._wildcard_to_z3_re(v_str)))
                    elif op_base == "IpAddress": constraint = self._cidr_to_z3_constraint(z3_var, v_str)
                    elif op_base == "NotIpAddress": constraint = self._cidr_to_z3_constraint(z3_var, v_str, is_negated=True)
                    elif "ForAnyValue" in op_base or "ForAllValues" in op_base:
                        if "StringLike" in op_base: constraint = InRe(z3_var, self._wildcard_to_z3_re(v_str))
                        elif "StringEquals" in op_base: constraint = (z3_var == StringVal(v_str))
                    
                    value_constraints.append(constraint)
                all_op_constraints.append(Or(value_constraints))
        return And(all_op_constraints) if all_op_constraints else BoolVal(True)

    def _statement_to_z3(self, stmt: Dict[str, Any]) -> BoolVal:
        action_patterns = get_statement_permission_elements(stmt, 'Action')
        not_action_patterns = get_statement_permission_elements(stmt, 'NotAction')
        
        if not_action_patterns:
            not_action_constraints = [InRe(self.request_action, self._wildcard_to_z3_re(p)) for p in not_action_patterns]
            action_match = Not(Or(not_action_constraints))
        elif action_patterns:
            action_constraints = [InRe(self.request_action, self._wildcard_to_z3_re(p)) for p in action_patterns]
            action_match = Or(action_constraints)
        else:
            action_match = BoolVal(False)

        resource_patterns = get_statement_permission_elements(stmt, 'Resource')
        not_resource_patterns = get_statement_permission_elements(stmt, 'NotResource')

        if not_resource_patterns:
            not_resource_constraints = [InRe(self.request_resource, self._wildcard_to_z3_re(p)) for p in not_resource_patterns]
            resource_match = Not(Or(not_resource_constraints))
        elif resource_patterns:
            resource_constraints = [InRe(self.request_resource, self._wildcard_to_z3_re(p)) for p in resource_patterns]
            resource_match = Or(resource_constraints)
        else:
            resource_match = BoolVal(False)

        condition_match = self._translate_condition(stmt.get("Condition", {}))
        return And(action_match, resource_match, condition_match)

    def _policy_to_z3(self, policy: Dict[str, Any]) -> BoolVal:
        statements = policy.get("Statement", [])
        if not isinstance(statements, list): statements = [statements]
        
        allow_formulas, deny_formulas = [], []
        for stmt in statements:
            if not isinstance(stmt, dict): continue
            stmt_formula = self._statement_to_z3(stmt)
            if stmt.get("Effect") == "Allow": allow_formulas.append(stmt_formula)
            elif stmt.get("Effect") == "Deny": deny_formulas.append(stmt_formula)

        final_allow_part = Or(allow_formulas) if allow_formulas else BoolVal(False)
        final_deny_part = Not(Or(deny_formulas)) if deny_formulas else BoolVal(True)
        return And(final_allow_part, final_deny_part)
        
    def _check(self, formula: BoolVal) -> bool:
        solver = Solver()
        solver.set('timeout', self.timeout)
        solver.add(formula)
        result = solver.check()
        
        if result == unknown:
            print(f"  [Warning] Z3 solver timed out. Cannot determine relationship, conservatively returning False (not a subset).", file=sys.stderr)
            return False
            
        return result == sat

    def is_subset(self, p1: Dict[str, Any], p2: Dict[str, Any]) -> bool:
        self.z3_vars = {'request_action': self.request_action, 'request_resource': self.request_resource}
        
        all_keys = set()
        for p in [p1, p2]:
            for stmt in p.get("Statement", []):
                if not isinstance(stmt, dict): continue
                if "Condition" in stmt and isinstance(stmt["Condition"], dict):
                    for op in stmt["Condition"]:
                        if isinstance(stmt["Condition"][op], dict):
                            all_keys.update(stmt["Condition"][op].keys())
        for key in all_keys:
            self._get_z3_var(key)

        p1_formula = self._policy_to_z3(p1)
        p2_formula = self._policy_to_z3(p2)
        counter_example_formula = And(p1_formula, Not(p2_formula))
        found_counter_example = self._check(counter_example_formula)
        return not found_counter_example

def combine_policy_docs_to_single_doc(policy_docs: list) -> dict:
    """Merges a list of policy documents into a single document with all statements."""
    all_statements = []
    cleaned_docs = get_cleaned_policy_documents_from_role_data(policy_docs)
    for doc in cleaned_docs:
        statements = doc.get('Statement', [])
        if isinstance(statements, list):
            all_statements.extend(statements)
        elif isinstance(statements, dict):
            all_statements.append(statements)
    return {"Version": "2012-10-17", "Statement": all_statements}

def evaluate_is_subset_of_permissions_with_conditions(p1_permission_docs, p2_boundary_docs):
    """
    Predicate: IsSubsetOfPermissions(P1, P2) using the Z3 SMT solver to handle Condition blocks.
    """
    master_p1 = combine_policy_docs_to_single_doc(p1_permission_docs)
    master_p2 = combine_policy_docs_to_single_doc(p2_boundary_docs)
    if not master_p1.get("Statement"): return True
    comparer = IAMPolicyComparer()
    return comparer.is_subset(master_p1, master_p2)

def _p1_allows_something_p2_denies(p1_raw_docs, p2_raw_docs):
    p1_docs = get_cleaned_policy_documents_from_role_data(p1_raw_docs)
    p2_docs = get_cleaned_policy_documents_from_role_data(p2_raw_docs)
    if not p1_docs: return False
    for p1_doc_content in p1_docs:
        for p1_statement in p1_doc_content.get('Statement', []):
            if not isinstance(p1_statement, dict): continue
            if p1_statement.get('Effect') == 'Allow':
                
                actions_from_p1_stmt = get_statement_permission_elements(p1_statement, 'Action')
                if get_statement_permission_elements(p1_statement, 'NotAction'): continue
                resources_from_p1_stmt = get_statement_permission_elements(p1_statement, 'Resource')
                if get_statement_permission_elements(p1_statement, 'NotResource'): continue
                for action_to_check in actions_from_p1_stmt:
                    for resource_to_check in resources_from_p1_stmt:
                        perm_status_in_p1 = check_permission_on_policies(action_to_check, resource_to_check, p1_docs)
                        if perm_status_in_p1 == 'ALLOW':
                            perm_status_in_p2 = check_permission_on_policies(action_to_check, resource_to_check, p2_docs)
                            if perm_status_in_p2 == 'DENY': return True
    return False

def evaluate_is_subset_of_permissions(p1_permission_docs, p2_boundary_docs):
    return not _p1_allows_something_p2_denies(p1_permission_docs, p2_boundary_docs)

# ==============================================================================
#  INTERSECTION LOGIC (Method 1 and Method 2 with Router)
# ==============================================================================

# --- METHOD 2 FOR INTERSECTION (FSM-BASED) ---
class PolicyIntersectionFinder:
    """
    Efficiently compares AWS IAM policies using Finite State Machines (FSM).
    This version handles complex wildcards and Deny statements.
    """
    SEPARATOR = "::SEP::"

    def __init__(self, policy1_doc: Dict[str, Any], policy2_doc: Dict[str, Any]):
        self.p1_statements = self._get_statements(policy1_doc)
        self.p2_statements = self._get_statements(policy2_doc)

    def _wildcard_to_regex(self, pattern: str) -> str:
        if not pattern: return ""
        pattern = pattern.replace(r'*', r'__STAR__').replace(r'?', r'__QUESTION__')
        pattern = re.escape(pattern)
        return pattern.replace(r'__STAR__', r'.*').replace(r'__QUESTION__', r'.')
    
    def _get_statements(self, policy_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        statements = policy_doc.get("Statement", [])
        return statements if isinstance(statements, list) else [statements]

    def _create_automaton_for_effect(self, statements: List[Dict[str, Any]], effect: str) -> FSM:
        final_automaton = None
        for stmt in statements:
            if stmt.get("Effect") != effect: continue

            actions = get_statement_permission_elements(stmt, 'Action')
            resources = get_statement_permission_elements(stmt, 'Resource')

            if not actions or not resources: continue

            action_regex_parts = [f"(?:{self._wildcard_to_regex(p)})" for p in actions]
            resource_regex_parts = [f"(?:{self._wildcard_to_regex(p)})" for p in resources]
            
            action_regex = f"(?:{'|'.join(action_regex_parts)})"
            resource_regex = f"(?:{'|'.join(resource_regex_parts)})"

            combined_regex = action_regex + self.SEPARATOR + resource_regex
            
            stmt_automaton = parse_pattern(combined_regex).to_fsm()

            if final_automaton is None:
                final_automaton = stmt_automaton
            else:
                final_automaton = final_automaton.union(stmt_automaton)
        
        if final_automaton is None:
            return parse_pattern("(?=a)b").to_fsm() # Empty FSM
            
        return final_automaton

    def has_intersection(self) -> bool:
        p1_allow_fsm = self._create_automaton_for_effect(self.p1_statements, "Allow")
        p1_deny_fsm = self._create_automaton_for_effect(self.p1_statements, "Deny")
        p2_allow_fsm = self._create_automaton_for_effect(self.p2_statements, "Allow")
        p2_deny_fsm = self._create_automaton_for_effect(self.p2_statements, "Deny")

        # Permissions allowed by both P1 and P2
        common_allow_fsm = p1_allow_fsm.intersection(p2_allow_fsm)
        if not common_allow_fsm.finals: return False

        # Permissions denied by either P1 or P2
        total_deny_fsm = p1_deny_fsm.union(p2_deny_fsm)
        
        # Effective intersection is the set of common allows that are NOT in the total denies.
        # This is equivalent to common_allow_fsm - total_deny_fsm
        effective_intersection = common_allow_fsm.difference(total_deny_fsm)
        
        # If the resulting automaton is not empty, there is a valid intersection.
        return bool(effective_intersection.finals)

def _evaluate_has_intersection_fsm(p1_permission_docs, p2_target_docs):
    """Entrypoint for the FSM-based intersection checker."""
    master_p1 = combine_policy_docs_to_single_doc(p1_permission_docs)
    master_p2 = combine_policy_docs_to_single_doc(p2_target_docs)
    
    finder = PolicyIntersectionFinder(master_p1, master_p2)
    return finder.has_intersection()

# --- METHOD 1 FOR INTERSECTION (SIMPLE) ---
def _check_pattern_lists_overlap(list1_patterns, list2_patterns):
    if not list1_patterns or not list2_patterns: return False
    for p1 in list1_patterns:
        for p2 in list2_patterns:
            if _do_individual_patterns_overlap(p1, p2): return True
    return False

def _evaluate_has_intersection_simple(p1_permission_docs, p2_target_docs):
    p1_docs = get_cleaned_policy_documents_from_role_data(p1_permission_docs)
    p2_docs = get_cleaned_policy_documents_from_role_data(p2_target_docs)
    if not p1_docs or not p2_docs: return False

    for p1_doc_content in p1_docs:
        for p1_statement in p1_doc_content.get('Statement', []):
            if not isinstance(p1_statement, dict) or p1_statement.get('Effect') != 'Allow': continue
            if get_statement_permission_elements(p1_statement, 'NotAction'): continue
            if get_statement_permission_elements(p1_statement, 'NotResource'): continue

            actions1_list = get_statement_permission_elements(p1_statement, 'Action')
            resources1_list = get_statement_permission_elements(p1_statement, 'Resource')
            if not actions1_list or not resources1_list: continue

            for p2_doc_content in p2_docs:
                for p2_statement in p2_doc_content.get('Statement', []):
                    if not isinstance(p2_statement, dict) or p2_statement.get('Effect') != 'Allow': continue
                    if get_statement_permission_elements(p2_statement, 'NotAction'): continue
                    if get_statement_permission_elements(p2_statement, 'NotResource'): continue
                    
                    actions2_list = get_statement_permission_elements(p2_statement, 'Action')
                    resources2_list = get_statement_permission_elements(p2_statement, 'Resource')
                    if not actions2_list or not resources2_list: continue
                    
                    if _check_pattern_lists_overlap(actions1_list, actions2_list):
                        if _check_pattern_lists_overlap(resources1_list, resources2_list):
                            return True 
    return False

# --- ROUTER FOR INTERSECTION CHECK ---
def _is_policy_simple(policy_docs: List[Dict[str, Any]]) -> bool:
    """Checks if a policy is simple enough for the fast checker."""
    cleaned_docs = get_cleaned_policy_documents_from_role_data(policy_docs)
    all_statements = []
    for doc in cleaned_docs:
        statements = doc.get("Statement", [])
        if isinstance(statements, list):
            all_statements.extend(statements)
        else:
            all_statements.append(statements)

    if len(all_statements) != 1: return False
    
    stmt = all_statements[0]

    resources = get_statement_permission_elements(stmt, "Resource")
    for res in resources:
        if isinstance(res, str) and res.count('*') >= 2:
            return False
            
    return True

def evaluate_has_intersection(p1_permission_docs: List[Dict[str, Any]], p2_target_docs: List[Dict[str, Any]]):
    """
    Router for intersection checking. Chooses between a fast, simple method and
    a more powerful FSM-based method based on policy complexity.
    """
    try:
        if not _is_policy_simple(p1_permission_docs) and not _is_policy_simple(p2_target_docs):
            # If either policy is complex, use the FSM method.
            return _evaluate_has_intersection_fsm(p1_permission_docs, p2_target_docs)
    except NameError: 
        # FSM is not defined because interegular is not installed. Fallback to simple method.
        pass

    # If both policies are simple (or FSM library not available), use the fast method.
    return _evaluate_has_intersection_simple(p1_permission_docs, p2_target_docs)