# cverifier/z3_types.py
from z3 import Function, StringSort, BoolSort

# Using StringSort for identifiers like Role ARN and Cognito Pool ID
RoleARN = StringSort()
CognitoPoolID = StringSort()
PolicySetID = StringSort() # To distinguish P0, Pbase, Psession, Psensitive

# --- Z3 Predicate Function Declarations ---
# Matches the image: AllowsAssumeRole(TP,CP) where TP is implicit in RoleARN, CP is CognitoPoolID
AllowsAssumeRole_Z3 = Function('AllowsAssumeRole', RoleARN, CognitoPoolID, BoolSort())

# Matches ClassicFlowEnabled(CF) where CF is implicit in CognitoPoolID
ClassicFlowEnabled_Z3 = Function('ClassicFlowEnabled', CognitoPoolID, BoolSort())

# Matches SpecifiedRoleInConfig(CF,R) where CF is CognitoPoolID, R is RoleARN
SpecifiedRoleInConfig_Z3 = Function('SpecifiedRoleInConfig', CognitoPoolID, RoleARN, BoolSort())

# Matches HasWideTrustPolicy(TP,CP) where TP is implicit in RoleARN, CP is CognitoPoolID
HasWideTrustPolicy_Z3 = Function('HasWideTrustPolicy', RoleARN, CognitoPoolID, BoolSort())

# Matches IsSubsetOfPermissions(P1,P2)
# P1 is implicit in RoleARN (permissions of that role)
# P2 is identified by PolicySetID (e.g., "P0", "Pbase", "Psession")
IsSubsetOfPermissions_Z3 = Function('IsSubsetOfPermissions', RoleARN, PolicySetID, BoolSort())

# Matches HasIntersection(P1,P2)
# P1 is implicit in RoleARN (permissions of that role)
# P2 is identified by PolicySetID (e.g., "Psensitive")
HasIntersection_Z3 = Function('HasIntersection', RoleARN, PolicySetID, BoolSort())