import json
import subprocess
import sys
import os
import json

def run_aws_cli_command(command, identity_pool_id=None, role_name=None, policy_arn=None, policy_name=None, version_id=None):
    """Helper function to run AWS CLI commands and return JSON output."""
    try:
        subprocess.run([sys.executable, '-m', 'awscli', '--version'], check=True, capture_output=True, text=True)
        aws_command = [sys.executable, '-m', 'awscli']
    except (subprocess.CalledProcessError, FileNotFoundError):
        aws_command = ['aws'] # Fallback to 'aws' command in PATH

    aws_command.extend(command)

    # Add command-specific parameters
    if identity_pool_id:
        aws_command.extend(['--identity-pool-id', identity_pool_id])
    if role_name:
        aws_command.extend(['--role-name', role_name])
    if policy_arn:
        aws_command.extend(['--policy-arn', policy_arn])
    if policy_name:
        aws_command.extend(['--policy-name', policy_name])
    if version_id:
        aws_command.extend(['--version-id', version_id])

    aws_command.extend(['--output', 'json']) # Always request JSON output

    # print(f"Running command: {' '.join(aws_command)}") # Debug print

    try:
        # Use check=True to raise CalledProcessError if the command fails
        result = subprocess.run(aws_command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except FileNotFoundError:
        print(f"Error: AWS CLI executable not found. Please install it.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"AWS CLI command failed: {e}", file=sys.stderr)
        print(f"Stderr: {e.stderr}", file=sys.stderr)
        # For permissions errors, suggest checking policies
        if "An error occurred (UnauthorizedOperation)" in e.stderr:
             print("Possible permissions error. Ensure your AWS credentials have sufficient permissions to list/get IAM roles and Cognito identity pools.", file=sys.stderr)
        return None
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON from AWS CLI output.", file=sys.stderr)
        print(f"Stdout: {result.stdout}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None

def get_roles_data_trusting_cognito():
    """Gets information only for IAM roles whose trust policy contains 'cognito-identity.amazonaws.com'."""
    roles_data = []
    print("Listing all IAM roles to filter by trust policy (searching for 'cognito-identity.amazonaws.com')...")
    roles_list_output = run_aws_cli_command(['iam', 'list-roles', '--max-items', '1000'])

    if not roles_list_output or 'Roles' not in roles_list_output:
        print("Could not list IAM roles.", file=sys.stderr)
        return []

    print(f"Found {len(roles_list_output['Roles'])} roles. Checking trust policies...")

    for role_summary in roles_list_output['Roles']:
        role_arn = role_summary['Arn']
        role_name = role_summary['RoleName']

        # Get Trust Policy
        role_full_output = run_aws_cli_command(['iam', 'get-role', '--role-name', role_name])
        trust_policy_doc = None
        if role_full_output and 'Role' in role_full_output:
            trust_policy_doc = role_full_output['Role'].get('AssumeRolePolicyDocument')

        is_cognito_trusted = False
        if trust_policy_doc:
            try:
                trust_policy_string = json.dumps(trust_policy_doc, separators=(',', ':'))
                if "cognito-identity.amazonaws.com" in trust_policy_string:
                    is_cognito_trusted = True
            except Exception as e:
                print(f"Warning: Could not serialize trust policy for role {role_name}: {e}", file=sys.stderr)

        if is_cognito_trusted:
            print(f"  [MATCH] Role '{role_name}' trusts Cognito. Getting its permission policies.")

            # Get Permission Policies (Inline)
            inline_policies_docs = []
            inline_policy_names_output = run_aws_cli_command(['iam', 'list-role-policies', '--role-name', role_name])
            if inline_policy_names_output and 'PolicyNames' in inline_policy_names_output:
                for policy_name in inline_policy_names_output['PolicyNames']:
                    inline_policy_doc_output = run_aws_cli_command(['iam', 'get-role-policy', '--role-name', role_name, '--policy-name', policy_name])
                    if inline_policy_doc_output and 'PolicyDocument' in inline_policy_doc_output:
                         inline_policies_docs.append(inline_policy_doc_output['PolicyDocument'])

            # Get Permission Policies (Attached Managed)
            attached_policies_docs = []
            attached_policies_list_output = run_aws_cli_command(['iam', 'list-attached-role-policies', '--role-name', role_name])
            if attached_policies_list_output and 'AttachedPolicies' in attached_policies_list_output:
                for attached_policy_summary in attached_policies_list_output['AttachedPolicies']:
                    policy_arn = attached_policy_summary['PolicyArn']
                    policy_output = run_aws_cli_command(['iam', 'get-policy', '--policy-arn', policy_arn])
                    if policy_output and 'Policy' in policy_output:
                        default_version_id = policy_output['Policy']['DefaultVersionId']
                        managed_policy_version_output = run_aws_cli_command(['iam', 'get-policy-version', '--policy-arn', policy_arn, '--version-id', default_version_id])
                        if managed_policy_version_output and 'PolicyVersion' in managed_policy_version_output:
                            attached_policies_docs.append(managed_policy_version_output['PolicyVersion']['Document'])

            roles_data.append({
                "arn": role_arn,
                "name": role_name,
                "trust_policy_document": trust_policy_doc,
                "permission_policy_documents": inline_policies_docs + attached_policies_docs
            })
        else:
            # print(f"  [SKIP] Role '{role_name}' does NOT trust Cognito.") # Optional: uncomment to see skipped roles
            pass

    return roles_data

def get_all_identity_pools_data():
    """Gets configuration information for all Cognito Identity Pools, including default roles."""
    pools_data = []
    print("\nListing Cognito Identity Pools...")
    pools_list_output = run_aws_cli_command(['cognito-identity', 'list-identity-pools', '--max-results', '60'])

    if not pools_list_output or 'IdentityPools' not in pools_list_output:
        print("Could not list Cognito Identity Pools.", file=sys.stderr)
        return []

    print(f"Found {len(pools_list_output['IdentityPools'])} identity pools.")

    for pool_summary in pools_list_output['IdentityPools']:
        pool_id = pool_summary['IdentityPoolId']
        pool_name = pool_summary['IdentityPoolName']
        print(f"  Getting config and default roles for pool: {pool_name} ({pool_id})")

        # Get Identity Pool Config (from describe-identity-pool)
        pool_details_output = run_aws_cli_command(['cognito-identity', 'describe-identity-pool', '--identity-pool-id', pool_id])

        # Get Default Roles (from get-identity-pool-roles) - THIS IS THE FIX
        pool_roles_output = run_aws_cli_command(['cognito-identity', 'get-identity-pool-roles', '--identity-pool-id', pool_id])

        pool_config = None
        if pool_details_output:
             pool_config = {
                 "AllowUnauthenticatedIdentities": pool_details_output.get("AllowUnauthenticatedIdentities", False),
                 "AllowClassicFlow": pool_details_output.get("AllowClassicFlow", False),
                 # Note: describe-identity-pool's role ARNs might be null, we use get-identity-pool-roles below
                 # "UnauthenticatedRoleArn": pool_details_output.get("UnauthenticatedRoleArn"),
                 # "AuthenticatedRoleArn": pool_details_output.get("AuthenticatedRoleArn"),
                 # Removed RoleMappings
             }
        else:
            print(f"Warning: Could not get describe-identity-pool output for {pool_id}. Skipping config for this pool.", file=sys.stderr)
            continue # Skip this pool if basic config cannot be retrieved

        # Extract roles from get-identity-pool-roles output
        default_unauth_role_arn = None
        default_auth_role_arn = None
        if pool_roles_output and 'Roles' in pool_roles_output:
             default_unauth_role_arn = pool_roles_output['Roles'].get('unauthenticated')
             default_auth_role_arn = pool_roles_output['Roles'].get('authenticated')
             # RoleMappings from get-identity-pool-roles are under 'RoleMappings',
             # but we are currently ignoring RoleMappings in our JSON output structure.

        # Add default roles to the config dictionary
        pool_config["UnauthenticatedRoleArn"] = default_unauth_role_arn
        pool_config["AuthenticatedRoleArn"] = default_auth_role_arn


        pools_data.append({
            "id": pool_id,
            "name": pool_name,
            "config": pool_config
        })

    return pools_data


if __name__ == "__main__":
    output_file = 'aws_cognito_filtered_config_data.json'
    print(f"Generating filtered AWS configuration data to '{output_file}'...")

    config_data = {
        "roles": [],
        "cognito_identity_pools": [],
        "default_anon_policy_permissions": [] # Manual step required: FILL THIS BASED ON AWS DOCS!
    }

    # Get roles data, filtered by trust policy
    config_data["roles"] = get_roles_data_trusting_cognito()
    print(f"\nFinished fetching role data. Found {len(config_data['roles'])} roles trusting Cognito.")


    # Get identity pools data, including default roles from get-identity-pool-roles
    config_data["cognito_identity_pools"] = get_all_identity_pools_data()
    print(f"\nFinished fetching identity pool data. Found {len(config_data['cognito_identity_pools'])} identity pools.")

    # --- Manual Step ---
    print("\n--- MANUAL STEP REQUIRED ---")
    print(f"Edit the generated file '{output_file}' and manually fill in the 'default_anon_policy_permissions' array")
    print("based on the official AWS documentation for Cognito Identity Pool default anonymous session policy.")
    print("Example: [{\"Effect\": \"Allow\", \"Action\": \"mobileanalytics:PutEvents\", \"Resource\": \"*\"}, ...]")
    print("--------------------------")
    # --- End Manual Step ---


    # Write the data to the JSON file
    try:
        with open(output_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        print(f"\nSuccessfully generated configuration data to '{output_file}'.")
        print("Remember to manually add the 'default_anon_policy_permissions'.")

    except Exception as e:
        print(f"Error writing to output file '{output_file}': {e}", file=sys.stderr)