# SOLVER/main.py

# --- BEGIN PREAMBLE ---
import sys
import os

if __name__ == '__main__' and (__package__ is None or __package__ == ''):
    # This script is being run directly, not as part of a module loaded via 'import'
    # or 'python -m'. We need to set up the package context for relative imports.
    
    # Get the absolute path to the directory containing this script (SOLVER)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Get the absolute path to the parent directory of this script's directory
    # (this is the directory that CONTAINS the SOLVER package)
    package_home = os.path.dirname(script_dir)
    
    # Add the parent directory to sys.path if it's not already there.
    # This allows Python to find the 'SOLVER' package.
    if package_home not in sys.path:
        sys.path.insert(0, package_home)
    
    # Set the __package__ attribute.
    # Relative imports like 'from .module' rely on __package__ being set.
    # We set it to the name of the current script's directory (which is "SOLVER").
    __package__ = os.path.basename(script_dir)
# --- END PREAMBLE ---

# Now, the rest of your original main.py (cverifier_main.py) content follows.
# Ensure all your imports that were relative (e.g., from .config_loader) remain as they are.

import argparse
import json
# import sys # sys is already imported in the preamble
# import os # os is already imported in the preamble
import traceback

# Relative imports for modules within the 'SOLVER' package
from .config_loader import load_aws_config_data, load_policy_document_from_file
from .vulnerability_checker import check_vulnerabilities, P0_NAME, PBASE_NAME, PSESSION_NAME, PSENSITIVE_NAME
# from .iam_utils import ... # If main.py needs functions directly from other files, ensure they are imported.
# from .policy_analyzer import ...
# from .predicate_evaluators import ...
# from .z3_types import ...


def main_logic(): # Renamed your main function to avoid conflict if any
    parser = argparse.ArgumentParser(description="C-Verifier: AWS Cognito Configuration Risk Analyzer.")
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the JSON file containing Cognito and IAM configurations."
    )
    parser.add_argument(
        "--pbase",
        help="Path to the JSON file for Pbase policy (for Check 1)."
    )
    parser.add_argument(
        "--psession",
        help="Path to the JSON file for Psession policy (for Check 2)."
    )
    parser.add_argument(
        "--psensitive",
        help="Path to the JSON file for Psensitive policy (for Check 5)."
    )
    parser.add_argument(
        "--checks",
        default="all",
        help='Comma-separated list of checks to run (e.g., "check1,check3,check5"). Use "all" for all checks. '
             'Available: check1, check2, check3, check4, check5.'
    )
    parser.add_argument(
        "--target-pool",
        default=None,
        help="Optional: Specify a single Cognito Pool ID to analyze."
    )
    # --- MODIFICATION START: Added --check-condition flag ---
    parser.add_argument(
        "--check-condition",
        action='store_true',
        help="Enable advanced IAM policy subset checking that considers 'Condition' blocks. This is more accurate but slower."
    )
    # --- MODIFICATION END ---
    args = parser.parse_args()

    # Load main configuration
    if not os.path.exists(args.config):
        # Paths like args.config are relative to the CWD.
        # If running `python main.py` from SOLVER/, then `.\test_config.json` refers to `SOLVER\test_config.json`
        print(f"FATAL Error: Configuration file '{args.config}' (resolved to '{os.path.abspath(args.config)}') not found.", file=sys.stderr)
        sys.exit(1)
    try:
        aws_config = load_aws_config_data(args.config)
    except Exception:
        print(f"FATAL Error: Could not load or parse main configuration file '{args.config}'.", file=sys.stderr)
        sys.exit(1)

    policies = {}
    policy_args_map = {
        PBASE_NAME: args.pbase,
        PSESSION_NAME: args.psession,
        PSENSITIVE_NAME: args.psensitive
    }

    for name, path_arg in policy_args_map.items():
        policy_file_path = None
        if path_arg: # If a path string is provided for this policy
            policy_file_path = path_arg

        if policy_file_path:
            if not os.path.exists(policy_file_path):
                print(f"Warning: Policy file '{policy_file_path}' (resolved to '{os.path.abspath(policy_file_path)}') for {name} not found. {name} will be empty.", file=sys.stderr)
                policies[name] = []
            else:
                try:
                    policies[name] = load_policy_document_from_file(policy_file_path, policy_name=name)
                except Exception:
                    print(f"Warning: Could not load or parse policy file '{policy_file_path}' for {name}. {name} will be empty.", file=sys.stderr)
                    policies[name] = []
        else:
            policies[name] = []


    all_available_checks = ["check1", "check2", "check3", "check4", "check5"]
    checks_to_run = []
    if args.checks.lower() == "all":
        checks_to_run = all_available_checks
    else:
        requested_checks = [c.strip().lower() for c in args.checks.split(',')]
        for rc in requested_checks:
            if rc in all_available_checks:
                checks_to_run.append(rc)
            else:
                print(f"Warning: Unknown check '{rc}' requested. Ignoring.", file=sys.stderr)
    
    if not checks_to_run:
        print("No valid checks selected to run. Exiting.", file=sys.stderr)
        sys.exit(0)

    if "check1" in checks_to_run and not args.pbase : print(f"Warning: Check 1 selected, but --pbase policy not provided (path was '{args.pbase}'). Results may be inaccurate.", file=sys.stderr)
    if "check2" in checks_to_run and not args.psession : print(f"Warning: Check 2 selected, but --psession policy not provided (path was '{args.psession}'). Results may be inaccurate.", file=sys.stderr)
    if "check5" in checks_to_run and not args.psensitive : print(f"Warning: Check 5 selected, but --psensitive policy not provided (path was '{args.psensitive}'). Results may be inaccurate.", file=sys.stderr)

    print(f"\nRunning C-Verifier with the following checks: {', '.join(checks_to_run)}")
    # --- MODIFICATION START: Added message for new flag ---
    if args.check_condition:
        print("Condition block checking is ENABLED. Analysis will be more precise but may take longer.")
    # --- MODIFICATION END ---
    print(f"Using Configuration File from: {os.path.abspath(args.config)}")
    if policies.get(PBASE_NAME) or args.pbase: print(f"Using Pbase Policy from: {os.path.abspath(args.pbase) if args.pbase and os.path.exists(args.pbase) else args.pbase}")
    if policies.get(PSESSION_NAME) or args.psession: print(f"Using Psession Policy from: {os.path.abspath(args.psession) if args.psession and os.path.exists(args.psession) else args.psession}")
    if policies.get(PSENSITIVE_NAME) or args.psensitive: print(f"Using Psensitive Policy from: {os.path.abspath(args.psensitive) if args.psensitive and os.path.exists(args.psensitive) else args.psensitive}")
    if args.target_pool:
        print(f"Targeting analysis for Cognito Pool ID: {args.target_pool}")

    try:
        # --- MODIFICATION START: Passing the new flag ---
        detected_risks = check_vulnerabilities(
            aws_config, 
            policies, 
            checks_to_run, 
            target_pool_id=args.target_pool,
            check_condition=args.check_condition
        )
        # --- MODIFICATION END ---
        
        print("\n\n--- Vulnerability Report Summary ---")
        if not detected_risks:
            print("No security risks detected based on the selected checks and criteria.")
        else:
            print(f"Total risks detected: {len(detected_risks)}\n")
            for i, risk_info in enumerate(detected_risks, 1):
                print(f"Risk #{i}:")
                print(f"  Risk Type        : {risk_info.get('Risk Type', 'N/A')}")
                print(f"  Cognito Pool ID  : {risk_info.get('Cognito Pool ID', 'N/A')}")
                print(f"  Involved Role ARN: {risk_info.get('Involved Role ARN', 'N/A')}")
                print(f"  Details          : {risk_info.get('Details', 'N/A')}")
                if i < len(detected_risks):
                    print("-" * 40)
        print("\n--- End of Report ---")

    except Exception as e:
        print(f"An unhandled error occurred during vulnerability checking: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main_logic()