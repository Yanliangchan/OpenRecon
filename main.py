#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import signal
import requests
import pandas as pd
import csv
from json import loads as json_loads

from colorama import init
from argparse import ArgumentParser, RawDescriptionHelpFormatter

from subprocess import run, PIPE

from sherlock.sherlock_project.__init__ import (
    __longname__,
    __shortname__,
    __version__,
    forge_api_latest_release,
)

from sherlock.sherlock_project.sherlock import (
    sherlock,
    QueryNotifyPrint,
    QueryStatus,
    SitesInformation,
    timeout_check,
    check_for_parameter,
    handler,
    multiple_usernames,
)

from holehe.holehe_project.__init__ import (
    __longname__,
    __shortname__,
    __version__,
    forge_api_latest_release,
)

def init_argparse() -> ArgumentParser:
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=f"{__longname__} (Version {__version__})",
    )

    parser.add_argument("--file",
                        "-f",
                        metavar="FILE",
                        dest="file",
                        default=None,
                        help="CSV file containing user details",
                        required=True)

    return parser

def run_holehe(email: str) -> str:
    """
    Run Holehe on the given email and return the output as a string.
    """
    try:
        result = run(
            ["holehe", email],
            stdout=PIPE,
            stderr=PIPE,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error running Holehe for {email}:\n{result.stderr}"
    except FileNotFoundError:
        return "Holehe is not installed or not found in PATH."
    except Exception as e:
        return f"An unexpected error occurred while running Holehe: {e}"

def query_spiderfoot(api_url: str, target: str, non_api_modules: list) -> dict:
    """
    Query SpiderFoot API using only non-API modules for the given target.
    """
    try:
        # Start a new scan with non-API modules
        response = requests.post(
            f"{api_url}/scan/new",
            json={
                "target": target,
                "modules": ",".join(non_api_modules),  # Specify non-API modules
                "usecase": "Passive",
            },
        )

        if response.status_code == 200:
            scan_id = response.json().get("scan_id")
            print(f"SpiderFoot scan initiated with Scan ID: {scan_id}")

            # Poll for results (simplified for demonstration purposes)
            result_response = requests.get(
                f"{api_url}/scan/{scan_id}/results"
            )
            if result_response.status_code == 200:
                return result_response.json()
            else:
                return {"error": f"Failed to fetch results: {result_response.text}"}
        else:
            return {"error": f"Failed to start scan: {response.text}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred while querying SpiderFoot: {e}"}
    
def main():
    parser = init_argparse()
    args = parser.parse_args()

    # If the user presses CTRL-C, exit gracefully without throwing errors
    signal.signal(signal.SIGINT, handler)

    CSV = args.file
    spiderfoot_url = "http://127.0.0.1:5001"  # Local SpiderFoot instance
    
    # List of non-API modules
    non_api_modules = [
        "sfp_dnsresolve",
        "sfp_dns",
        "sfp_httpheaders",
        "sfp_robots",
        "sfp_htmlmeta",
        "sfp_crt",
        "sfp_geoip",
        "sfp_ports",
    ]

    # Read the CSV file
    df = pd.read_csv(CSV)

    # Create object with all information about sites we are aware of.
    try:
        sites = SitesInformation(
            os.path.join(os.path.dirname(__file__),
                         "sherlock/sherlock_project/resources/data.json"))
    except Exception as error:
        print(f"ERROR:  {error}")
        sys.exit(1)

    site_data_all = {site.name: site.information for site in sites}

    # Create notify object for query results.
    query_notify = QueryNotifyPrint(result=None,
                                    verbose=False,
                                    print_all=False,
                                    browse=False)

    # Prepare output data for consolidated CSV
    consolidated_data = []
    
    # Run report on all specified users.
    for index, row in df.iterrows():
        first_name = row['First Name']
        last_name = row['Last Name']
        email = row['Email']
        username = row['Alt']
        print(f"Processing: {first_name} {last_name} ({email})")

        row_data = {"Name": f"{first_name} {last_name}"}

        # Sherlock Username Search
        print("Running Sherlock...")
        sherlock_results = sherlock(
            username,
            site_data_all,
            query_notify,
            tor=False,
            unique_tor=False,
            dump_response=False,
            proxy=None,
            timeout=60,
        )
        sherlock_finds = [site.name for site, result in sherlock_results.items() if result.status == QueryStatus.CLAIMED]
        row_data["Sherlock"] = ", ".join(sherlock_finds)

        # Holehe Email Search
        print("Running Holehe...")
        holehe_results = run_holehe(email)
        row_data["Holehe"] = holehe_results.replace("\n", ", ")  # Flatten Holehe results

        # SpiderFoot Target Search
        print("Running SpiderFoot...")
        spiderfoot_results = query_spiderfoot(spiderfoot_url, email, non_api_modules)
        if "error" in spiderfoot_results:
            print(f"SpiderFoot Error: {spiderfoot_results['error']}")
            row_data["SpiderFoot"] = spiderfoot_results["error"]
        else:
            # Extract SpiderFoot findings
            spiderfoot_finds = [result["data"] for result in spiderfoot_results.get("events", [])]
            row_data["SpiderFoot"] = ", ".join(spiderfoot_finds)

        # Append data for this row
        consolidated_data.append(row_data)

    # Save consolidated data to CSV
    output_csv = "consolidated_results.csv"
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Name", "Sherlock", "Holehe", "SpiderFoot"])
        writer.writeheader()
        writer.writerows(consolidated_data)

    print(f"Consolidated results saved to {output_csv}")
        
        
if __name__ == "__main__":
    main()
