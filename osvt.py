#!/usr/bin/env python
"""
Author: Abdulmalik Banaser 
Email: ab4594@rit.edu 

To run extention: 
> $ osqueryi --nodisable-extensions
> $ SELECT value FROM osquery_flags WHERE name = 'extensions_socket';
> Copy the socket extension path
> $ python3 osvt.py --socket <Value returned above by Osquery>
"""

import osquery
from virus_total_apis import PublicApi as VirusTotalPublicApi
import time 
import os 

@osquery.register_plugin
class VirusTotalPlugin(osquery.TablePlugin):
    """
    A class defntion to create new Osquery table
    """
    def name(self):
        """
        Name attribute for the table.
        """
        return "osvt"

    def columns(self):
        """
        Defining the columns' title in the table
        """
        return [
            osquery.TableColumn(name="path", type=osquery.STRING),
            osquery.TableColumn(name="sha256", type=osquery.STRING),
            osquery.TableColumn(name="virus total detection rate (%)", type=osquery.STRING)
        ]

    def generate(self, context):
        """
        Populate each row in the table
        """
        KEY = "" # Virus Total API key
        vt = VirusTotalPublicApi(KEY) # Create Virus Total object using the API key
        query_data = [] # The resulted data to be added to the table.

        INSTANCE = osquery.SpawnInstance() # Spawn an Osquery instance to populate the table. 
        INSTANCE.open()

        directory = input("[*] Please enter the full path of a directory: ").strip() # User input for the directory. 
        while (os.path.isdir(directory) is False):
            print("[-] Directory does not exists, please try again!")
            directory = input("[*] Please enter the full path of a directory: ").strip()

        RESULTS = INSTANCE.client.query(f"select path, sha256 from hash  where directory = '{directory}'") # Run the pre-defined Osquery command for the given directory.
        
        if RESULTS.status.code != 0: # Check the status code of the result of the query.
            print("[-] Error running the query: %s" % RESULTS.status.message)
        else:
            print("[+] Success running the query: %s" % RESULTS.status.message)
        for qrow in RESULTS.response:
            row = {}
            row["path"] = qrow["path"]
            row["sha256"] = qrow["sha256"]
            response = vt.get_file_report(qrow["sha256"]) # Submit the file hash to Virust Total 
            row["virus total detection rate (%)"] = f"{100 * response['results']['positives'] // response['results']['total']}%" # Compute the percentage of detection
            query_data.append(row)
            time.sleep(15) # Sleep of 15 seconds since the community API for Virus Total only allow 4 queries per minute. 

        return query_data
    

if __name__ == "__main__":
    while True: 
        osquery.start_extension(
            name="osvt",
            version="1.0.0",)