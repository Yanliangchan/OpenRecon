"""
Holehe Module

This module contains the main logic to search for user account information
using email addresses across various websites and services.

"""

# This variable is only used to check for ImportErrors induced by users running as script rather than as a module or package
import_error_test_var = None

__shortname__   = "Holehe"
__longname__    = "Holehe: Investigate Email Addresses Across Websites"
__version__     = "1.0.0"

forge_api_latest_release = "https://api.github.com/repos/megadose/holehe/master"
