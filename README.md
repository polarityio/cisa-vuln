# Polarity DHS CISA Known Exploited Vulnerabilities Integration

The Polarity - DHS CISA Known Exploited Vulnerabilities Integration returns information on vulnerabilities (CVEs) that have been identified by CISA as meeting the following criteria:

1. The vulnerability has an assigned Common Vulnerabilities and Exposures (CVE) ID.
2. There is reliable evidence that the vulnerability has been actively exploited in the wild.
3. There is a clear remediation action for the vulnerability, such as a vendor provided update.

The integration requires network access to the CISA Known Vulnerability List available here: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The integration will automatically refresh the list every night at midnight server time. For example, for a server set to use UTC (oftentimes the default),
the integration will update the CISA Known Vulnerability List at 00:00 UTC which would be 20:00 EST, or 17:00 PST.  The list loading process takes several seconds to complete.  If a user runs a search while the integration is reloading data, the user will receive a message asking them to retry their search in a few minutes.

The list is also reloaded any time the integration is restarted after the first search is run.

To learn more about the DHS CISA Known Exploited Vulnerabilities, please visit https://www.cisa.gov/known-exploited-vulnerabilities

Check out the integration below:

<img src="images/overlay.png" width="50%">


## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
