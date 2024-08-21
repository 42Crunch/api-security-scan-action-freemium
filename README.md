# GitHub Action: 42Crunch Dynamic API Security Testing (Freemium)

42Crunch [API Conformance Scan](https://docs.42crunch.com/latest/content/concepts/api_contract_conformance_scan.htm) serves two purposes:

- Testing the resilience and behavior of APIs by automatically generating security tests from the APIs' OpenAPI (formerly Swagger) definition. Scan reproduces the typical behavior of a hacker by injecting bad payloads, bad tokens, and using invalid HTTP verbs and paths. This helps detect vulnerabilities early in the API life cycle, especially those associated with the [OWASP API Security Top 10](https://apisecurity.io/owasp-api-security-top-10/owasp-api-security-top-10-project/).
- Validating that the implementation of the API conforms to its established contract: Scan checks all responses against the OpenAPI definition and detects unexpected responses and data leaks.

APIs which thoroughly enforce compliance to an established contract are far more resilient to all types of attacks.

You can use this action to test an individual API, identified by its OpenAPI definition. You must supply a target URL and a credential to invoke the API.

You can learn more about 42Crunch Scan by watching a 5 minute introduction video [here](https://42crunch.com/free-user-faq/).

![](https://img.shields.io/badge/Warning-orange)  We recommend that you do <u>not</u> target a production system. While the tool does not try to inject malicious payloads, it is possible that the API implementation is not resilient enough to handle the tests and may crash or behave unexpectedly. 

![](https://img.shields.io/badge/Please%20read-red)  You may only use 42Crunch Scan against APIs that you own, but not those of third parties.

## Action inputs

### `api-definition`

Filename of the API to scan, relative to the workspace root, for example `myOAS.json` or `OASFiles/openweather.yaml`

### `api-credential`

The API key or token required to invoke the API hosted at `target-url`. This value can come from a GitHub secret or can be dynamically obtained from a previous pipeline step, as per the example below.

### `target-url`

The URL of the API deployment used by the scan. This URL contains the host **as well as the API basePath**, for example : https://apis.acme.com/apis/v1. It must be accessible from the CI/CD platform. 

### `upload-to-code-scanning`

Upload the scan results in SARIF format to [Github Code Scanning](https://docs.github.com/en/github/finding-security-vulnerabilities-and-errors-in-your-code/about-code-scanning). This assumes you have Github Advanced security enabled. 

Default is `false`.

Note that the workflow must have specific permissions for this step to be successful. 

```YAML
...
jobs:
  run_42c_scan:
    permissions:
      contents: read # for actions/checkout to fetch code
      security-events: write # for results upload to Github Code Scanning
...
```

### `log-level`

Sets the level of details in the logs, one of: `FATAL`, `ERROR`, `WARN`, `INFO`, `DEBUG`. 
Default is `INFO`.

### `data-enrich`

Enriches the OpenAPI file by leveraging the default data dictionary. For each property with a standard format (such as uuid or date-time), patterns and constraints will be added to the OpenAPI file before running the scan.

Default is ` false`.

### `sarif-report`

Converts the raw scan JSON format to SARIF and saves the results into a specified file. 
If not present, the SARIF report is not generated.

### `export-as-pdf`

If set, this action exports a summary of the scan report as a PDF file. If not present, the PDF report is not generated.

### `scan-report`

If set, this action saves the scan report in the specified file in JSON format. If not present, the scan report is not saved.

## Examples

### Individual step example

A typical new step in an existing workflow would look like this:

```yaml
- name: Scan API for vulnerabilities
        uses: 42Crunch/api-security-scan-action-freemium@v1
        with:
            # Upload results to Github Code Scanning
            # Set to false if you don't have Github Advanced Security.
            api-definition: api-specifications/PhotoManager.json
            api-credential: ${{ secrets.PHOTO_API_TOKEN }}
            target-url: ${{ env.TARGET_URL }}
            upload-to-code-scanning: false
            log-level: info
            sarif-report: 42Crunch_ScanReport_${{ github.run_id }}.SARIF
            scan-report: 42Crunch_RawReport_${{ github.run_id }}.json
            export-as-pdf: 42Crunch_ScanReport_${{ github.run_id }}.pdf
```

### Full workflow example

A typical workflow which dynamically invokes an endpoint to obtain a token and then scans the API would look like this:

```yaml
name: "42Crunch API Security Dynamic Scan"

on:
  workflow_dispatch:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]  

env:
    TARGET_URL: "https://apis.acme.test:8090/api"
    # For illustration purposes only, do not store credentials in clear text. 
    # Use Github Secrets instead.
    USER_NAME: "user1@demo.mail"
    USER_PASS: "ball"

jobs:
  run_42c_scan:
    runs-on: ubuntu-latest
    permissions:
     contents: read # for actions/checkout to fetch code
     security-events: write # for results upload to Github Code Scanning
    steps:
      - name: Checkout repo
        uses: actions/checkout@v4
      - name: Set up Python 3.11
        uses: actions/setup-python@v2
        with:
          python-version: 3.11
      - name: Install Python prerequisites
        run: pip install requests
      - name: Get API Token
        id: get_token
        run: |
          login_response=$(python .42c/scripts/api-login.py -u ${{ env.USER_NAME }} -p ${{ env.USER_PASS }} -t ${{ env.TARGET_URL }})
          echo "API_TOKEN=$login_response" >> $GITHUB_OUTPUT
      - name: Scan API for vulnerabilities
        uses: 42Crunch/api-security-scan-action-freemium@v1
        with:
            # Upload results to Github Code Scanning
            # Set to false if you don't have Github Advanced Security.
            upload-to-code-scanning: true
            api-definition: api-specifications/PhotoManager.json
            api-credential: ${{ steps.get_photoapi_token.outputs.API_TOKEN }}
            target-url: ${{ env.TARGET_URL }}
            log-level: info
            sarif-report: 42Crunch_ScanReport_${{ github.run_id }}.SARIF
            scan-report: 42Crunch_RawReport_${{ github.run_id }}.json
            export-as-pdf: 42Crunch_ScanReport_${{ github.run_id }}.pdf
      - name: save-scan-report
        if: always()        
        uses: actions/upload-artifact@v3
        with:
            name: 42Crunch_ScanReport_${{ github.run_id }}
            path: 42Crunch_ScanReport_${{ github.run_id }}.SARIF
            if-no-files-found: error  
```
## Viewing SARIF files in Visual Studio Code

Microsoft provides a [SARIF viewer extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) you can install into Visual Studio Code. Used in conjunction with [42Crunch extension](https://marketplace.visualstudio.com/items?itemName=42Crunch.vscode-openapi), it helps you view issues found by 42Crunch Scan within the OpenAPI file.

The SARIF extension, once connected to GitHub, can directly display the issues from GitHub Code Scanning.

![](./graphics/SARIFinVSCode.png)

## Testing this action

If you want to test this action with a sample API, you can follow the tutorial [here](https://github.com/42crunch/apisecurity-tutorial). This repository contains a sample API and a workflow that will scan it for vulnerabilities. 

## Limitations

The freemium version lets you fully test 42Crunch scan features. It does have usage limitations:

- Organizations on freemium service are limited to 25 scans per repository, with a maximum of three repositories per GitHub organization. The limit is reset every calendar month.
- Only the default security quality gates (SQGs) are included.
- Only the standard data dictionary is included.

## Support

The action is maintained by the 42Crunch ecosystems team. If you run into an issue, or have a question not answered here, you can create a support ticket at [support.42crunch.com](https://support.42crunch.com/) and we will be happy to help.

When reporting an issue, do include:
- The version of the GitHub action
- Relevant logs and error messages
- Steps to reproduce the issue