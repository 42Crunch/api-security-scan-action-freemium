#!/usr/bin/env python3

import os
import logging

from dataclasses import dataclass

from xliic_sdk.scan import ScanReport
from xliic_cli.freemium.scan import run_scan_locally, ScanExecutionConfig
from xliic_sdk.vendors import github_running_configuration, upload_sarif
from xliic_cli.scan.reports.sarif.convert_to_sarif import convert_to_sarif
from xliic_cli.scan.reports.pdf.convert_to_pdf import create_pdf_report, RunningConfig as PDFRunningConfig

logger = logging.getLogger(__name__)


class ExecutionError(Exception):
    pass


@dataclass
class RunningConfiguration:
    #
    # Configurable parameters
    #
    target_url: str
    log_level: str = "info"
    data_enrich: bool = False
    api_definition: str = None
    api_credential: str = None
    upload_to_code_scanning: bool = False
    export_as_pdf: str = None

    scan_report: str = None
    sarif_report: str = None

    enforce_sqg: bool = False

    # Internal parameters
    github_token: str = None
    github_repository: str = None
    github_organization: str = None
    github_repository_owner: str = None
    github_ref: str = None
    github_sha: str = None

    def __repr__(self):
        return f"""
RunningConfiguration:
    target_url: {self.target_url}
    log_level: {self.log_level}
    enforce_sqg: {self.enforce_sqg}
    data_enrich: {self.data_enrich}
    export_as_pdf: {self.export_as_pdf}
    upload_to_code_scanning: {self.upload_to_code_scanning}
    api_definition: {self.api_definition}
    api_credential: {self.api_credential}
    sarif_report: {self.sarif_report}
    scan_report: {self.scan_report}
    github_token: {self.github_token}
    github_repository: {self.github_repository}
    github_organization: {self.github_organization}
    github_repository_owner: {self.github_repository_owner}
    github_ref: {self.github_ref}
    github_sha: {self.github_sha}
    """

    @classmethod
    def from_github(cls) -> "RunningConfiguration":

        config = github_running_configuration(
            inputs={
                "upload-to-code-scanning": "bool",
                "token": "str",
                "target-url": "str",
                "api-definition": "str",
                "api-credential": "str",
                "log-level": "str",
                "data-enrich": "bool",
                "sarif-report": "str",
                "scan-report": "str",
                "enforce-sqg": "bool",
                "export-as-pdf": "str"
            },
            envs={
                "github_repository": "str",
                "github_repository_owner": "str",
                "github_ref": "str",
                "github_sha": "str",
            }
        )

        o = cls(
            log_level=config["log-level"],
            data_enrich=config["data-enrich"],
            enforce_sqg=config["enforce-sqg"],
            export_as_pdf=config["export-as-pdf"],
            upload_to_code_scanning=config["upload-to-code-scanning"],
            sarif_report=config["sarif-report"],
            scan_report=config["scan-report"],
            target_url=config["target-url"],
            api_definition=config["api-definition"],
            api_credential=config["api-credential"],

            github_token=config["token"],
            github_repository=config["github_repository"],
            github_organization=config["github_repository_owner"],
            github_repository_owner=config["github_repository_owner"],
            github_ref=config["github_ref"],
            github_sha=config["github_sha"]
        )

        # Ensure log level value is valid
        o.log_level = o.log_level.lower()

        if o.log_level is None:
            o.log_level = "info"
        elif o.log_level not in ["fatal", "error", "warn", "info", "debug"]:
            o.log_level = "info"

        return o


def scan_run(running_config: RunningConfiguration):

    # Create output file name for report from input file name
    if running_config.scan_report:
        scan_output_report = running_config.scan_report
    else:
        scan_output_report = f"{running_config.api_definition}.{os.urandom(10).hex()}.scan-report.json"

    ## Is debug mode enabled?
    logger.debug("Running in debug mode, will display all commands output")

    ## Exist the api-definition file?
    if not os.path.exists(running_config.api_definition):
        print("[!] API definition file not found")
        exit(1)

    logger.debug(f"API definition file found: {running_config.api_definition}")

    #
    # Run 42Crunch cli scan
    #
    scan_config = ScanExecutionConfig(
        target_url=running_config.target_url,
        openapi_file=running_config.api_definition,
        api_credentials=running_config.api_credential,

        enforce_sqg=running_config.enforce_sqg,

        output_format="json",
        output_file=scan_output_report,
        output_overwrite=True,

        enrich=running_config.data_enrich,
        log_level=running_config.log_level,
        github_org=running_config.github_organization,
        github_repository=running_config.github_repository,
        github_user=running_config.github_repository_owner,

        dev_env=True
    )

    try:
        quota_msg, sqg = run_scan_locally(scan_config)
    except Exception as e:
        logger.error(f"[!] {e}")
        exit(1)

    #
    # Convert to SARIF
    #
    if running_config.sarif_report:
        sarif_report = running_config.sarif_report
    else:
        base_dir = os.path.dirname(running_config.api_definition)
        base_name = os.path.splitext(os.path.basename(running_config.api_definition))[0]
        sarif_report = os.path.join(base_dir, f"{base_name}.sarif")

    convert_to_sarif(
        openapi_file_path=running_config.api_definition,
        report_file_path=scan_output_report,
        output_report_path=sarif_report
    )

    #
    # Show scan results
    #
    # We print the results to the console, so that they are visible in the GitHub Actions logs
    report = ScanReport.from_file(scan_output_report)

    ## Global score
    print(f"Scanned {running_config.api_definition} with target URL: {running_config.target_url}")
    print(f"Executed Tests: {report.executed_tests}")
    print(f"Potential Tests: {report.potential_tests}")
    print(f"OWASP TOP 10 Issues found: {report.owasp_top_10_issues}")

    print(f"\nSARIF report was saved to: {sarif_report}")
    print("Successfully uploaded results to Code Scanning\n")

    print(quota_msg)

    #
    # Upload to GitHub code scanning
    #

    if running_config.upload_to_code_scanning:
        logger.debug("Uploading SARIF report to GitHub code scanning")
        upload_sarif(
            github_token=running_config.github_token,
            github_repository=running_config.github_repository,
            github_sha=running_config.github_sha,
            ref=running_config.github_ref,
            sarif_file_path=sarif_report
        )
        logger.debug("Successfully uploaded results to Code Scanning")

    #
    # Make PDF report
    #
    if running_config.export_as_pdf:
        logger.debug(f"Generating PDF report '{running_config.export_as_pdf}'")

        config = PDFRunningConfig(
            scan_file=scan_output_report,
            output_file=running_config.export_as_pdf,
            source="GitHub Actions"
        )

        create_pdf_report(config)

        logger.debug(f"Successfully generated PDF report '{running_config.export_as_pdf}'")

    #
    # Check if pipeline should fail
    #

    ## If SQG is found, fail the pipeline
    if sqg and sqg.has_to_fail(running_config.enforce_sqg):
        print(f"\n[!] The API failed the security quality gate 'Default Audit SQG'\n")
        exit(1)

    #
    # Clean up?
    #

    ## Remove scan report
    if not running_config.scan_report:
        try:
            os.remove(scan_output_report)
        except:
            ...


def main():
    try:
        running_config = RunningConfiguration.from_github()
    except ValueError as e:
        print(f"[!] {e}")
        exit(1)

    # -------------------------------------------------------------------------
    # Setup logging
    # -------------------------------------------------------------------------

    ## Logger handlers for console
    console = logging.StreamHandler()

    if running_config.log_level == "debug":
        logger.setLevel(logging.DEBUG)
        console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    else:
        logger.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(console)

    # -------------------------------------------------------------------------
    # Run scan
    # -------------------------------------------------------------------------

    scan_run(running_config)


# Main script execution
if __name__ == "__main__":
    main()
