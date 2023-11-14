#!/usr/bin/env python3

import os
import logging

from dataclasses import dataclass

from xliic_sdk.helpers import get_binary_path, execute
from xliic_sdk.vendors import github_running_configuration, display_header, upload_sarif

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
    upload_to_code_scanning: bool = False
    api_definition: str = None
    api_credential: str = None

    sarif_report: str = None

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
    data_enrich: {self.data_enrich}
    upload_to_code_scanning: {self.upload_to_code_scanning}
    api_definition: {self.api_definition}
    api_credential: {self.api_credential}
    sarif_report: {self.sarif_report}
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
            upload_to_code_scanning=config["upload-to-code-scanning"],
            sarif_report=config["sarif-report"],
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


def scan_run(running_config: RunningConfiguration, binaries: str):
    base_dir = os.getcwd()

    logger.debug("Executing scan_run with those parameters:")
    logger.debug(running_config)

    # Create output file name for report from input file name
    scan_output_report = f"{running_config.api_definition}.audit-report.json"

    ## Is debug mode enabled?
    logger.debug("Running in debug mode, will display all commands output")

    ## Exist the api-definition file?
    if not os.path.exists(running_config.api_definition):
        msg = f"   API definition file not found: {running_config.api_definition}"
    else:
        msg = f"   API definition file found: {running_config.api_definition}"

    logger.debug(msg)

    #
    # Run 42Crunch cli scan
    #
    scan_cmd = [
        "42ctl",
        "scan",
        "run",
        "local",
        "-b", binaries,
        "-i", os.path.join(base_dir, running_config.api_definition),
        "-r", scan_output_report,
        "-a", running_config.api_credential,
        "-t", running_config.target_url,
        "--github-user", running_config.github_repository_owner,
        "--github-org", running_config.github_organization,
        "--log-level", running_config.log_level
    ]

    logger.debug("Executing scan command:")
    logger.debug(scan_cmd)

    try:
        execute(scan_cmd)
    except ExecutionError as e:
        display_header("Audit command failed", str(e))
        exit(1)

    #
    # Convert to SARIF
    #

    # Related OpenAPI file.
    #
    # IMPORTANT: FOR GitHub Code Scanning, the OpenAPI file must be relative to the repository root,
    # and can't start with: /github/workspace

    if running_config.sarif_report:
        sarif_report = running_config.sarif_report
    else:
        sarif_report = os.path.join(base_dir, f"{running_config.api_definition}.sarif")

    cmd = [
        "42ctl",
        "scan",
        "report",
        "sarif",
        "convert",
        "-r", scan_output_report,
        "-a", running_config.api_definition,
        "-o", sarif_report
    ]

    logger.debug("Executing convert to SARIF command:")
    logger.debug(cmd)

    try:
        execute(cmd)
    except ExecutionError as e:
        display_header("Convert to SARIF command failed", str(e))
        return

    #
    # Upload to GitHub code scanning
    #
    if running_config.upload_to_code_scanning:
        upload_sarif(
            github_token=running_config.github_token,
            github_repository=running_config.github_repository,
            github_sha=running_config.github_sha,
            ref=running_config.github_ref,
            sarif_file_path=sarif_report
        )


def main():
    try:
        binary_path = get_binary_path()
    except ExecutionError as e:
        logger.error(display_header("Unable to get 42c-ast binary", str(e)))
        exit(1)

    try:
        running_config = RunningConfiguration.from_github()
    except ValueError as e:
        logger.error(display_header("Invalid configuration", str(e)))
        exit(1)

    # Currently, only two log levels are supported: INFO and DEBUG
    if running_config.log_level == "debug":
        logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    logger.debug("Starting 42Crunch CLI scan in debug mode")

    # Run discovery
    scan_run(running_config, binary_path)


# Main script execution
if __name__ == "__main__":
    main()
