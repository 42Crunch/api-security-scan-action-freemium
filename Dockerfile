FROM 42crunch/github-api-security-base-image:v1.1.0

#
# Specific instructions for GitHub
#
COPY ./entrypoint_github_actions_scan.py /entrypoint-github-actions-scan
RUN chmod +x /entrypoint-*

WORKDIR /github/workspace
ENTRYPOINT ["/entrypoint-github-actions-scan"]
