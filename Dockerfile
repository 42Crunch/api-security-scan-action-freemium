FROM cr0hn/sample-an-testing-for-documentation:v1.0.0

#
# Specific instructions for GitHub
#
COPY ./entrypoint_github_actions_scan.py /entrypoint-github-actions-scan
RUN chmod +x /entrypoint-*

WORKDIR /github/workspace
ENTRYPOINT ["/entrypoint-github-actions-scan"]