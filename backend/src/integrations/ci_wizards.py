"""CI setup wizards — catalog metadata for YAML-generator integrations.

Each wizard maps to a frontend setup flow under /integrations/<slug>.
The kernel knows them as `BaseWizard` subclasses so the catalog endpoint
surfaces them alongside senders and ingesters."""
from __future__ import annotations

from src.connectors.base import BaseWizard, TestResult
from src.connectors.registry import register_connector


@register_connector
class GitHubActionWizard(BaseWizard):
    id = "github-action"
    name = "GitHub Action"
    category = "ci"
    description = "Trigger scans on push and pull request from GitHub Actions"
    version = "v1.0"
    status = "stable"
    icon_slug = "github"

    def test(self) -> TestResult:
        return TestResult(ok=True)


@register_connector
class GitLabComponentWizard(BaseWizard):
    id = "gitlab-component"
    name = "GitLab CI Component"
    category = "ci"
    description = "Trigger scans on push and merge request from GitLab CI"
    version = "v0.2.5"
    status = "beta"
    icon_slug = "gitlab"

    def test(self) -> TestResult:
        return TestResult(ok=True)


@register_connector
class BitbucketPipeWizard(BaseWizard):
    id = "bitbucket-pipe"
    name = "Bitbucket Pipe"
    category = "ci"
    description = "Trigger scans on push and pull request from Bitbucket Pipelines"
    version = "v0.2.5"
    status = "beta"
    icon_slug = "bitbucket"

    def test(self) -> TestResult:
        return TestResult(ok=True)


@register_connector
class AzureDevOpsTaskWizard(BaseWizard):
    id = "azure-devops-task"
    name = "Azure DevOps Task"
    category = "ci"
    description = "Trigger scans on PR and build from Azure Pipelines"
    version = "v0.2.5"
    status = "beta"
    icon_slug = "azuredevops"

    def test(self) -> TestResult:
        return TestResult(ok=True)


@register_connector
class JenkinsLibraryWizard(BaseWizard):
    id = "jenkins-shared-library"
    name = "Jenkins Shared Library"
    category = "ci"
    description = "Trigger scans from your Jenkins pipeline"
    version = "v0.2.5"
    status = "beta"
    icon_slug = "jenkins"

    def test(self) -> TestResult:
        return TestResult(ok=True)
