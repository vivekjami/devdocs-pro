# DevDocs Pro CI/CD Workflows

This directory contains GitHub Action workflows for continuous integration and deployment of DevDocs Pro.

## Workflows

### `ci.yml` - Main Continuous Integration Workflow

- Triggered on pushes to `main` and `develop` branches, and pull requests to `main`
- Runs tests, security validation, and AI integration tests
- Builds release artifacts
- Generates a workflow assessment report

### `security-ci.yml` - Security-Specific CI Workflow

- Focuses on security-specific tests and validations
- May run additional security checks like dependency scanning and SAST

### `validate-workflows.yml` - Workflow Validation

- Validates all GitHub Action workflow files using actionlint
- Ensures workflow files are syntactically correct before they're used

## Environment Variables

The CI workflows use several environment variables for testing:

- `GEMINI_API_KEY`: API key for Google Gemini (test key used in CI, real key should be set as a GitHub secret)
- `JWT_SECRET`, `DEVDOCS_MASTER_KEY`, etc.: Security-related variables for testing
- Other configuration flags like `ENCRYPTION_ENABLED`, `AUTH_ENABLED`, etc.

## Workflow Structure

1. **Test Job**: Runs formatting checks, linting, and all tests
2. **Security Validation**: Validates security-specific features
3. **AI Integration Test**: Tests AI integration features
4. **Workflow Summary**: Generates a summary report of the workflow run

## Adding New Workflows

When adding new workflows:

1. Ensure they follow the same structure and conventions
2. Include appropriate environment variables
3. Add caching for dependencies where possible
4. Update this README with details about the new workflow

## Troubleshooting

If the CI workflow fails:

1. Check the workflow logs for specific error messages
2. Look at the workflow assessment report for a high-level summary
3. Ensure all required directories exist before tests run
4. Verify environment variables are properly configured
