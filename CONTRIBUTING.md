# Contributing to Probable-Octo-Palm-Tree

Thank you for your interest in contributing to this project.

We welcome contributions that improve the platform, fix bugs, enhance security, optimize performance, improve UI/UX, or expand documentation.

Please read these guidelines carefully before contributing.

---

# Table of Contents

- Introduction
- Project Architecture
- Development Setup
- Contribution Workflow
- Branch Naming Rules
- Commit Message Standards
- Coding Standards
- Pull Request Guidelines
- Testing Requirements
- Documentation Rules
- Security Policy
- Reporting Issues
- Contributor Expectations

---

# Introduction

This project is built as a modular cybersecurity and telemetry monitoring platform consisting of:

- AI Engine
- Attribution Engine
- Backend API
- Browser Extension
- Dashboard
- Local Agent

Contributors are expected to maintain modularity, readability, scalability, and security throughout all contributions.

---

# Project Architecture

```plaintext
Probable-Octo-Palm-Tree/
│
├── ai-engine/              # AI analysis and threat intelligence
├── attribution-engine/     # Threat attribution logic
├── backend-api/            # API services and backend logic
├── browser-extension/      # Browser telemetry extension
├── dashboard/              # Frontend monitoring dashboard
├── local-agent/            # Local system telemetry agent
│
├── README.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── UPDATE_LOG.md
├── start.sh
├── start.bat
└── start_all.py
```

---

# Development Setup

## 1. Fork the Repository

Create your own fork of the project repository.

---

## 2. Clone the Repository

```bash
git clone https://github.com/your-username/Probable-Octo-Palm-Tree.git
cd Probable-Octo-Palm-Tree
```

---

## 3. Create a Virtual Environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 4. Install Dependencies

### Python Dependencies

```bash
pip install -r requirements.txt
```

### Frontend Dependencies

```bash
npm install
```

---

# Contribution Workflow

## Step 1 — Sync Latest Changes

```bash
git pull origin main
```

---

## Step 2 — Create a New Branch

Never commit directly to `main`.

### Feature Branch Example

```bash
git checkout -b feature/live-threat-detection
```

### Bug Fix Branch Example

```bash
git checkout -b fix/extension-async-bug
```

---

## Step 3 — Make Changes

Keep changes:
- Modular
- Focused
- Well documented
- Cleanly structured

Avoid unrelated modifications in a single PR.

---

## Step 4 — Test Your Changes

Ensure:
- No console errors
- APIs function correctly
- Extension communication works
- Dashboard updates properly
- Local agent telemetry is operational

---

## Step 5 — Commit Changes

Use meaningful commit messages.

### Examples

```bash
feat(api): add realtime telemetry endpoint
fix(extension): resolve async download scan issue
docs(readme): update installation steps
refactor(dashboard): improve state management
```

---

## Step 6 — Push Your Branch

```bash
git push origin your-branch-name
```

---

## Step 7 — Open a Pull Request

Include:
- Clear description
- Screenshots (if UI related)
- Testing summary
- Known limitations (if any)

---

# Branch Naming Rules

| Type | Format |
|---|---|
| Feature | `feature/feature-name` |
| Bug Fix | `fix/issue-name` |
| Documentation | `docs/update-name` |
| Refactor | `refactor/module-name` |
| Testing | `test/component-name` |

---

# Commit Message Standards

Follow this structure:

```plaintext
type(scope): short description
```

## Allowed Types

| Type | Purpose |
|---|---|
| feat | New feature |
| fix | Bug fix |
| docs | Documentation |
| style | Formatting |
| refactor | Code restructuring |
| test | Testing updates |
| chore | Maintenance |

---

# Coding Standards

## General Guidelines

- Write readable code
- Use meaningful variable names
- Avoid duplicated logic
- Keep functions modular
- Comment complex logic only when necessary
- Follow existing project architecture

---

## Frontend Standards

- Separate UI and logic
- Avoid inline scripts/styles
- Keep components modular
- Maintain responsive layouts

---

## Backend Standards

- Use modular APIs
- Validate all inputs
- Handle exceptions properly
- Avoid hardcoded credentials

---

## Security Standards

Contributors must:
- Never commit secrets or API keys
- Never expose sensitive telemetry
- Validate external inputs
- Follow secure coding practices

---

# Pull Request Guidelines

A pull request may be rejected if it:
- Breaks functionality
- Introduces security risks
- Contains unrelated changes
- Does not follow project standards
- Lacks testing

---

# Testing Requirements

Before submitting:

## Backend

```bash
pytest
```

## Frontend

```bash
npm test
```

## Manual Validation

Verify:
- Live telemetry works
- Dashboard updates correctly
- Browser extension communication functions
- APIs respond correctly
- No major console errors exist

---

# Documentation Rules

Update documentation whenever changes affect:
- APIs
- Setup process
- Environment variables
- Architecture
- User workflows
- Commands or scripts

Good documentation is part of the contribution.

---

# Security Policy

If you discover a vulnerability:

- Do NOT open a public issue
- Contact maintainers privately
- Provide detailed reproduction steps
- Allow maintainers time for responsible disclosure

---

# Reporting Issues

When opening issues, include:

- Operating system
- Browser version
- Steps to reproduce
- Expected behavior
- Actual behavior
- Logs/screenshots if applicable

---

# Contributor Expectations

Contributors are expected to:
- Maintain professional communication
- Respect project structure
- Keep commits clean
- Write maintainable code
- Prioritize stability and security

Quality contributions are valued more than quantity.

---

# Final Note

Thank you for contributing to Probable-Octo-Palm-Tree.

Your contributions help improve the project's reliability, scalability, and future development.
