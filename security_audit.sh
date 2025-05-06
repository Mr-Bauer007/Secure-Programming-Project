#!/bin/bash

echo "📦 Generating SBOM using CycloneDX..."
cyclonedx-py environment -o bom.json
echo "✅ SBOM saved to bom.json"

echo "🔍 Checking for vulnerabilities with pip-audit..."
pip-audit -o pip_audit_report.txt -f text
echo "✅ Vulnerability report saved to pip_audit_report.txt"

echo "📂 Generating dependency tree..."
pipdeptree > dependencies.txt
echo "✅ Dependency tree saved to dependencies.txt"

echo "🕵️ Running Bandit security scan..."
bandit -r . -o bandit_report.txt -f txt
echo "✅ Bandit report saved to bandit_report.txt"

echo "🛡️ All security outputs saved."

