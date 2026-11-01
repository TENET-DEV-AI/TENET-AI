name: Copilot Setup Steps

on:
  workflow_dispatch:

jobs:
  copilot-setup-steps:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    timeout-minutes: 30
    steps:
      - name: Checkout repository
        uses: actions/checkout@v5

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Install Python dependencies
        run: |
          python -m pip install --upgrade pip
          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
          if [ -f requirements-dev.txt ]; then pip install -r requirements-dev.txt; fi

      - name: Set up Node.js
        uses: actions/setup-node@v5
        with:
          node-version: "20"

      - name: Install dashboard dependencies
        run: |
          if [ -f dashboard/package-lock.json ]; then
            cd dashboard && npm ci
          fi

      - name: Install landing dependencies
        run: |
          if [ -f landing/package-lock.json ]; then
            cd landing && npm ci
          fi

      - name: Verify core services import
        run: |
          python -m compileall services/ingest/app.py services/analyzer/app.py
