# AEGIS Gateway – Frontend Tier (HMI & Static Assets)

## Overview
The `frontend/` directory contains all user interface templates, stylesheets, client-side JavaScript controllers, and historical revisions for the **Aegis Gateway Human-Machine Interface (HMI)**.

## Directory Structure
- **`templates/`**:
  - `index.html`: Main Industrial SOC and OT Operations HMI dashboard. Includes real-time SVG topology gauges, incident lifecycle steppers, mitigation controls, administrative panels, and audit logs.
  - `login.html`: Administrative login portal with simulated multi-factor authentication (MFA) and educational disclaimers.
  - `attacker.html`: Read-only simulated attacker console for controlled demonstration injections.
- **`static/`**:
  - `css/dashboard.css`: Industrial dark and light theme styles, responsive grid layouts, sticky navigation headers, and modal styling.
  - `js/dashboard.js`: Client-side JavaScript controller consuming `/events` via `EventSource` (Server-Sent Events), updating SVG telemetry charts, managing RBAC role views, and issuing mitigation API calls.
- **`archive/`**:
  - Historical iterative backup files (`.bak*`) preserved from previous development phases.

## Asset Serving & Resolution
The backend Flask application (`backend/aegis_gateway/api.py`) automatically discovers and serves templates and static assets from `frontend/` with fallback support.
