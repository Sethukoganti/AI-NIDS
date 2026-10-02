# AI-NIDS Upgrade Implementation Plan

PHASE 1: FIX ARCHITECTURAL GAPS (backend + frontend navigation + RBAC surface)
- Add global status bar to AppShell + top-level status area
- Add notification center page + route
- Add admin-only pages (NetworkControl, SystemHealth, AuditLogs, Users, ResponseCenter, Settings expanded)
- Fix App routes (add /network, /users, /audit, /notifications, /system-health, /investigations, /alerts, /response, /assistant as standalone)
- Enforce role-based Sidebar / navigation (Admin sees all, Analyst sees only allowed)
- Add request-level permissions checks in frontend (useAuth + role gating)

PHASE 2: ADMIN CONTROL CENTER (expose existing admin APIs)
- Build AdminOverview dashboard using /api/admin/settings, /api/admin/network/status, /api/admin/system/health
- Build NetworkControlCenter page using /api/admin/network/status, /network/status/history, /network/status/evaluate, /network/config
- Build UserManagement page using /api/admin/users, /api/admin/roles
- Build Settings center (sections: Network, Detection, Alerts, Model, Dataset, Notifications, Users, Security, Data Retention, System, Audit Logs) using /api/admin/settings and /api/admin/settings/{scope}
- Build SystemHealth page using /api/admin/system/health
- Build AuditLogs page using /api/admin/audit-logs
- Build ResponseCenter (Admin + Analyst) with recommendation vs executed distinction
- Add dataset admin delete / manage using /api/admin/datasets
- Add model deploy / manage using /api/admin/model/deploy

PHASE 3: ANALYST WORKFLOW IMPROVEMENTS
- Improve Dashboard (separate Admin vs Analyst views with permission-filtered metrics)
- Improve Detections page (flagged flows vs alert queue clearly separated)
- Improve Investigations page (investigation workspace with notes, resolution)
- Improve TrafficAnalyzer (clear 6-step workflow, progress indicators, error explanations)
- Improve AI Assistant (streaming, evidence references, permission-aware, suggested questions per page)

PHASE 4: DATA CONSISTENCY, ERROR HANDLING, LOADING, SECURITY
- Ensure all API responses come from real DB (no fabricated counts)
- Fix any missing 401/403 handling
- Ensure network status is derived from real indicators (not random)
- Ensure risk calculation uses real attack class + confidence + port
- Ensure audit logs record every sensitive change
- Ensure AI assistant filters admin-only context
- Add skeleton/loading states where missing
- Fix any broken routes (predictions vs detections, insights vs model, etc.)

PHASE 5: DOCUMENTATION + TESTING
- Update README with final architecture, roles, API map
- Ensure database tables exist (users, roles, datasets, predictions, alerts, investigations, audit_logs, network_status, network_status_history, network_configuration, detection_configuration, alert_configuration, model_versions, notifications, system_configuration)
- Add basic RBAC tests (analyst -> 403 on admin endpoint; admin -> allowed)
