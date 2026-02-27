# TENET AI - Project Roadmap

This roadmap outlines the planned evolution of TENET AI from its current prototype state to a production-ready, open-source security framework.

---

## 📍 Current Status: Phase 1 (Alpha / MVP)
**Focus**: Core detection engine, basic dashboard, and plugin architecture.

- [x] Implementation of Ingest Service (FastAPI)
- [x] Implementation of ML Analyzer (Scikit-learn)
- [x] Adversarial Prompt Detection (Injection, Jailbreak)
- [x] React-based SOC Dashboard for monitoring
- [x] Security-hardened dependency management
- [x] CI/CD boilerplate for automated testing

---

## 🚀 Future Phases

### Phase 1: Enhancement & Stabilization (Q1 2026)
- [ ] **Expanded Threat Library**: Add detection for more complex prompt techniques like "Base64 encoding attacks" and "Translation-based bypasses".
- [ ] **Advanced Heuristics**: Implement more robust pattern matching for common jailbreak templates.
- [ ] **Dashboard Depth**: Add historical trend analysis (7-day, 30-day views) and per-user risk profiling.

### Phase 2: Intelligence & Integration (Q2 2026)
- [ ] **Ensemble Detection**: Combine Scikit-learn with a lightweight transformer-based model (e.g., DistilBERT) for more accurate intent analysis.
- [ ] **Cloud-Native Connectors**: Pre-built integration plugins for AWS Bedrock, Azure OpenAI, and Google Vertex AI.
- [ ] **Audit Trail Storage**: Integrate a persistent database (PostgreSQL) for long-term security auditing and compliance logging.

### Phase 3: Scaling & Community (Q3 2026)
- [ ] **Community Threat Feed**: Allow users to share (anonymized) malicious prompts to update everyone's detection models.
- [ ] **Enterprise Security**: Role-Based Access Control (RBAC) and SSO integration for the SOC Dashboard.
- [ ] **Multi-Model Support**: Specialized detection models for different LLM types (e.g., Code-focused models vs. Chat-focused models).

### Phase 4: Full Protection Ecosystem (Future)
- [ ] **Output Sanitization**: Detect and redact PII or harmful content in LLM responses before they reach the user.
- [ ] **Self-Learning Loop**: Automated re-training of models based on security analyst feedback from the dashboard.
- [ ] **Edge Deployment**: Optimized models for deployment on mobile and IoT edge devices.

---

> [!NOTE]
> This roadmap is a living document and will be updated as the community and project needs evolve.
