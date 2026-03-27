from __future__ import annotations

from typing import Dict, List

TRUST_MATERIALS: List[Dict[str, str]] = [
    {
        "slug": "how-anchor-governs-ai-use",
        "title": "How ANCHOR governs AI use",
        "body": (
            "ANCHOR provides governance, policy control, auditability, and trust surfaces for AI use in veterinary clinics. "
            "It is designed to support safe institutional adoption of AI by making usage visible, governed, and accountable "
            "without turning ANCHOR into a clinical decision-making system."
        ),
    },
    {
        "slug": "what-anchor-stores",
        "title": "What ANCHOR stores — and does not store",
        "body": (
            "ANCHOR uses a metadata-only accountability model. It stores governance and operational metadata such as policy version, "
            "decision type, risk indicators, timestamps, route or mode context, and trust-state signals. "
            "ANCHOR does not store raw prompts or outputs as product doctrine."
        ),
    },
    {
        "slug": "how-governance-receipts-work",
        "title": "How governance receipts work",
        "body": (
            "Governance receipts provide an auditable record of how AI use was governed at the time of a request. "
            "They can include request identifiers, policy version, governance outcome, privacy-related indicators, and decision metadata "
            "without storing the underlying prompt or output content."
        ),
    },
    {
        "slug": "why-metadata-only-accountability-matters",
        "title": "Why metadata-only accountability matters",
        "body": (
            "Metadata-only accountability helps clinics preserve oversight and auditability while reducing exposure associated with "
            "raw prompt and output retention. This supports privacy-aware governance and institution-grade trust without relying on content archives."
        ),
    },
    {
        "slug": "how-learning-supports-safe-adoption",
        "title": "How learning supports safer adoption",
        "body": (
            "ANCHOR Learn connects governance signals to education. When staff encounter governed or higher-friction AI use patterns, "
            "ANCHOR can point them toward explainers, microlearning, and safe-use guidance so adoption improves over time."
        ),
    },
]
