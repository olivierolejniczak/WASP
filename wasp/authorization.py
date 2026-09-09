"""
Authorization form generator — the "lettre d'autorisation" required before any
WASP scan may start (cf. cahier des charges §2 — Cadre légal, bloquant avant
démarrage). Pure templating, deterministic, no LLM call, so it works with
zero model / zero network dependency (lowHardware+AI: this document must be
producible even when Ollama is unreachable).
"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

from wasp.i18n import t
from wasp.mdhtml import md_to_html

_ENGAGEMENT_LABELS = {
    "black-box": {"en": "Black box — no prior information", "fr": "Black box — aucune information préalable"},
    "grey-box":  {"en": "Grey box — limited access (user credentials, partial network map)",
                  "fr": "Grey box — accès limité (identifiants utilisateur, schéma réseau partiel)"},
    "white-box": {"en": "White box — full access (schemas, configs, admin accounts)",
                  "fr": "White box — accès complet (schémas, configs, comptes admin)"},
}

_DEFAULT_TECHNIQUES = [
    "port_scan", "vuln_scan", "web_enum", "ad_enum", "kerberoast",
    "credential_testing", "exploitation", "lateral_movement",
]

_TECHNIQUE_LABELS = {
    "port_scan":          {"en": "TCP/UDP port scanning & service fingerprinting",
                            "fr": "Scan de ports TCP/UDP & fingerprinting de services"},
    "vuln_scan":          {"en": "Authenticated/unauthenticated vulnerability scanning",
                            "fr": "Scan de vulnérabilités authentifié/non-authentifié"},
    "web_enum":           {"en": "Web enumeration (directories, technologies, headers)",
                            "fr": "Énumération web (répertoires, technologies, en-têtes)"},
    "ad_enum":            {"en": "Active Directory enumeration (LDAP, users, groups, GPOs)",
                            "fr": "Énumération Active Directory (LDAP, utilisateurs, groupes, GPO)"},
    "ad_bloodhound":      {"en": "AD attack-path graphing (BloodHound-style collection of ACLs, sessions, group nesting)",
                            "fr": "Cartographie des chemins d'attaque AD (collecte type BloodHound des ACL, sessions, imbrication de groupes)"},
    "kerberoast":         {"en": "Kerberoasting / AS-REP Roasting",
                            "fr": "Kerberoasting / AS-REP Roasting"},
    "credential_testing": {"en": "Authentication attempts on exposed services (restricted list, no lockout)",
                            "fr": "Tentatives d'authentification sur services exposés (liste restreinte, sans lockout)"},
    "exploitation":       {"en": "Exploitation of confirmed vulnerabilities (no data modification/destruction)",
                            "fr": "Exploitation des vulnérabilités confirmées (sans modification/destruction de données)"},
    "lateral_movement":   {"en": "Lateral movement / privilege escalation simulation (no real implant deployment)",
                            "fr": "Mouvement latéral / élévation de privilèges simulés (sans déploiement réel d'implant)"},
}


def render_authorization_form(
    client_name: str,
    target_scope: str,
    engagement_type: str,
    start_date: date,
    end_date: date,
    tester_lead: str,
    client_contact: str,
    emergency_contact: str,
    exclusions: str = "",
    techniques: list[str] | None = None,
    lang: str = "en",
) -> str:
    """Return the signed-authorization letter as Markdown."""
    techniques = techniques or _DEFAULT_TECHNIQUES
    engagement_label = _ENGAGEMENT_LABELS.get(engagement_type, _ENGAGEMENT_LABELS["black-box"]).get(
        lang, _ENGAGEMENT_LABELS["black-box"]["en"])

    if lang == "fr":
        lines = [
            "# Lettre d'autorisation de test d'intrusion",
            "",
            f"**Client :** {client_name}  ",
            f"**Type de mission :** {engagement_label}  ",
            f"**Périmètre autorisé :** `{target_scope}`  ",
            f"**Fenêtre d'intervention :** {start_date.isoformat()} → {end_date.isoformat()}",
            "",
            "## Exclusions explicites du périmètre",
            "",
            exclusions or "_Aucune exclusion déclarée._",
            "",
            "## Techniques autorisées",
            "",
        ]
        for tech in techniques:
            label = _TECHNIQUE_LABELS.get(tech, {}).get("fr", tech)
            lines.append(f"- [x] {label}")
        lines += [
            "",
            "## Limites strictes",
            "",
            "- Aucun déni de service (DoS/DDoS), même partiel",
            "- Aucune modification de données en production",
            "- Aucun chiffrement ou suppression de fichiers",
            "- Arrêt immédiat en cas d'impact non anticipé sur la production",
            "",
            "## Contacts",
            "",
            f"**Chef de mission :** {tester_lead}  ",
            f"**Référent IT client :** {client_contact}  ",
            f"**Astreinte urgence :** {emergency_contact}",
            "",
            "## Attestation",
            "",
            "Le signataire ci-dessous certifie être habilité à autoriser ce test d'intrusion "
            "au nom du client, et accepte les conditions, le périmètre et la fenêtre "
            "d'intervention définis dans ce document.",
            "",
            "| Représentant légal client | ALTICAP GROUP |",
            "|---|---|",
            "| Nom : `______________` | Nom : `______________` |",
            "| Fonction : `______________` | Fonction : `______________` |",
            "| Date : `______________` | Date : `______________` |",
            "| Signature : | Signature : |",
            "",
            f"_Document généré le {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} — "
            "à imprimer et faire signer avant tout démarrage technique._",
        ]
    else:
        lines = [
            "# Penetration Test Authorization Letter",
            "",
            f"**Client:** {client_name}  ",
            f"**Engagement type:** {engagement_label}  ",
            f"**Authorized scope:** `{target_scope}`  ",
            f"**Testing window:** {start_date.isoformat()} → {end_date.isoformat()}",
            "",
            "## Explicit scope exclusions",
            "",
            exclusions or "_No exclusions declared._",
            "",
            "## Authorized techniques",
            "",
        ]
        for tech in techniques:
            label = _TECHNIQUE_LABELS.get(tech, {}).get("en", tech)
            lines.append(f"- [x] {label}")
        lines += [
            "",
            "## Strict limits",
            "",
            "- No denial of service (DoS/DDoS), even partial",
            "- No modification of production data",
            "- No encryption or deletion of files",
            "- Immediate stop if unanticipated production impact occurs",
            "",
            "## Contacts",
            "",
            f"**Engagement lead:** {tester_lead}  ",
            f"**Client IT contact:** {client_contact}  ",
            f"**Emergency escalation:** {emergency_contact}",
            "",
            "## Attestation",
            "",
            "The undersigned certifies they are authorized to approve this penetration test "
            "on behalf of the client, and accepts the conditions, scope, and testing window "
            "defined in this document.",
            "",
            "| Client legal representative | ALTICAP GROUP |",
            "|---|---|",
            "| Name: `______________` | Name: `______________` |",
            "| Title: `______________` | Title: `______________` |",
            "| Date: `______________` | Date: `______________` |",
            "| Signature: | Signature: |",
            "",
            f"_Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} — "
            "print and sign before any technical work starts._",
        ]

    return "\n".join(lines)


def write_authorization_form(
    output_dir: str,
    client_name: str,
    target_scope: str,
    engagement_type: str,
    start_date: date,
    end_date: date,
    tester_lead: str,
    client_contact: str,
    emergency_contact: str,
    exclusions: str = "",
    techniques: list[str] | None = None,
    lang: str = "en",
) -> str:
    """Render and write the authorization form (.md + .html). Returns the .md path."""
    md = render_authorization_form(
        client_name, target_scope, engagement_type, start_date, end_date,
        tester_lead, client_contact, emergency_contact, exclusions, techniques, lang,
    )
    slug = target_scope.replace("://", "-").replace("/", "-").replace(":", "-").strip("-")[:50]
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    title = "Autorisation de test" if lang == "fr" else "Test Authorization"
    out_path = str(Path(output_dir) / f"wasp-authorization-{ts}-{slug}-{lang}.md")
    Path(out_path).write_text(md, encoding="utf-8")
    Path(out_path[:-3] + ".html").write_text(md_to_html(md, title=title), encoding="utf-8")
    return out_path


def _self_check():
    md = render_authorization_form(
        client_name="ACME SA", target_scope="192.168.1.0/24", engagement_type="grey-box",
        start_date=date(2026, 9, 15), end_date=date(2026, 9, 17),
        tester_lead="J. Dupont", client_contact="M. Martin", emergency_contact="+33 6 00 00 00 00",
        lang="fr",
    )
    assert "Lettre d'autorisation" in md
    assert "192.168.1.0/24" in md
    assert "Kerberoasting" in md
    assert "Représentant légal client" in md

    md_en = render_authorization_form(
        client_name="ACME Inc", target_scope="10.0.0.0/24", engagement_type="black-box",
        start_date=date(2026, 9, 15), end_date=date(2026, 9, 17),
        tester_lead="J. Doe", client_contact="M. Smith", emergency_contact="+1 555 0000",
        lang="en",
    )
    assert "Authorization Letter" in md_en
    assert "No denial of service" in md_en


if __name__ == "__main__":
    _self_check()
    print("ok")
