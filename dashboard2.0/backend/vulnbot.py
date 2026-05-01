"""VulnBot service for dashboard chatbot interactions."""

import json
import time
from typing import Any, Dict, List, Optional

import requests

from config import Config


class VulnBotService:
    """Build context from scans/remediation data and answer chatbot questions."""

    def __init__(self, db, nessus_connector):
        self.db = db
        self.nessus = nessus_connector

    def ask(self, question: str, ui_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Answer a chatbot question using DB context + optional LLM."""
        ui_context = ui_context or {}
        question = (question or "").strip()

        local_context = self._build_local_context(question, ui_context)
        live_context = self._build_live_nessus_context() if Config.VULNBOT_INCLUDE_LIVE_NESSUS else {}

        llm_answer = None
        try:
            llm_answer = self._call_llm(question, local_context, live_context, ui_context)
        except Exception:
            pass

        if llm_answer:
            return {
                "answer": llm_answer.strip(),
                "mode": "llm",
                "provider": Config.VULNBOT_LLM_PROVIDER or "none",
                "context_summary": self._summarize_context(local_context, live_context),
            }

        return {
            "answer": self._fallback_answer(question, local_context, ui_context),
            "mode": "fallback",
            "provider": "rules",
            "context_summary": self._summarize_context(local_context, live_context),
        }

    def _build_local_context(self, question: str, ui_context: Dict[str, Any]) -> Dict[str, Any]:
        stats = self.db.get_stats()

        conn = self.db.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, name, severity, host, port, description, solution, status
            FROM vulnerabilities
            WHERE status = 'open'
            ORDER BY CASE severity
                        WHEN 'Critical' THEN 0
                        WHEN 'High' THEN 1
                        WHEN 'Medium' THEN 2
                        WHEN 'Low' THEN 3
                        ELSE 4
                    END,
                    id DESC
            LIMIT ?
            """,
            (Config.VULNBOT_MAX_CONTEXT_VULNS,),
        )
        open_vulns = [self._map_vuln_row(row) for row in cursor.fetchall()]

        cursor.execute(
            """
            SELECT id, name, severity, host, port, description, solution, status
            FROM vulnerabilities
            WHERE status = 'open' AND severity = 'Critical'
            ORDER BY id DESC
            LIMIT 10
            """
        )
        critical_vulns = [self._map_vuln_row(row) for row in cursor.fetchall()]

        cursor.execute(
            """
            SELECT rc.id, v.id, v.name, v.host, v.port, rc.status, rc.started_at, rc.completed_at, rc.verification_status
            FROM remediation_cases rc
            JOIN vulnerabilities v ON rc.vulnerability_id = v.id
            ORDER BY rc.started_at DESC
            LIMIT 12
            """
        )
        recent_cases = [self._map_case_row(row) for row in cursor.fetchall()]

        selected_vuln = self._resolve_selected_vulnerability(cursor, ui_context)

        ms17_like = [
            v for v in open_vulns
            if "ms17-010" in (v["name"] or "").lower()
            or "eternalblue" in (v["name"] or "").lower()
            or "smb" in (v["name"] or "").lower()
        ]

        ms11_like = [
            v for v in open_vulns
            if "ms11-030" in (v["name"] or "").lower()
            or "2509553" in (v["name"] or "").lower()
            or "dns resolution" in (v["name"] or "").lower()
        ]

        conn.close()

        return {
            "question": question,
            "stats": stats,
            "open_vulnerabilities": open_vulns,
            "critical_vulnerabilities": critical_vulns,
            "recent_cases": recent_cases,
            "selected_vulnerability": selected_vuln,
            "ms17_vulnerabilities": ms17_like,
            "ms11_vulnerabilities": ms11_like,
            "ui_context": ui_context,
        }

    def _build_live_nessus_context(self) -> Dict[str, Any]:
        """Optional live context from Nessus API for near real-time awareness."""
        try:
            scans = self.nessus.list_scans() or []
            scans = sorted(scans, key=lambda s: s.get("last_modification_date", 0), reverse=True)
            compact = []
            for scan in scans[:3]:
                compact.append({
                    "id": scan.get("id"),
                    "name": scan.get("name"),
                    "status": scan.get("status"),
                    "folder_id": scan.get("folder_id"),
                    "last_modification_date": scan.get("last_modification_date"),
                })
            return {"recent_scans": compact}
        except Exception:
            return {"recent_scans": []}

    def _call_llm(
        self,
        question: str,
        local_context: Dict[str, Any],
        live_context: Dict[str, Any],
        ui_context: Dict[str, Any],
    ) -> Optional[str]:
        provider = (Config.VULNBOT_LLM_PROVIDER or "").strip().lower()
        api_key = (Config.VULNBOT_LLM_API_KEY or "").strip()
        if not provider or not api_key:
            return None

        system_prompt = (
            "Tu es VulnBot, un assistant IA expert en cybersécurité intégré à un dashboard SOC. "
            "Tu réponds en français à toutes les questions, qu'elles soient liées à la cybersécurité, "
            "aux vulnérabilités du dashboard, à l'informatique, ou à n'importe quel autre sujet. "
            "Quand une question concerne les données du dashboard (vulnérabilités, scans, remédiations), "
            "utilise le contexte JSON fourni pour donner une réponse précise et opérationnelle. "
            "Pour toute autre question, réponds avec tes connaissances générales de façon claire et utile. "
            "Sois concis, direct et professionnel."
        )

        payload_context = {
            "stats": local_context.get("stats", {}),
            "selected_vulnerability": local_context.get("selected_vulnerability"),
            "critical_vulnerabilities": local_context.get("critical_vulnerabilities", [])[:8],
            "recent_cases": local_context.get("recent_cases", [])[:8],
            "nessus_live": live_context.get("recent_scans", [])[:3],
            "ui_context": {k: v for k, v in ui_context.items() if k != "nessus_context_text"},
        }

        # Inject parsed Nessus file context if available
        nessus_text = ui_context.get("nessus_context_text", "")
        nessus_prefix = f"Contexte fichier Nessus uploadé:\n{nessus_text}\n\n" if nessus_text else ""

        user_prompt = (
            f"{nessus_prefix}"
            f"Question utilisateur:\n{question or '(pas de question explicite)'}\n\n"
            f"Contexte dashboard JSON:\n{json.dumps(payload_context, ensure_ascii=False)}"
        )

        try:
            if provider == "anthropic":
                return self._call_anthropic(system_prompt, user_prompt, api_key)
            if provider == "openai":
                return self._call_openai(system_prompt, user_prompt, api_key)
            if provider == "gemini":
                return self._call_gemini(system_prompt, user_prompt, api_key)
        except Exception as e:
            return f"[VulnBot erreur LLM]: {str(e)}"
        return None

    def _call_anthropic(self, system_prompt: str, user_prompt: str, api_key: str) -> Optional[str]:
        model = Config.VULNBOT_LLM_MODEL or "claude-3-5-sonnet-latest"
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 500,
                "temperature": 0.2,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=20,
        )
        if response.status_code >= 300:
            return None
        body = response.json()
        content = body.get("content", [])
        if not content:
            return None
        return content[0].get("text")

    def _call_openai(self, system_prompt: str, user_prompt: str, api_key: str) -> Optional[str]:
        endpoint = (Config.VULNBOT_LLM_ENDPOINT or "https://api.openai.com/v1").rstrip("/")
        primary_model = Config.VULNBOT_LLM_MODEL or "deepseek/deepseek-r1-0528:free"

        # Fallback chain for OpenRouter free models
        models = [primary_model] + [m for m in [
            "google/gemini-2.0-flash-exp:free",
            "google/gemma-3-27b-it:free",
            "mistralai/mistral-7b-instruct:free",
            "deepseek/deepseek-r1:free",
            "meta-llama/llama-3.3-70b-instruct:free",
        ] if m != primary_model]

        for model in models:
            try:
                response = requests.post(
                    f"{endpoint}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "http://localhost:5000",
                        "X-Title": "VulnBot Dashboard",
                    },
                    json={
                        "model": model,
                        "temperature": 0.2,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                    },
                    timeout=60,
                )
                if response.status_code in (429, 503):
                    time.sleep(1)
                    continue  # rate limited, wait and try next model
                if response.status_code in (404, 400):
                    continue  # model not found, try next
                if response.status_code >= 300:
                    continue  # any other error, try next
                body = response.json()
                choices = body.get("choices", [])
                if not choices:
                    continue
                text = ((choices[0].get("message") or {}).get("content") or "").strip()
                if text:
                    return text
            except Exception:
                continue

        return None  # let fallback_answer handle it

    def _call_gemini(self, system_prompt: str, user_prompt: str, api_key: str) -> Optional[str]:
        endpoint = (Config.VULNBOT_LLM_ENDPOINT or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
        model = Config.VULNBOT_LLM_MODEL or "gemini-1.5-pro"
        response = requests.post(
            f"{endpoint}/models/{model}:generateContent?key={api_key}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [
                    {
                        "parts": [
                            {"text": f"{system_prompt}\n\n{user_prompt}"}
                        ]
                    }
                ],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 500},
            },
            timeout=20,
        )
        if response.status_code >= 300:
            return None
        body = response.json()
        candidates = body.get("candidates", [])
        if not candidates:
            return None
        parts = ((candidates[0].get("content") or {}).get("parts") or [])
        texts = [p.get("text", "") for p in parts if p.get("text")]
        return "\n".join(texts).strip() or None

    def _fallback_answer(self, question: str, local_context: Dict[str, Any], ui_context: Dict[str, Any]) -> str:
        question_lower = (question or "").lower()
        stats = local_context.get("stats", {})
        selected = local_context.get("selected_vulnerability")

        # Vulnérabilité cliquée depuis le tableau — répondre directement
        if ui_context.get("source") == "vulnerability-row":
            if selected:
                return self._format_selected_vulnerability_response(selected, question)
            # Fallback: chercher par nom dans la DB
            vuln_name = ui_context.get("selected_vulnerability", {}).get("name", "")
            if vuln_name:
                found = self._search_vuln_in_db(vuln_name)
                if found:
                    return self._format_selected_vulnerability_response(found, question)
                # Même sans DB, expliquer via le nom
                dummy = {"name": vuln_name, "severity": ui_context.get("selected_vulnerability", {}).get("severity", ""),
                         "host": ui_context.get("selected_vulnerability", {}).get("host", ""),
                         "port": ui_context.get("selected_vulnerability", {}).get("port", ""),
                         "description": "", "solution": ""}
                return self._format_selected_vulnerability_response(dummy, question)

        # Recherche par nom dans la question (ex: "explique WS-Management Server Detection")
        vuln_from_question = self._search_vuln_by_name_in_question(question, local_context)
        if vuln_from_question:
            return self._format_selected_vulnerability_response(vuln_from_question, question)

        # Recherche d'un case de remédiation (ex: "case #13", "case 13", "remédiation 13")
        case_from_question = self._search_case_by_id_in_question(question)
        if case_from_question:
            return self._format_case_details(case_from_question)

        if "critique" in question_lower or "critical" in question_lower:
            return self._format_critical_answer(local_context)

        if "ms17-010" in question_lower or "eternalblue" in question_lower or "smb" in question_lower:
            return self._format_signature_vuln_answer(
                local_context.get("ms17_vulnerabilities", []),
                "MS17-010 / EternalBlue",
                [
                    "1) Vérifier l'état SMBv1 sur l'hôte cible.",
                    "2) Désactiver SMBv1 côté serveur et client.",
                    "3) Appliquer les correctifs Microsoft MS17-010 adaptés à l'OS.",
                    "4) Redémarrer les services concernés (ou l'hôte si nécessaire).",
                    "5) Valider par re-scan Nessus et vérification Metasploit.",
                ],
            )

        if "ms11-030" in question_lower or "2509553" in question_lower:
            return self._format_signature_vuln_answer(
                local_context.get("ms11_vulnerabilities", []),
                "MS11-030 / KB2509553",
                [
                    "1) Vérifier la présence de KB2509553 (Get-HotFix).",
                    "2) Installer le correctif manquant via Windows Update / WSUS.",
                    "3) Redémarrer si l'installation l'exige.",
                    "4) Relancer le scan Nessus pour confirmation.",
                ],
            )

        if "historique" in question_lower or "remédiation" in question_lower or "remediation" in question_lower:
            return self._format_history_answer(local_context)

        # Questions sur les classes/sévérités Nessus
        if any(k in question_lower for k in ["classe", "class", "sévérité", "severity", "niveau", "level",
                                              "info", "informational", "critical", "high", "medium", "low",
                                              "cvss", "score", "risque", "risk"]):
            return self._format_severity_explanation(question_lower)

        if selected:
            return self._format_selected_vulnerability_response(selected, question)

        # Question générale
        open_count = stats.get('open_vulnerabilities', 0)
        critical_count = stats.get('critical_vulnerabilities', 0)
        active_count = stats.get('active_remediations', 0)

        return (
            f"Je suis VulnBot, assistant cybersécurité de votre dashboard.\n\n"
            f"État actuel du dashboard :\n"
            f"- {open_count} vulnérabilités ouvertes ({critical_count} critiques)\n"
            f"- {active_count} remédiations actives\n\n"
            f"Cliquez sur n'importe quelle ligne de vulnérabilité pour obtenir une explication détaillée.\n"
            f"Vous pouvez aussi poser des questions comme :\n"
            f"- « Explique WS-Management Server Detection »\n"
            f"- « Quelles sont les vulnérabilités critiques ? »\n"
            f"- « Comment corriger MS17-010 ? »\n"
            f"- « Historique des remédiations »"
        )

    def _search_case_by_id_in_question(self, question: str) -> Optional[Dict[str, Any]]:
        """Extract case ID from question and fetch details from DB."""
        import re
        match = re.search(r'case\s*#?(\d+)', question.lower())
        if not match:
            match = re.search(r'remédiation\s*#?(\d+)', question.lower())
        if not match:
            return None

        case_id = int(match.group(1))
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT rc.id, rc.vulnerability_id, v.name, v.host, v.port, rc.status,
                          rc.started_at, rc.completed_at, rc.agent_output, rc.verification_status
                   FROM remediation_cases rc
                   JOIN vulnerabilities v ON rc.vulnerability_id = v.id
                   WHERE rc.id = ?""",
                (case_id,)
            )
            row = cursor.fetchone()
            conn.close()
            if not row:
                return None
            return {
                "id": row[0],
                "vulnerability_id": row[1],
                "vulnerability_name": row[2],
                "host": row[3],
                "port": row[4],
                "status": row[5],
                "started_at": row[6],
                "completed_at": row[7],
                "agent_output": row[8],
                "verification_status": row[9],
            }
        except Exception:
            return None

    def _format_case_details(self, case: Dict[str, Any]) -> str:
        """Format detailed explanation of a remediation case."""
        case_id = case.get("id")
        vuln_name = case.get("vulnerability_name", "Vulnérabilité inconnue")
        host = case.get("host", "N/A")
        port = case.get("port", "N/A")
        status = case.get("status", "unknown")
        started = case.get("started_at", "N/A")
        completed = case.get("completed_at", "N/A")
        output = case.get("agent_output", "")
        verification = case.get("verification_status", "")

        lines = [
            f"**Case #{case_id} : {vuln_name}**",
            "",
            f"Hôte : {host}  |  Port : {port}",
            f"Statut : {status.upper()}",
            f"Démarré : {started}",
        ]

        if completed:
            lines.append(f"Terminé : {completed}")
        if verification:
            lines.append(f"Vérification : {verification}")

        lines.append("")

        if status == "failed":
            lines.append("**Pourquoi a-t-il échoué ?**")
            failure_reason = self._analyze_failure(output, vuln_name)
            lines.append(failure_reason)
        elif status == "completed":
            lines.append("**Remédiation réussie**")
            lines.append("L'agent a terminé les actions de correction. Vérifiez avec un re-scan Nessus ou Metasploit.")
        elif status == "in_progress" or status == "running":
            lines.append("**En cours d'exécution**")
            lines.append("L'agent travaille actuellement sur cette remédiation. Patientez quelques minutes.")
        else:
            lines.append(f"**Statut : {status}**")

        if output:
            lines.append("")
            lines.append("**Détails de l'agent (extrait) :**")
            lines.append(f"```\n{output[:500]}\n```")

        lines.append("")
        lines.append("💡 **Actions recommandées :**")
        if status == "failed":
            lines.append("- Vérifier les logs complets dans le dashboard")
            lines.append("- Vérifier les credentials WinRM configurés sur le serveur")
            lines.append("- Tester la connectivité réseau vers l'hôte cible")
            lines.append("- Relancer manuellement la remédiation depuis le dashboard")
        elif status == "completed" and not verification:
            lines.append("- Lancer la vérification Metasploit depuis le dashboard")
            lines.append("- Effectuer un re-scan Nessus pour confirmer la correction")

        return "\n".join(lines)

    def _analyze_failure(self, output: str, vuln_name: str) -> str:
        """Analyze agent output to determine failure cause."""
        if not output:
            return ("Aucun log d'erreur disponible. Causes possibles : timeout réseau, "
                    "credentials WinRM invalides, ou erreur interne de l'agent.")

        output_lower = output.lower()

        if "timeout" in output_lower or "timed out" in output_lower:
            return ("⏱️ **Timeout réseau** — L'agent n'a pas pu joindre l'hôte cible dans le délai imparti. "
                    "Vérifiez que l'hôte est accessible depuis le serveur Kali et que WinRM (port 5985) est ouvert.")

        if "authentication" in output_lower or "credential" in output_lower or "unauthorized" in output_lower:
            return ("🔐 **Échec d'authentification** — Les credentials WinRM sont incorrects ou l'utilisateur "
                    "n'a pas les permissions nécessaires. Vérifiez les credentials configurés et les droits admin.")

        if "connection refused" in output_lower or "no route to host" in output_lower:
            return ("🚫 **Connexion refusée** — L'hôte cible refuse la connexion WinRM. "
                    "Vérifiez que le service WinRM est démarré sur l'hôte et que le pare-feu autorise le port 5985.")

        if "permission denied" in output_lower or "access denied" in output_lower:
            return ("🔒 **Permissions insuffisantes** — L'utilisateur WinRM n'a pas les droits pour exécuter "
                    "les commandes de remédiation (désactivation SMB, installation de patch, etc.). "
                    "Utilisez un compte avec privilèges administrateur.")

        if "not found" in output_lower or "does not exist" in output_lower:
            return ("❓ **Ressource introuvable** — Un fichier, service ou clé de registre attendu n'existe pas "
                    "sur l'hôte cible. Cela peut indiquer une version d'OS différente ou une configuration non standard.")

        if "ms17-010" in vuln_name.lower() or "smb" in vuln_name.lower():
            return ("L'agent a tenté de désactiver SMBv1 mais a rencontré une erreur. "
                    "Causes possibles : OS non supporté (Windows XP/2003), clé de registre protégée, "
                    "ou service LanmanServer déjà arrêté.")

        if "ms11-030" in vuln_name.lower() or "2509553" in vuln_name.lower():
            return ("L'agent a tenté d'installer KB2509553 mais a échoué. "
                    "Causes possibles : Windows Update désactivé, patch déjà installé mais non détecté, "
                    "ou incompatibilité avec la version d'OS.")

        return ("Erreur non identifiée. Consultez les logs complets dans le dashboard pour plus de détails. "
                f"Extrait : {output[:200]}")

    def _search_vuln_by_name_in_question(self, question: str, local_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Search for a vulnerability by name mentioned in the question."""
        if not question:
            return None
        q = question.lower()
        # Only trigger on explicit explain/describe keywords
        keywords = ["explique", "explain", "décris", "describe", "qu'est-ce que", "c'est quoi",
                    "what is", "détail", "detail", "analyse", "analyze", "parle de", "info sur",
                    "corriger", "fix", "remediate", "remédier"]
        if not any(k in q for k in keywords):
            return None

        all_vulns = local_context.get("open_vulnerabilities", [])
        best = None
        best_score = 0
        for v in all_vulns:
            name = (v.get("name") or "").lower()
            if not name:
                continue
            # Count matching words
            name_words = set(name.split())
            q_words = set(q.split())
            score = len(name_words & q_words)
            if score > best_score and score >= 2:
                best_score = score
                best = v

        # Also try DB search for broader coverage
        if not best:
            best = self._search_vuln_in_db(question)

        return best

    def _search_vuln_in_db(self, question: str) -> Optional[Dict[str, Any]]:
        """Search vulnerability by partial name match in DB."""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            # Extract meaningful words (>4 chars) from question
            words = [w for w in question.split() if len(w) > 4 and w.isalpha()]
            for word in words[:5]:
                cursor.execute(
                    """SELECT id, name, severity, host, port, description, solution, status
                       FROM vulnerabilities WHERE LOWER(name) LIKE ? LIMIT 1""",
                    (f"%{word.lower()}%",)
                )
                row = cursor.fetchone()
                if row:
                    conn.close()
                    return self._map_vuln_row(row)
            conn.close()
        except Exception:
            pass
        return None

    def _format_selected_vulnerability_response(self, vuln: Dict[str, Any], question: str = "") -> str:
        vuln_name = vuln.get("name") or "Vulnérabilité inconnue"
        host = vuln.get("host") or "hôte inconnu"
        port = vuln.get("port") or "-"
        severity = vuln.get("severity") or "N/A"
        desc = (vuln.get("description") or "").strip()
        solution = (vuln.get("solution") or "").strip()
        case_count = self._count_cases_for_vulnerability(vuln.get("id"))

        # Build rich explanation
        explanation = self._build_vuln_explanation(vuln_name, desc)
        remediation = solution if solution else self._heuristic_solution(vuln_name)
        risk = self._assess_risk(vuln_name, severity)

        lines = [
            f"**{vuln_name}**",
            "",
            f"Sévérité : {severity}  |  Hôte : {host}  |  Port : {port}",
            "",
            "**Qu'est-ce que c'est ?**",
            explanation,
            "",
            "**Risque**",
            risk,
        ]

        if remediation:
            lines += ["", "**Remédiation recommandée**", remediation[:500]]

        if case_count > 0:
            lines += ["", f"📋 {case_count} case(s) de remédiation lié(s) à cette vulnérabilité dans le dashboard."]

        return "\n".join(lines)

    def _build_vuln_explanation(self, name: str, description: str) -> str:
        """Return description from DB if available, otherwise a knowledge-based explanation."""
        if description and len(description) > 30:
            return description[:600] + ("..." if len(description) > 600 else "")

        n = name.lower()

        # Nessus scanner/info plugins
        if "nessus syn scanner" in n or "syn scanner" in n:
            return ("Le plugin **Nessus SYN Scanner** effectue un scan de ports TCP en mode SYN (half-open). "
                    "Il envoie des paquets SYN et analyse les réponses pour identifier les ports ouverts "
                    "sans établir de connexion complète. Ce n'est pas une vulnérabilité — c'est la méthode "
                    "de découverte utilisée par Nessus pour cartographier les services actifs sur l'hôte.")

        if "nessus scan information" in n or "scan information" in n:
            return ("Informations générales sur le scan Nessus : durée, plugins utilisés, configuration. "
                    "Ce n'est pas une vulnérabilité mais un résumé des paramètres du scan.")

        if "dce/rpc" in n or "dce services" in n or "dce service" in n:
            return ("L'énumération DCE/RPC liste les services Windows exposés via le protocole RPC. "
                    "Ces informations permettent à un attaquant d'identifier les services disponibles "
                    "(DCOM, WMI, etc.) et de cibler des exploits spécifiques.")

        if "common platform enumeration" in n or "cpe" in n:
            return ("Common Platform Enumeration (CPE) identifie le système d'exploitation et les logiciels "
                    "installés sur l'hôte. Ces données alimentent la base de vulnérabilités Nessus "
                    "pour détecter les CVE applicables.")

        if "ethernet mac" in n or "mac address" in n:
            return ("Détection de l'adresse MAC de l'interface réseau. Utilisée pour l'inventaire "
                    "et l'identification du fabricant de la carte réseau. Aucun risque direct.")

        if "ethernet card" in n or "card manufacturer" in n:
            return ("Identification du fabricant de la carte réseau via l'adresse MAC (OUI). "
                    "Information de reconnaissance sans risque direct.")

        if "device type" in n:
            return ("Nessus a identifié le type d'équipement (serveur, workstation, switch, etc.) "
                    "via les réponses réseau. Information de reconnaissance utile pour l'inventaire.")

        if "http server type" in n or "http server" in n:
            return ("Détection du type et de la version du serveur HTTP (Apache, IIS, Nginx...). "
                    "Cette information permet à un attaquant de cibler des CVE spécifiques à la version. "
                    "Recommandation : masquer la bannière HTTP (ServerTokens Prod sur Apache, server_tokens off sur Nginx).")

        if "icmp timestamp" in n:
            return ("Les réponses ICMP Timestamp permettent d'estimer l'heure système de l'hôte, "
                    "ce qui peut aider à contourner des mécanismes de sécurité basés sur le temps. "
                    "Recommandation : filtrer les requêtes ICMP Timestamp au niveau du pare-feu.")

        if "smb signing" in n:
            return ("La signature SMB n'est pas requise sur cet hôte. Sans signature obligatoire, "
                    "un attaquant peut réaliser des attaques de type **SMB Relay** pour usurper "
                    "des identités sur le réseau. Recommandation : activer RequireSecuritySignature via GPO.")

        if "ms16-047" in n or "3148527" in n or "badlock" in n:
            return ("MS16-047 (Badlock) est une vulnérabilité dans les protocoles SAM et LSAD de Windows. "
                    "Elle permet à un attaquant positionné en man-in-the-middle d'effectuer des attaques "
                    "de downgrade et d'accéder aux données d'authentification. "
                    "Correction : appliquer le patch KB3148527.")

        if "ms17-010" in n or "eternalblue" in n or "4013389" in n:
            return ("MS17-010 (EternalBlue) est une vulnérabilité critique dans SMBv1 de Windows. "
                    "Elle permet une exécution de code à distance sans authentification. "
                    "Exploitée par WannaCry, NotPetya et de nombreux ransomwares. "
                    "Correction : désactiver SMBv1 et appliquer le patch MS17-010.")

        if "ws-management" in n or "winrm" in n:
            return ("WS-Management (WinRM) est un protocole Microsoft de gestion à distance basé sur SOAP/HTTP. "
                    "Sa détection indique que le service est exposé sur le réseau. "
                    "Bien que légitime pour l'administration, une exposition non contrôlée peut permettre "
                    "l'exécution de commandes à distance si les credentials sont compromis.")

        if "netbios" in n or ("smb" in n and "signing" not in n):
            return ("NetBIOS/SMB est un protocole de partage de fichiers et d'imprimantes Windows. "
                    "Son exposition peut révéler des informations sur le système (nom, domaine, OS) "
                    "et constitue un vecteur d'attaque pour des exploits comme EternalBlue (MS17-010).")

        if "traceroute" in n:
            return ("Traceroute Information indique que l'hôte répond aux paquets TTL expirés, "
                    "permettant la cartographie du réseau. C'est une information de reconnaissance "
                    "utile aux attaquants pour comprendre la topologie réseau.")

        if "tcp/ip timestamp" in n or "tcp timestamp" in n:
            return ("Les timestamps TCP/IP permettent à un attaquant d'estimer l'uptime du système "
                    "et de contourner certains mécanismes de sécurité basés sur le temps. "
                    "Désactiver cette option réduit la surface d'attaque.")

        if "ssl" in n or "tls" in n:
            return ("Une vulnérabilité SSL/TLS indique une faiblesse dans le chiffrement des communications. "
                    "Cela peut permettre des attaques de type man-in-the-middle, déchiffrement de trafic "
                    "ou usurpation d'identité.")

        if "patch" in n or "missing" in n or "update" in n:
            return ("Un correctif de sécurité manquant signifie que le système n'a pas appliqué "
                    "une mise à jour critique publiée par l'éditeur. Ces vulnérabilités sont souvent "
                    "exploitées activement car les exploits sont publics.")

        if "credential" in n or "authentication" in n:
            return ("Une vulnérabilité d'authentification peut permettre un accès non autorisé au système. "
                    "Cela inclut les mots de passe faibles, les mécanismes d'auth défaillants "
                    "ou l'absence de contrôle d'accès.")

        if "detection" in n or "information" in n or "disclosure" in n or "enumeration" in n:
            return ("Cette détection indique une divulgation d'informations sur le système. "
                    "Bien que souvent classée 'Info', elle fournit aux attaquants des données "
                    "précieuses pour cibler des attaques plus précises (OS fingerprinting, version detection).")

        return (f"Vulnérabilité détectée par Nessus : {name}. "
                "Consultez le rapport Nessus complet pour la description détaillée du plugin. "
                "Cette finding nécessite une analyse approfondie selon le contexte de votre environnement.")

    def _assess_risk(self, name: str, severity: str) -> str:
        """Generate a risk assessment based on name and severity."""
        n = name.lower()
        sev = (severity or "").lower()

        if sev == "critical":
            base = "🔴 CRITIQUE — Exploitation active probable. Action immédiate requise."
        elif sev == "high":
            base = "🟠 ÉLEVÉ — Risque significatif d'exploitation. Traitement prioritaire."
        elif sev == "medium":
            base = "🟡 MOYEN — Risque modéré. À corriger dans le cycle de patch normal."
        elif sev == "low":
            base = "🟢 FAIBLE — Impact limité. À corriger lors de la prochaine maintenance."
        else:
            base = "ℹ️ INFO — Donnée de reconnaissance. Utile pour l'inventaire et l'audit."

        if "ws-management" in n or "winrm" in n:
            return base + " Restreindre l'accès WinRM aux seuls hôtes d'administration."
        if "netbios" in n or "smb" in n:
            return base + " Bloquer les ports 137-139/445 sur le périmètre réseau."
        if "traceroute" in n or "timestamp" in n or "detection" in n:
            return base + " Filtrer les réponses ICMP/TCP au niveau du pare-feu."

        return base

    def _format_critical_answer(self, local_context: Dict[str, Any]) -> str:
        criticals = local_context.get("critical_vulnerabilities", [])
        if not criticals:
            return "Aucune vulnérabilité critique ouverte n’a été trouvée dans les données locales."

        lines = ["Vulnérabilités critiques ouvertes (top 8):"]
        for vuln in criticals[:8]:
            lines.append(
                f"- [{vuln.get('id')}] {vuln.get('name')} "
                f"(host: {vuln.get('host') or '-'}, port: {vuln.get('port') or '-'})"
            )
        lines.append("\nTu peux cliquer une ligne pour obtenir le plan de correction détaillé.")
        return "\n".join(lines)

    def _format_signature_vuln_answer(self, vulns: List[Dict[str, Any]], label: str, steps: List[str]) -> str:
        lines = [f"Éléments trouvés pour {label}:"]
        if vulns:
            for vuln in vulns[:6]:
                lines.append(
                    f"- [{vuln.get('severity')}] {vuln.get('name')} "
                    f"(host: {vuln.get('host') or '-'}, port: {vuln.get('port') or '-'})"
                )
        else:
            lines.append("- Aucun élément correspondant n’a été détecté dans les vulnérabilités ouvertes.")

        lines.append("\nÉtapes de remédiation recommandées:")
        lines.extend([f"- {step}" for step in steps])
        return "\n".join(lines)

    def _format_severity_explanation(self, question_lower: str) -> str:
        """Explain Nessus severity classes."""

        if "info" in question_lower and not any(k in question_lower for k in ["critical","high","medium","low"]):
            return (
                "**Classe INFO (Informational) dans Nessus**\n\n"
                "La classe INFO correspond aux findings de niveau 0 dans l'échelle CVSS.\n\n"
                "Ce ne sont pas des vulnérabilités à proprement parler, mais des **informations de reconnaissance** collectées par Nessus :\n"
                "- Détection de services actifs (WinRM, SMB, RDP...)\n"
                "- Identification de l'OS et de la version\n"
                "- Traceroute, timestamps TCP/IP\n"
                "- Informations sur les certificats SSL\n\n"
                "**Risque direct :** Aucun. Mais ces données aident un attaquant à cartographier votre réseau.\n\n"
                "**Action recommandée :** Restreindre les informations exposées (désactiver les bannières, filtrer ICMP) "
                "et utiliser ces données pour l'inventaire de votre surface d'attaque."
            )

        lines = ["**Classes de sévérité Nessus (CVSS)**\n"]
        lines.append("🔴 **Critical (CVSS 9.0–10.0)**")
        lines.append("Exploitation facile, impact maximal. Patch immédiat requis.")
        lines.append("Exemples : EternalBlue (MS17-010), Log4Shell, BlueKeep.\n")

        lines.append("🟠 **High (CVSS 7.0–8.9)**")
        lines.append("Risque élevé, souvent exploitable à distance. Traitement prioritaire.")
        lines.append("Exemples : RCE sans auth, élévation de privilèges.\n")

        lines.append("🟡 **Medium (CVSS 4.0–6.9)**")
        lines.append("Exploitable sous certaines conditions. À corriger dans le cycle de patch normal.")
        lines.append("Exemples : XSS, CSRF, mauvaise configuration SSL.\n")

        lines.append("🟢 **Low (CVSS 0.1–3.9)**")
        lines.append("Impact limité, souvent local. À corriger lors de la prochaine maintenance.")
        lines.append("Exemples : divulgation de version, options HTTP non sécurisées.\n")

        lines.append("ℹ️ **Info (CVSS 0)**")
        lines.append("Pas une vulnérabilité. Données de reconnaissance : services détectés, OS, topologie réseau.")
        lines.append("Utile pour l'inventaire et l'audit de surface d'attaque.")

        return "\n".join(lines)

    def _format_history_answer(self, local_context: Dict[str, Any]) -> str:
        cases = local_context.get("recent_cases", [])
        if not cases:
            return "Aucun historique de remédiation n’est disponible pour le moment."

        lines = ["Historique des remédiations récentes (top 10):"]
        for case in cases[:10]:
            started = case.get("started_at") or "N/A"
            lines.append(
                f"- Case #{case.get('id')} | {case.get('vulnerability_name')} | "
                f"host: {case.get('host') or '-'} | status: {case.get('status')} | start: {started}"
            )
        return "\n".join(lines)

    def _count_cases_for_vulnerability(self, vulnerability_id: Optional[int]) -> int:
        if not vulnerability_id:
            return 0
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM remediation_cases WHERE vulnerability_id = ?",
            (vulnerability_id,),
        )
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def _resolve_selected_vulnerability(self, cursor, ui_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        vuln_id = ui_context.get("vulnerability_id")
        if vuln_id:
            try:
                vuln_id = int(vuln_id)
            except Exception:
                vuln_id = None

        if vuln_id:
            cursor.execute(
                """
                SELECT id, name, severity, host, port, description, solution, status
                FROM vulnerabilities
                WHERE id = ?
                LIMIT 1
                """,
                (vuln_id,),
            )
            row = cursor.fetchone()
            if row:
                return self._map_vuln_row(row)

        selected = ui_context.get("selected_vulnerability")
        if isinstance(selected, dict):
            return {
                "id": selected.get("id"),
                "name": selected.get("name"),
                "severity": selected.get("severity"),
                "host": selected.get("host"),
                "port": selected.get("port"),
                "description": selected.get("description") or "",
                "solution": selected.get("solution") or "",
                "status": selected.get("status") or "open",
            }
        return None

    def _summarize_context(self, local_context: Dict[str, Any], live_context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "open_vulnerabilities": len(local_context.get("open_vulnerabilities", [])),
            "critical_vulnerabilities": len(local_context.get("critical_vulnerabilities", [])),
            "recent_cases": len(local_context.get("recent_cases", [])),
            "live_scans": len(live_context.get("recent_scans", [])) if isinstance(live_context, dict) else 0,
        }

    def _heuristic_solution(self, vuln_name: str) -> str:
        name = (vuln_name or "").lower()
        if "ms17-010" in name or "eternalblue" in name or "smb" in name:
            return (
                "Désactiver SMBv1, appliquer les correctifs MS17-010 correspondants, "
                "puis valider via re-scan Nessus et vérification Metasploit."
            )
        if "ms11-030" in name or "2509553" in name or "dns resolution" in name:
            return (
                "Installer le correctif KB2509553 (MS11-030), redémarrer si nécessaire, "
                "et vérifier via scan de contrôle."
            )
        if "unsupported windows os" in name or "end-of-life" in name:
            return "Planifier la mise à niveau OS et appliquer toutes les mises à jour de sécurité intermédiaires."
        if "brotli" in name:
            return "Mettre à jour la bibliothèque brotli vers une version corrigée puis relancer les services."
        return "Appliquer le correctif recommandé par l’éditeur puis effectuer un re-scan de validation."

    @staticmethod
    def _map_vuln_row(row) -> Dict[str, Any]:
        return {
            "id": row[0],
            "name": row[1],
            "severity": row[2],
            "host": row[3],
            "port": row[4],
            "description": row[5] or "",
            "solution": row[6] or "",
            "status": row[7] or "open",
        }

    @staticmethod
    def _map_case_row(row) -> Dict[str, Any]:
        return {
            "id": row[0],
            "vulnerability_id": row[1],
            "vulnerability_name": row[2],
            "host": row[3],
            "port": row[4],
            "status": row[5],
            "started_at": row[6],
            "completed_at": row[7],
            "verification_status": row[8],
        }
