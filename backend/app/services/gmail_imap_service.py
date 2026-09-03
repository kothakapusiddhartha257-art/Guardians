import asyncio
import imaplib
import email
import hashlib
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from backend.app.core.config import settings
from backend.app.schemas.gateway import EmailMessageRecord
from backend.app.services.pipeline import execute_analysis_dag, INVESTIGATION_CACHE, ACTIVE_CASES_DB
from backend.app.services.email_monitor import email_monitor
from backend.app.services.response_engine import evaluate_policy_and_overrides

logger = logging.getLogger("traceguard.gmail_imap")

# Stateful deduplication registry: maps Message-ID / UID / SHA256 -> Scanned Record
SCANNED_GMAIL_REGISTRY: Dict[str, Dict[str, Any]] = {}
import os
from dotenv import load_dotenv

LATEST_SCAN_SUMMARY: Dict[str, Any] = {
    "total_scanned": 0,
    "high_risk": 0,
    "suspicious": 0,
    "clean": 0,
    "failed": 0,
    "last_scanned_at": None
}


class GmailImapService:
    """Production-grade Gmail IMAP service for real RFC822 forensic ingestion."""

    def __init__(self):
        self._auto_scan_task: Optional[asyncio.Task] = None
        self.auto_scan_enabled: bool = settings.GMAIL_AUTO_SCAN
        self.auto_scan_interval_minutes: int = max(1, settings.GMAIL_AUTO_SCAN_INTERVAL_MINUTES)
        self.is_connected: bool = False

    def is_configured(self) -> bool:
        load_dotenv(override=True)
        pwd = os.getenv("GMAIL_APP_PASSWORD", settings.GMAIL_APP_PASSWORD).strip()
        return bool(pwd and pwd not in ("PASTE_APP_PASSWORD_HERE", "abcdefghijklmnop", ""))

    def _sync_connect_and_login(self) -> imaplib.IMAP4_SSL:
        """Internal synchronous helper to establish SSL IMAP connection."""
        load_dotenv(override=True)
        user = os.getenv("GMAIL_EMAIL", settings.GMAIL_EMAIL).strip()
        pwd = os.getenv("GMAIL_APP_PASSWORD", settings.GMAIL_APP_PASSWORD).strip().replace(" ", "")

        if not pwd or pwd in ("PASTE_APP_PASSWORD_HERE", "abcdefghijklmnop"):
            self.is_connected = False
            raise ValueError("Invalid Google App Password. Please generate a real 16-character App Password at myaccount.google.com/apppasswords and paste it in .env.")

        try:
            client = imaplib.IMAP4_SSL(settings.IMAP_HOST, settings.IMAP_PORT)
            client.login(user, pwd)
            client.select(settings.IMAP_FOLDER, readonly=True)
            self.is_connected = True
            return client
        except imaplib.IMAP4.error as e:
            self.is_connected = False
            err_str = str(e)
            logger.error(f"[Gmail IMAP] Authentication failed for {user}: {e}")
            if "AUTHENTICATIONFAILED" in err_str or "Invalid credentials" in err_str:
                raise PermissionError("Google rejected the password. Please verify that 2-Step Verification is ON and generate an App Password at https://myaccount.google.com/apppasswords.")
            raise PermissionError(f"Unable to authenticate with Gmail: {err_str}")
        except Exception as e:
            self.is_connected = False
            logger.error(f"[Gmail IMAP] Connection error to {settings.IMAP_HOST}:{settings.IMAP_PORT}: {e}")
            raise ConnectionError(f"Failed to connect to Gmail IMAP service: {str(e)}")

    async def test_connection(self) -> Dict[str, Any]:
        """Tests live IMAP connectivity with Gmail."""
        if not self.is_configured():
            return {
                "success": False,
                "email": settings.GMAIL_EMAIL,
                "configured": False,
                "message": "Gmail App Password not configured in backend .env file."
            }

        loop = asyncio.get_event_loop()
        try:
            def _test():
                client = self._sync_connect_and_login()
                status, count_data = client.search(None, "ALL")
                msg_count = len(count_data[0].split()) if status == "OK" and count_data[0] else 0
                try:
                    client.close()
                    client.logout()
                except Exception:
                    pass
                return msg_count

            total_msgs = await loop.run_in_executor(None, _test)
            return {
                "success": True,
                "email": settings.GMAIL_EMAIL,
                "configured": True,
                "folder": settings.IMAP_FOLDER,
                "total_messages_in_mailbox": total_msgs,
                "message": f"Successfully connected to Gmail IMAP ({settings.IMAP_HOST}:{settings.IMAP_PORT}) and accessed {settings.IMAP_FOLDER}."
            }
        except PermissionError as e:
            return {
                "success": False,
                "email": settings.GMAIL_EMAIL,
                "configured": True,
                "message": str(e)
            }
        except Exception as e:
            return {
                "success": False,
                "email": settings.GMAIL_EMAIL,
                "configured": True,
                "message": f"Connection error: {str(e)}"
            }

    async def fetch_and_scan_emails(
        self,
        limit: int = 20,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Retrieves recent emails from Gmail INBOX, preserves complete raw RFC822 bytes,
        deduplicates previously scanned messages, executes the forensic DAG, and stores results.
        """
        if not self.is_configured():
            raise ValueError("Unable to authenticate with Gmail. Check the backend Gmail configuration.")

        loop = asyncio.get_event_loop()

        # Step 1: Retrieve raw messages over IMAP in thread executor
        def _sync_fetch():
            client = self._sync_connect_and_login()
            status, search_data = client.search(None, "ALL")
            if status != "OK" or not search_data or not search_data[0]:
                try:
                    client.close()
                    client.logout()
                except Exception:
                    pass
                return []

            msg_ids = search_data[0].split()
            # Select latest `limit` messages in reverse chronological order (newest first)
            target_ids = msg_ids[-limit:][::-1]
            raw_entries = []

            for mid in target_ids:
                try:
                    # BODY.PEEK[] ensures we do not alter message unread/seen flags on Gmail
                    fetch_status, fetch_data = client.fetch(mid, "(BODY.PEEK[])")
                    if fetch_status != "OK" or not fetch_data:
                        continue

                    raw_bytes = None
                    for part in fetch_data:
                        if isinstance(part, tuple) and len(part) >= 2:
                            raw_bytes = part[1]
                            break

                    if raw_bytes and len(raw_bytes) > 0:
                        raw_entries.append({
                            "imap_id": mid.decode("utf-8", errors="ignore"),
                            "raw_bytes": raw_bytes
                        })
                except Exception as ex:
                    logger.warning(f"[Gmail IMAP] Failed to fetch message ID {mid}: {ex}")

            try:
                client.close()
                client.logout()
            except Exception:
                pass

            return raw_entries

        raw_messages = await loop.run_in_executor(None, _sync_fetch)

        if not raw_messages:
            return {
                "status": "COMPLETE",
                "total_retrieved": 0,
                "summary": {"total": 0, "high_risk": 0, "suspicious": 0, "clean": 0, "failed": 0},
                "results": [],
                "message": "No emails found in mailbox."
            }

        results = []
        failures = []
        total = len(raw_messages)

        # Step 2: Iterate through emails, deduplicate, and run forensic DAG
        for idx, entry in enumerate(raw_messages):
            raw_bytes: bytes = entry["raw_bytes"]
            imap_id = entry["imap_id"]
            sha256 = hashlib.sha256(raw_bytes).hexdigest()

            # Parse metadata fast for deduplication and logging
            msg_obj = email.message_from_bytes(raw_bytes)
            message_id = msg_obj.get("Message-ID", f"imap-{imap_id}-{sha256[:10]}")
            subject = msg_obj.get("Subject", "(No Subject)")
            from_addr = msg_obj.get("From", "Unknown Sender")
            date_str = msg_obj.get("Date", datetime.utcnow().isoformat() + "Z")

            if progress_callback:
                await progress_callback(
                    done=idx,
                    total=total,
                    current_subject=subject,
                    stage="Retrieved raw RFC822 from Gmail IMAP"
                )

            # Check deduplication registry
            dedup_key = message_id.strip("<>") if message_id else sha256
            if dedup_key in SCANNED_GMAIL_REGISTRY:
                cached_rec = SCANNED_GMAIL_REGISTRY[dedup_key]
                results.append(cached_rec)
                if progress_callback:
                    await progress_callback(
                        done=idx + 1,
                        total=total,
                        current_subject=subject,
                        stage="Existing investigation matched (deduplicated)"
                    )
                continue

            try:
                if progress_callback:
                    await progress_callback(
                        done=idx,
                        total=total,
                        current_subject=subject,
                        stage="Running 11-Lens Forensic DAG Pipeline"
                    )

                # Execute existing Phase 1 Forensic DAG
                bundle = await execute_analysis_dag(raw_bytes, actor=f"GMAIL_IMAP_{settings.GMAIL_EMAIL}")

                # Evaluate autonomous policy decisions
                verdict, action_taken, triggered_overrides = evaluate_policy_and_overrides(bundle)

                # Format top triggered signals
                signals = []
                if bundle.risk_score.top_reasons:
                    signals = [r.human_readable for r in bundle.risk_score.top_reasons[:3]]
                elif bundle.header_anomalies:
                    signals = [f"Header anomaly: {a.rule_id} ({a.severity})" for a in bundle.header_anomalies[:3]]
                else:
                    signals = ["Cryptographic verification completed", "Intent classification pattern"]

                claimed_dom = bundle.email.headers_normalized.from_address.domain if bundle.email.headers_normalized.from_address else ""
                actual_dom = bundle.email.headers_normalized.return_path.domain if bundle.email.headers_normalized.return_path else claimed_dom

                rec = {
                    "id": bundle.email.email_id,
                    "email_id": bundle.email.email_id,
                    "case_id": bundle.case_id,
                    "gmail_message_id": imap_id,
                    "message_id": message_id,
                    "sha256": bundle.email.sha256,
                    "subject": bundle.email.headers_normalized.subject or subject,
                    "sender": from_addr,
                    "claimed_domain": claimed_dom,
                    "actual_domain": actual_dom,
                    "received_at": date_str,
                    "threat_score": bundle.risk_score.threat_score,
                    "infra_confidence": bundle.risk_score.infrastructure_confidence,
                    "attribution_confidence": bundle.risk_score.attribution_confidence,
                    "verdict": verdict,  # SAFE | LOW_RISK | SUSPICIOUS | MALICIOUS
                    "classification": bundle.risk_score.classification,
                    "action_taken": action_taken,  # DELIVER | FLAG | QUARANTINE
                    "top_signals": signals,
                    "auth": {
                        "spf": bundle.auth.spf.result.upper() if bundle.auth.spf else "NONE",
                        "dkim": "PASS" if any(d.valid for d in bundle.auth.dkim) else ("FAIL" if bundle.auth.dkim else "NONE"),
                        "dmarc": bundle.auth.dmarc.result.upper() if bundle.auth.dmarc else "NONE",
                        "arc": "PASS" if bundle.auth.arc.chain_valid else ("FAIL" if bundle.auth.arc.present else "NONE")
                    },
                    "relay_hops_count": len(bundle.relay_hops),
                    "related_cases_count": bundle.related_cases_count,
                    "investigation_url": f"/investigation?id={bundle.email.email_id}",
                    "created_at": datetime.utcnow().isoformat() + "Z"
                }

                # Save to deduplication registry
                SCANNED_GMAIL_REGISTRY[dedup_key] = rec
                if sha256 not in SCANNED_GMAIL_REGISTRY:
                    SCANNED_GMAIL_REGISTRY[sha256] = rec

                results.append(rec)

                # Feed into live gateway records & broadcast via WebSocket
                gateway_msg_rec = EmailMessageRecord(
                    id=bundle.email.email_id,
                    provider="gmail",
                    provider_message_id=imap_id,
                    message_id=message_id,
                    sender=from_addr,
                    recipient=settings.GMAIL_EMAIL,
                    subject=bundle.email.headers_normalized.subject or subject,
                    received_at=date_str,
                    raw_eml_hash=bundle.email.sha256,
                    threat_score=bundle.risk_score.threat_score,
                    infra_confidence=bundle.risk_score.infrastructure_confidence,
                    attribution_confidence=bundle.risk_score.attribution_confidence,
                    verdict=verdict,
                    action_taken=action_taken,
                    triggered_rules=[{"rule": s} for s in signals],
                    analysis_status="complete",
                    case_id=bundle.case_id,
                    email_id=bundle.email.email_id,
                    correlated_cases_count=bundle.related_cases_count,
                    created_at=datetime.utcnow().isoformat() + "Z"
                )

                email_monitor.live_email_records.insert(0, gateway_msg_rec)
                if len(email_monitor.live_email_records) > 200:
                    email_monitor.live_email_records.pop()

                # Broadcast live WebSocket notification
                asyncio.create_task(email_monitor.broadcast_websocket_event({
                    "type": "NEW_LIVE_EMAIL",
                    "data": gateway_msg_rec.model_dump()
                }))

                if progress_callback:
                    await progress_callback(
                        done=idx + 1,
                        total=total,
                        current_subject=subject,
                        stage="Forensic analysis finalized & logged"
                    )

            except Exception as err:
                logger.error(f"[Gmail IMAP] Failed analyzing email {message_id}: {err}", exc_info=True)
                failures.append({"message_id": message_id, "error": str(err)})

        # Compute summary
        high_risk = len([r for r in results if (r.get("threat_score") or 0) >= 0.75])
        suspicious = len([r for r in results if 0.35 <= (r.get("threat_score") or 0) < 0.75])
        clean = len([r for r in results if (r.get("threat_score") or 0) < 0.35])

        summary = {
            "total": len(results),
            "high_risk": high_risk,
            "suspicious": suspicious,
            "clean": clean,
            "failed": len(failures),
            "failed_items": failures
        }

        LATEST_SCAN_SUMMARY.update({
            "total_scanned": len(results),
            "high_risk": high_risk,
            "suspicious": suspicious,
            "clean": clean,
            "failed": len(failures),
            "last_scanned_at": datetime.utcnow().isoformat() + "Z"
        })

        return {
            "status": "COMPLETE",
            "mailbox": settings.GMAIL_EMAIL,
            "summary": summary,
            "results": results,
            "scanned_at": datetime.utcnow().isoformat() + "Z"
        }

    def get_results(self) -> List[Dict[str, Any]]:
        """Returns unique scanned Gmail emails in reverse chronological order."""
        # De-duplicate by email_id
        seen = set()
        out = []
        for rec in reversed(list(SCANNED_GMAIL_REGISTRY.values())):
            eid = rec.get("email_id")
            if eid and eid not in seen:
                seen.add(eid)
                out.append(rec)
        return out

    def get_result_by_id(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves analysis result for a specific email_id."""
        for rec in SCANNED_GMAIL_REGISTRY.values():
            if rec.get("email_id") == email_id or rec.get("id") == email_id:
                return rec
        return None

    def start_auto_scan(self, interval_minutes: int = 5):
        """Starts the background auto-scanning worker loop."""
        self.auto_scan_interval_minutes = max(1, interval_minutes)
        self.auto_scan_enabled = True
        if self._auto_scan_task and not self._auto_scan_task.done():
            self._auto_scan_task.cancel()
        self._auto_scan_task = asyncio.create_task(self._auto_scan_loop())
        logger.info(f"[Gmail IMAP] Auto-scan polling enabled every {self.auto_scan_interval_minutes} minutes.")

    def stop_auto_scan(self):
        """Stops the background auto-scanning loop."""
        self.auto_scan_enabled = False
        if self._auto_scan_task and not self._auto_scan_task.done():
            self._auto_scan_task.cancel()
            self._auto_scan_task = None
        logger.info("[Gmail IMAP] Auto-scan polling disabled.")

    async def _auto_scan_loop(self):
        """Periodic background worker checking Gmail for new unanalyzed messages."""
        while self.auto_scan_enabled:
            try:
                await asyncio.sleep(self.auto_scan_interval_minutes * 60)
                if self.is_configured():
                    logger.info(f"[Gmail IMAP Auto-Scan] Polling {settings.GMAIL_EMAIL} for new messages...")
                    await self.fetch_and_scan_emails(limit=20)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Gmail IMAP Auto-Scan] Error in polling loop: {e}")
                await asyncio.sleep(30)


# Singleton instance
gmail_imap_service = GmailImapService()
