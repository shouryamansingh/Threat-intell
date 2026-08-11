"""Scheduling system for Threat Intelligence Automation"""

import time
import threading
import sqlite3
from datetime import datetime, timedelta, time as datetime_time
import pytz
from typing import List, Dict
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
import logging

import config
from config import SOC_DELIVERY_DELAY_HOURS, MAX_NEWS_PER_DAY_SOC
from database import db, parse_keywords
from web_scraper import scraper
from email_system import email_system
from soc_report_formatter_enhanced import enhanced_soc_formatter as soc_formatter

logger = logging.getLogger(__name__)

# Every cron trigger below is pinned to this zone explicitly. APScheduler
# defaults to the *machine's* local timezone, which is IST on a developer
# laptop and UTC on a default cloud instance — so the same code silently
# shifted the Monday scrape and the Tuesday SOC delivery by 5h30m when
# deployed. config.APP_TIMEZONE (TI_TIMEZONE) is now the single source of truth.
APP_TZ = pytz.timezone(config.APP_TIMEZONE)


class ThreatIntelScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler(timezone=APP_TZ)
        self.scheduler.start()
        self.is_running = False
        
        # Setup weekly scraping schedule - ENABLED FOR MONDAY 10 AM
        self.setup_weekly_scraping()
        
        # Setup daily SOC delivery check - DISABLED (using manual trigger only)
        # self.setup_daily_soc_delivery()
        
        # Setup persistent delivery monitoring
        self.setup_persistent_delivery_monitoring()

        # Check for missed deliveries on startup - DISABLED to prevent duplicate emails
        # self.recover_missed_deliveries()

        # Periodic self-diagnosis: keeps feed/network/DB breakage from going
        # unnoticed until the next scrape mysteriously returns 0 articles.
        self.setup_health_monitoring()

        # Bounded log growth. Without this the retention function was dead code.
        self.setup_log_retention()

        logger.info(f"Threat Intelligence Scheduler initialized (timezone={config.APP_TIMEZONE})")
    
    def setup_weekly_scraping(self):
        """Setup weekly scraping - Every Monday at 10:00 AM"""
        # Convert day name to number (Monday = 0)
        day_map = {
            'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
            'friday': 4, 'saturday': 5, 'sunday': 6
        }
        
        scraping_day = config.SCRAPING_DAY
        scraping_time = config.SCRAPING_TIME
        day_num = day_map.get(scraping_day.lower(), 0)  # Default to Monday

        trigger = CronTrigger(
            day_of_week=day_num,
            hour=scraping_time.hour,
            minute=scraping_time.minute,
            timezone=APP_TZ
        )

        self.scheduler.add_job(
            func=self.run_weekly_scraping,
            trigger=trigger,
            id='weekly_scraping',
            name='Weekly Scraping - Monday 10 AM',
            replace_existing=True
        )

        logger.info(
            f"✅ Weekly scraping scheduled for {scraping_day} at "
            f"{scraping_time.strftime('%I:%M %p')} {config.APP_TIMEZONE}"
        )
    
    def setup_health_monitoring(self):
        """Run the health checks every 6 hours (plus once ~2 min after boot)
        and log problems to system_logs so they surface in the dashboard.

        Uses health_checks.run_all_checks — read-only probes, never sends
        email (the SMTP check stops at STARTTLS).
        """
        self.scheduler.add_job(
            func=self.run_health_checks,
            trigger=CronTrigger(hour='*/6', minute=15, timezone=APP_TZ),
            id='health_monitor',
            name='System Health Monitor (every 6h)',
            replace_existing=True
        )
        # One early run after startup so a broken environment is reported
        # within minutes, not hours. (Delayed so boot isn't slowed down.)
        # Timezone-aware "now": a naive datetime here is interpreted in the
        # scheduler's zone, which would be wrong by the UTC offset on a server.
        self.scheduler.add_job(
            func=self.run_health_checks,
            trigger='date',
            run_date=datetime.now(APP_TZ) + timedelta(minutes=2),
            id='health_monitor_boot',
            name='System Health Monitor (startup)',
            replace_existing=True
        )
        logger.info("✅ Health monitoring scheduled (startup + every 6 hours)")

    def setup_log_retention(self):
        """Prune logs and old rejected articles once a day, at 03:40 local.

        db.cleanup_old_records has existed since the beginning but nothing ever
        called it, so system_logs and activity_log grew without bound. Runs in
        the small hours so the write lock never competes with a scrape or a
        delivery.
        """
        self.scheduler.add_job(
            func=self.run_log_retention,
            trigger=CronTrigger(hour=3, minute=40, timezone=APP_TZ),
            id='log_retention',
            name=f'Log retention sweep (keep {config.LOG_RETENTION_DAYS} days)',
            replace_existing=True
        )
        logger.info(
            f"✅ Log retention scheduled daily at 03:40 {config.APP_TIMEZONE} "
            f"(keeping {config.LOG_RETENTION_DAYS} days)"
        )

    def run_log_retention(self):
        """Execute the retention sweep, recording the outcome in system_logs."""
        try:
            deleted = db.cleanup_old_records(days=config.LOG_RETENTION_DAYS)
            total = sum(deleted.values())
            if total:
                db.log_system_event(
                    'INFO',
                    f"Retention sweep removed {total} rows older than "
                    f"{config.LOG_RETENTION_DAYS} days ({deleted})",
                    'RETENTION'
                )
        except Exception as e:
            logger.error(f"Log retention sweep failed: {e}")
            db.log_system_event('ERROR', f"Log retention sweep failed: {e}", 'RETENTION')

    def run_health_checks(self):
        """Execute health checks and log WARN/FAIL results."""
        try:
            from health_checks import run_all_checks
            report = run_all_checks(deep=True)
            issues = [f"{c['name']}: {c['message']}" for c in report['checks']
                      if c['status'] in ('warn', 'fail')]
            if report['status'] == 'fail':
                db.log_system_event('ERROR',
                                    f"Health check FAILED — {'; '.join(issues)}",
                                    'HEALTH_MONITOR')
                logger.error(f"❌ Health check FAILED: {'; '.join(issues)}")
            elif report['status'] == 'warn':
                db.log_system_event('WARNING',
                                    f"Health check warnings — {'; '.join(issues)}",
                                    'HEALTH_MONITOR')
                logger.warning(f"⚠️ Health check warnings: {'; '.join(issues)}")
            else:
                logger.info("✅ Health check passed")
        except Exception as e:
            logger.error(f"Health monitor crashed: {e}")

    def setup_daily_soc_delivery(self):
        """Setup Tuesday SOC deliveries at 11:00 AM"""
        # Check on Tuesday at 11:00 AM for pending SOC deliveries
        
        # Tuesday delivery at 11:00 AM
        tuesday_trigger = CronTrigger(day_of_week=1, hour=11, minute=0, timezone=APP_TZ)  # Tuesday = 1, 11:00 AM
        self.scheduler.add_job(
            func=self.process_soc_deliveries,
            trigger=tuesday_trigger,
            id='tuesday_soc_delivery',
            name='Tuesday SOC Delivery Processing',
            replace_existing=True
        )
        
        logger.info("✅ Tuesday SOC delivery processing scheduled for 11:00 AM (One news per Tuesday)")
    
    def setup_persistent_delivery_monitoring(self):
        """Setup persistent delivery monitoring with enhanced scheduler.

        enhanced_scheduler polls the soc_deliveries table every 30s and
        actually sends the SOC email. Without it, scheduled deliveries
        never fire — deliver_to_soc() in this file is just a stub.
        """
        from enhanced_scheduler import enhanced_scheduler
        enhanced_scheduler.start()
        logger.info("✅ Persistent delivery monitor started — SOC deliveries will fire at their scheduled time")
    
    def setup_persistent_delivery_monitoring_old(self):
        """Setup monitoring for persistent deliveries every 5 minutes"""
        # Check for scheduled deliveries every 5 minutes
        trigger = CronTrigger(minute='*/5', timezone=APP_TZ)  # Every 5 minutes
        self.scheduler.add_job(
            func=self.check_scheduled_deliveries,
            trigger=trigger,
            id='persistent_delivery_monitor',
            name='Persistent Delivery Monitor',
            replace_existing=True
        )
        logger.info("Persistent delivery monitoring scheduled every 5 minutes")
    
    def recover_missed_deliveries(self):
        """Check for missed deliveries on startup and process them"""
        try:
            logger.info("🔍 Checking for missed deliveries on startup...")
            
            # Get all scheduled deliveries that should have been sent
            missed_deliveries = db.get_scheduled_deliveries(limit=100)
            
            if missed_deliveries:
                logger.info(f"📋 Found {len(missed_deliveries)} missed deliveries to process")
                
                for delivery in missed_deliveries:
                    try:
                        # Process the missed delivery
                        success = self.process_delivery(delivery)
                        
                        if success:
                            logger.info(f"✅ Recovered missed delivery for article {delivery['article_id']}")
                        else:
                            logger.warning(f"⚠️ Failed to recover delivery for article {delivery['article_id']}")
                            
                    except Exception as e:
                        logger.error(f"❌ Error recovering delivery {delivery['id']}: {str(e)}")
                        db.update_delivery_status(delivery['id'], 'failed', str(e))
            else:
                logger.info("✅ No missed deliveries found")
                
        except Exception as e:
            logger.error(f"❌ Error during delivery recovery: {str(e)}")
    
    def check_scheduled_deliveries(self):
        """Check for scheduled deliveries that need to be processed"""
        try:
            # Get deliveries that are due now or overdue
            due_deliveries = db.get_scheduled_deliveries(limit=10)
            
            if due_deliveries:
                logger.info(f"📋 Found {len(due_deliveries)} deliveries due for processing")
                
                for delivery in due_deliveries:
                    try:
                        success = self.process_delivery(delivery)
                        
                        if not success and delivery['retry_count'] < 3:
                            # Schedule retry in 30 minutes
                            retry_time = datetime.now(pytz.timezone("Asia/Kolkata")) + timedelta(minutes=30)
                            logger.info(f"🔄 Scheduling retry for delivery {delivery['id']} at {retry_time}")
                            
                    except Exception as e:
                        logger.error(f"❌ Error processing delivery {delivery['id']}: {str(e)}")
                        db.update_delivery_status(delivery['id'], 'failed', str(e))
                        
        except Exception as e:
            logger.error(f"❌ Error checking scheduled deliveries: {str(e)}")
    
    def process_delivery(self, delivery: Dict) -> bool:
        """Process a single delivery - DISABLED to prevent duplicates, only enhanced_scheduler sends emails"""
        try:
            delivery_id = delivery['id']
            article_id = delivery['article_id']
            
            logger.info(f"⚠️ process_delivery called for article {article_id} - SKIPPING (enhanced_scheduler handles this)")
            logger.info(f"   Delivery will be processed by enhanced_scheduler only")
            
            # DO NOT SEND EMAIL - Let enhanced_scheduler handle it
            return True
                
        except Exception as e:
            logger.error(f"❌ Error in process_delivery {delivery['id']}: {str(e)}")
            return False
    
    def run_weekly_scraping(self):
        """Execute weekly scraping and send to manager"""
        try:
            logger.info("Starting weekly scraping session...")
            
            # Run scraping
            scraping_results = scraper.run_scraping_session()
            
            if scraping_results.get('articles_saved_to_db', 0) > 0:
                # Get top articles for manager review
                articles = db.get_pending_articles_for_manager(config.MAX_NEWS_TO_MANAGER)
                
                if articles:
                    # Send to manager for approval
                    success = email_system.send_manager_approval_email(articles)
                    
                    if success:
                        logger.info(f"Manager approval email sent with {len(articles)} articles")
                        db.log_system_event(
                            'INFO',
                            f'Weekly scraping completed. {len(articles)} articles sent to manager for approval.',
                            'SCHEDULER'
                        )
                    else:
                        logger.error("Failed to send manager approval email")
                        db.log_system_event(
                            'ERROR',
                            'Failed to send manager approval email after weekly scraping',
                            'SCHEDULER'
                        )
                else:
                    logger.warning("No articles found for manager review")
                    db.log_system_event(
                        'WARNING',
                        'Weekly scraping completed but no articles found for manager review',
                        'SCHEDULER'
                    )
            else:
                logger.warning("No articles were saved from scraping session")
                db.log_system_event(
                    'WARNING',
                    'Weekly scraping completed but no relevant articles were found',
                    'SCHEDULER'
                )
        
        except Exception as e:
            logger.error(f"Error in weekly scraping: {str(e)}")
            db.log_system_event(
                'ERROR',
                f'Error in weekly scraping: {str(e)}',
                'SCHEDULER'
            )
    
    def schedule_soc_delivery(self, article_id: int, delivery_delay_hours: int = SOC_DELIVERY_DELAY_HOURS):
        """Schedule SOC delivery for an approved article with transaction safety"""
        try:
            import sqlite3
            
            # ⏰ STEP 1: Capture CURRENT system time at approval moment
            ist_tz = pytz.timezone("Asia/Kolkata")
            approval_time = datetime.now(ist_tz)
            
            logger.info(f"🕐 APPROVAL RECEIVED at: {approval_time.strftime('%A, %B %d, %Y at %I:%M:%S %p IST')}")
            
            conn = sqlite3.connect(db.db_path, timeout=30)
            cursor = conn.cursor()
            
            # 🔒 START EXCLUSIVE TRANSACTION to prevent race conditions
            cursor.execute('BEGIN EXCLUSIVE')
            
            try:
                # Check if SOC delivery already exists for this article
                cursor.execute('SELECT COUNT(*) FROM soc_deliveries WHERE article_id = ?', (article_id,))
                existing_count = cursor.fetchone()[0]
                
                if existing_count > 0:
                    logger.info(f"⚠️ SOC delivery already exists for article {article_id}, skipping duplicate")
                    conn.rollback()
                    conn.close()
                    return False
                
                # Count pending deliveries (INSIDE TRANSACTION - prevents race condition)
                cursor.execute('SELECT COUNT(*) FROM soc_deliveries WHERE status = "pending"')
                position = cursor.fetchone()[0]
                
                logger.info(f"📊 SCHEDULER: Article {article_id} assigned position {position} (Total pending: {position})")
                
                # Calculate delivery time (PASS approval_time to use exact approval moment)
                delivery_time = self._calculate_next_delivery_slot(position, approval_time)
                
                logger.info(f"📅 SCHEDULER: Calculated delivery slot for position {position}: {delivery_time.strftime('%A, %B %d at %I:%M %p')}")
                
                # Insert immediately (INSIDE TRANSACTION - atomic operation)
                cursor.execute('''
                    INSERT INTO soc_deliveries (article_id, position, scheduled_for, status, created_at)
                    VALUES (?, ?, ?, 'pending', datetime('now'))
                ''', (article_id, position, delivery_time.isoformat()))
                
                delivery_id = cursor.lastrowid
                
                # ✅ COMMIT transaction (releases lock)
                conn.commit()
                
                logger.info(f"✅ Article {article_id} successfully scheduled at position {position} for {delivery_time}")

                # NOTE: We deliberately do NOT add an APScheduler DateTrigger job
                # here. Delivery is owned by enhanced_scheduler, which polls the
                # soc_deliveries table every 30s and atomically claims due rows.
                # That design survives restarts (jobstore is the DB) AND prevents
                # the previous bug where the APScheduler job called a no-op stub.

                db.log_system_event(
                    'INFO',
                    f'SOC delivery scheduled for article {article_id} at {delivery_time.strftime("%A, %B %d at %I:%M %p")} (Position: {position})',
                    'SCHEDULER'
                )
                
                conn.close()
                return delivery_time
                
            except Exception as e:
                conn.rollback()
                conn.close()
                logger.error(f"❌ Transaction error for article {article_id}: {str(e)}")
                raise e
        
        except Exception as e:
            logger.error(f"❌ Error scheduling SOC delivery for article {article_id}: {str(e)}")
            return False
    
    def _cancel_auto_jobs_for_article(self, article_id: int) -> int:
        """Remove any pending one-off apscheduler jobs that would re-deliver
        this specific article at a stale time. Returns the count removed.

        Two job-id shapes are matched:
          * legacy: ``soc_delivery_<article_id>_<timestamp>``
          * /api/schedule-delivery: ``manual-delivery-<ts>-<article_id>``
        (article-specific only — a ``manual-delivery-<ts>-all`` job targets
        every pending article and is deliberately left untouched here.)
        """
        legacy_prefix = f"soc_delivery_{article_id}_"
        manual_suffix = f"-{article_id}"
        removed = 0
        for job in list(self.scheduler.get_jobs()):
            jid = job.id
            is_legacy = jid.startswith(legacy_prefix)
            is_manual = jid.startswith("manual-delivery-") and jid.endswith(manual_suffix)
            if is_legacy or is_manual:
                try:
                    self.scheduler.remove_job(jid)
                    removed += 1
                except Exception as e:
                    logger.warning(f"Failed to remove auto-job {jid}: {e}")
        return removed

    def _finalize_delivery(self, delivery_id: int, article_id: int, success: bool):
        """Mark a delivery row sent/failed and remove its pending auto-job."""
        try:
            import sqlite3
            conn = sqlite3.connect(db.db_path, timeout=30)
            conn.execute("PRAGMA busy_timeout=30000")
            cursor = conn.cursor()
            if success:
                cursor.execute(
                    "UPDATE soc_deliveries SET status = 'sent', delivery_date = datetime('now') WHERE id = ?",
                    (delivery_id,),
                )
            else:
                cursor.execute(
                    "UPDATE soc_deliveries SET status = 'failed' WHERE id = ?",
                    (delivery_id,),
                )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Could not update delivery {delivery_id} status: {e}")

        if success:
            cancelled = self._cancel_auto_jobs_for_article(article_id)
            if cancelled:
                logger.info(f"Removed {cancelled} pending auto-job(s) for article {article_id}")
            # Push the 'sent' state to connected dashboards immediately so a
            # manual send updates every open tab, not just the one that clicked.
            try:
                import enhanced_scheduler as _es
                _es._push_delivery_update(article_id, delivery_id)
            except Exception:
                pass

    def cancel_pending_delivery(self, delivery_id: int) -> dict:
        """Cancel a pending SOC delivery row + its apscheduler job.
        Returns {"ok": bool, "message": str, "article_id": int|None}."""
        try:
            import sqlite3
            conn = sqlite3.connect(db.db_path, timeout=30)
            conn.execute("PRAGMA busy_timeout=30000")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT article_id, status FROM soc_deliveries WHERE id = ?",
                (delivery_id,),
            )
            row = cursor.fetchone()
            if not row:
                conn.close()
                return {"ok": False, "message": f"No delivery with id {delivery_id}", "article_id": None}
            article_id, status = row
            if status != "pending":
                conn.close()
                return {"ok": False, "message": f"Delivery is already '{status}', nothing to cancel", "article_id": article_id}
            cursor.execute(
                "UPDATE soc_deliveries SET status = 'cancelled' WHERE id = ?",
                (delivery_id,),
            )
            conn.commit()
            conn.close()
            cancelled = self._cancel_auto_jobs_for_article(article_id)
            db.log_system_event(
                "INFO",
                f"Delivery {delivery_id} for article {article_id} cancelled by user (removed {cancelled} auto-job(s))",
                "SCHEDULER",
            )
            return {"ok": True, "message": "Delivery cancelled", "article_id": article_id, "auto_jobs_removed": cancelled}
        except Exception as e:
            logger.error(f"Error cancelling delivery {delivery_id}: {e}")
            return {"ok": False, "message": str(e), "article_id": None}

    def _claim_pending_delivery(self, delivery_id: int) -> bool:
        """Atomically move a delivery row from 'pending' to 'sending'.

        Returns True ONLY for the worker that wins the claim. This is the
        same guard enhanced_scheduler uses, so the SOC email goes out exactly
        once even if the 15s poller, a second button click, or a stale one-off
        job all race for the same row."""
        conn = sqlite3.connect(db.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE soc_deliveries SET status='sending' WHERE id=? AND status='pending'",
                (delivery_id,),
            )
            claimed = cur.rowcount
            conn.commit()
            return claimed > 0
        finally:
            conn.close()

    def _release_claim(self, delivery_id: int):
        """Return a claimed ('sending') row to 'pending' so it stays eligible
        for a later attempt (used when we claim a row but then can't send it,
        e.g. content was rejected by the formatter)."""
        try:
            conn = sqlite3.connect(db.db_path, timeout=30)
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute(
                "UPDATE soc_deliveries SET status='pending' WHERE id=? AND status='sending'",
                (delivery_id,),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Could not release claim on delivery {delivery_id}: {e}")

    def trigger_manual_delivery(self, article_id: int = None) -> bool:
        """Manually trigger delivery of scheduled articles (for testing or recovery)"""
        try:
            import sqlite3
            
            if article_id:
                # Deliver specific article - standalone method
                logger.info(f"🔧 Manual delivery triggered for article {article_id}")

                # Get delivery info from database (oldest pending row for this article)
                conn = sqlite3.connect(db.db_path)
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT sd.id, sd.article_id, na.title, na.summary, na.content,
                           na.url, na.source, sd.scheduled_for
                    FROM soc_deliveries sd
                    JOIN news_articles na ON sd.article_id = na.id
                    WHERE sd.article_id = ? AND sd.status = 'pending'
                    ORDER BY sd.scheduled_for
                    LIMIT 1
                ''', (article_id,))

                delivery = cursor.fetchone()
                conn.close()

                if not delivery:
                    logger.error(f"❌ No pending delivery found for article {article_id}")
                    return False

                delivery_id, art_id, title, summary, content, url, source, scheduled_for = delivery

                # 🔒 Send-once guard: claim the row BEFORE doing any work. If the
                # 15s poller, a second click, or a stale one-off job already
                # claimed it, bail — no duplicate SOC email.
                if not self._claim_pending_delivery(delivery_id):
                    logger.warning(f"⚠️ Delivery {delivery_id} already claimed/sent — skipping manual send")
                    return False

                # Get article data
                article = {
                    'id': art_id,
                    'title': title,
                    'summary': summary,
                    'content': content,
                    'url': url,
                    'source': source,
                    'relevance_score': 0.9,
                    'keywords': []
                }

                # Format and send (row is now 'sending', owned by us)
                try:
                    soc_report = soc_formatter.format_soc_report(article)
                    if soc_report is None:
                        logger.warning(f"⚠️ Skipping article {article_id} - low content quality")
                        self._release_claim(delivery_id)  # back to pending
                        return False

                    html_content = soc_formatter.generate_soc_report_html(soc_report)
                    success = self.send_soc_formatted_email(soc_report, html_content)
                except Exception as e:
                    logger.exception(f"❌ Manual send raised for article {article_id}: {e}")
                    self._finalize_delivery(delivery_id, art_id, False)
                    return False

                # Finalize: mark row as sent (or failed) and remove any pending
                # auto-job that would otherwise re-send this article at its
                # originally scheduled time.
                self._finalize_delivery(delivery_id, art_id, success)

                if success:
                    logger.info(f"✅ Manual delivery successful for article {article_id} — marked sent + auto-job removed")
                else:
                    logger.error(f"❌ Manual delivery failed for article {article_id} — marked failed")

                return success
                
            else:
                # Process all pending deliveries (IGNORE schedule, send immediately)
                logger.info("🔧 Manual delivery triggered for all pending articles")
                
                # Get ALL pending deliveries regardless of scheduled time
                conn = sqlite3.connect(db.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT sd.id, sd.article_id, na.title, na.summary, na.content, 
                           na.url, na.source, sd.scheduled_for
                    FROM soc_deliveries sd
                    JOIN news_articles na ON sd.article_id = na.id
                    WHERE sd.status = 'pending'
                    ORDER BY sd.scheduled_for
                    LIMIT 50
                ''')
                
                pending_deliveries = cursor.fetchall()
                conn.close()
                
                if not pending_deliveries:
                    logger.info("📋 No pending deliveries found")
                    return True
                
                logger.info(f"📋 Found {len(pending_deliveries)} pending delivery(ies) - triggering now")
                
                success_count = 0
                for delivery in pending_deliveries:
                    delivery_id, article_id, title, summary, content, url, source, scheduled_for = delivery

                    # 🔒 Claim each row individually; skip any a concurrent worker
                    # (poller / another trigger) already grabbed — send-once.
                    if not self._claim_pending_delivery(delivery_id):
                        logger.info(f"⏭️ Delivery {delivery_id} already claimed/sent — skipping")
                        continue

                    try:
                        # Prepare article
                        article = {
                            'id': article_id,
                            'title': title,
                            'summary': summary,
                            'content': content,
                            'url': url,
                            'source': source,
                            'relevance_score': 0.9,
                            'keywords': []
                        }

                        # Format and send (row is now 'sending', owned by us)
                        soc_report = soc_formatter.format_soc_report(article)
                        if soc_report is None:
                            logger.warning(f"⚠️ Skipping article {article_id} - low content quality")
                            self._release_claim(delivery_id)  # back to pending
                            continue

                        html_content = soc_formatter.generate_soc_report_html(soc_report)
                        success = self.send_soc_formatted_email(soc_report, html_content)

                        # Finalize: mark sent/failed AND cancel any pending auto-job
                        # so this article doesn't get re-delivered on its original schedule.
                        self._finalize_delivery(delivery_id, article_id, success)

                        if success:
                            logger.info(f"✅ Delivered article {article_id}: {title[:50]} — marked sent + auto-job removed")
                            success_count += 1
                        else:
                            logger.error(f"❌ Failed to deliver article {article_id} — marked failed")

                    except Exception as e:
                        logger.error(f"❌ Error processing article {article_id}: {str(e)}")
                        self._finalize_delivery(delivery_id, article_id, False)
                
                logger.info(f"✅ Manual delivery completed: {success_count}/{len(pending_deliveries)} successful")
                return success_count > 0
                
        except Exception as e:
            logger.error(f"❌ Error in manual delivery: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _calculate_next_delivery_slot(self, position: int, approval_time: datetime) -> datetime:
        """
        Calculate the SOC delivery slot.

        Policy: every approved article goes out on the SAME upcoming Tuesday
        at 11:00 AM IST. Each `position` adds a small 2-minute stagger so
        we don't fire N SMTP sends in the same instant (Gmail rate-limits
        bursts) — but the date never shifts to a later Tuesday. This
        replaces the old behaviour where position pushed deliveries 1
        week further into the future per article.

        Args:
            position: Queue position (0, 1, 2, …) within the same week.
            approval_time: Manager approval time (IST, tz-aware).

        Returns:
            Delivery datetime on the next eligible Tuesday at 11:00 AM IST
            (+ a 2 × position minute offset).
        """
        try:
            current_weekday = approval_time.weekday()   # 0=Mon … 6=Sun
            current_hour    = approval_time.hour

            logger.info(
                f"🕐 Approval Time: "
                f"{approval_time.strftime('%A, %B %d, %Y at %I:%M:%S %p IST')}"
            )

            # Find the next Tuesday-at-11:00 from the approval moment.
            if current_weekday == 1 and current_hour < 11:
                days_to_tuesday = 0          # today (Tuesday before 11 AM)
            elif current_weekday == 1:
                days_to_tuesday = 7          # today (Tuesday after 11 AM) → next week
            else:
                days_to_tuesday = (1 - current_weekday) % 7
                if days_to_tuesday == 0:
                    days_to_tuesday = 7

            base = approval_time + timedelta(days=days_to_tuesday)
            base = base.replace(hour=11, minute=0, second=0, microsecond=0)
            logger.info(f"   📍 Upcoming Tuesday: {base.strftime('%A, %B %d, %Y at %I:%M %p')}")

            # Stagger by minutes (NOT weeks) so all articles approved this
            # week land on the same Tuesday.
            delivery_date = base + timedelta(minutes=2 * position)
            logger.info(
                f"   🎯 Position {position} → +{2 * position} min stagger → "
                f"{delivery_date.strftime('%A, %B %d, %Y at %I:%M %p')}"
            )
            return delivery_date

        except Exception as e:
            logger.error(f"❌ Error calculating delivery slot: {e}")
            ist_tz = pytz.timezone("Asia/Kolkata")
            fallback = datetime.now(ist_tz) + timedelta(days=7)
            fallback = fallback.replace(hour=11, minute=0, second=0, microsecond=0)
            logger.warning(f"⚠️ Using fallback: {fallback.strftime('%A, %B %d at %I:%M %p')}")
            return fallback
    
    def deliver_to_soc(self, article_id: int):
        """Deliver approved article to SOC team - REMOVED to prevent duplicates"""
        try:
            # This method is now disabled to prevent duplicate emails
            # All SOC deliveries are handled by process_delivery method via Persistent Delivery Monitor
            logger.info(f"📤 deliver_to_soc called for article {article_id} - delegating to Persistent Delivery Monitor")
            return True
        except Exception as e:
            logger.error(f"Error delivering article {article_id} to SOC: {str(e)}")
            db.log_system_event(
                'ERROR',
                f'Error delivering article {article_id} to SOC: {str(e)}',
                'SOC_DELIVERY'
            )
            return False
    
    def send_soc_formatted_email(self, report, html_content: str) -> bool:
        """Send formatted email to SOC team with Excel attachment"""
        try:
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            from email.mime.base import MIMEBase
            from email import encoders
            import os
            import re

            # Strip article numbering from title (like "02. ")
            clean_title = re.sub(r'^\s*#?\s*\(?\s*\d{1,3}\)?[\.:\)]\s*', '', str(report.title)).strip()

            # Create message (use "mixed" for attachments)
            message = MIMEMultipart("mixed")
            message["Subject"] = f'Notable Global Cyber Threat – "{clean_title}"'
            message["From"] = config.SENDER_EMAIL
            message["To"] = config.SOC_EMAIL
            # Add CC recipients (live)
            soc_cc = config.SOC_EMAIL_CC
            if soc_cc:
                message["Cc"] = ", ".join(soc_cc)
            
            # Create HTML part only (no plain text)
            html_part = MIMEText(html_content, "html")
            
            # Add HTML part to message
            message.attach(html_part)
            
            # Generate and attach Excel file
            excel_filename = soc_formatter.generate_excel_attachment(report, f"TI-{report.title[:20]}")
            if excel_filename and os.path.exists(excel_filename):
                try:
                    with open(excel_filename, 'rb') as f:
                        excel_attachment = MIMEBase('application', 'vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                        excel_attachment.set_payload(f.read())
                        encoders.encode_base64(excel_attachment)
                        excel_attachment.add_header(
                            'Content-Disposition',
                            'attachment',
                            filename=os.path.basename(excel_filename)
                        )
                        message.attach(excel_attachment)
                    
                    logger.info(f"✅ Excel attachment added: {excel_filename}")
                    
                    # Clean up Excel file after attaching
                    os.remove(excel_filename)
                except Exception as e:
                    logger.warning(f"⚠️ Could not attach Excel file: {e}")
            
            # Send email
            with email_system.create_smtp_connection() as server:
                server.send_message(message)
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to send SOC formatted email: {str(e)}")
            return False
    
    def process_soc_deliveries(self):
        """Process pending SOC deliveries with alternate day logic"""
        try:
            # Get pending approved articles
            pending_articles = db.get_approved_articles_for_soc()
            
            if not pending_articles:
                logger.info("No pending SOC deliveries")
                return
            
            # Check if any article should be delivered today
            today = datetime.now(pytz.timezone("Asia/Kolkata")).date()
            
            # Get last delivery date from database
            import sqlite3
            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT MAX(DATE(delivery_date)) as last_delivery_date
                FROM soc_deliveries 
                WHERE status = 'sent'
            ''')
            
            result = cursor.fetchone()
            last_delivery_date = result[0] if result[0] else None
            
            conn.close()
            
            # Determine if we should deliver today
            should_deliver_today = False
            
            if last_delivery_date is None:
                # No previous deliveries, can deliver today
                should_deliver_today = True
            else:
                # Parse the date string
                from datetime import datetime
                last_date = datetime.strptime(last_delivery_date, '%Y-%m-%d').date()
                days_since_last = (today - last_date).days
                
                # Deliver every other day (alternate days)
                if days_since_last >= 1:  # At least 1 day gap
                    should_deliver_today = True
            
            if should_deliver_today and pending_articles:
                # Deliver the oldest pending article
                article_to_deliver = pending_articles[0]  # Oldest first
                
                success = self.deliver_to_soc(article_to_deliver['id'])
                
                if success:
                    logger.info(f"Daily SOC delivery completed for article: {article_to_deliver['title'][:50]}")
                else:
                    logger.error(f"Failed daily SOC delivery for article: {article_to_deliver['title'][:50]}")
            else:
                logger.info("No SOC delivery scheduled for today (alternate day logic)")
        
        except Exception as e:
            logger.error(f"Error processing SOC deliveries: {str(e)}")
            db.log_system_event(
                'ERROR',
                f'Error processing SOC deliveries: {str(e)}',
                'SCHEDULER'
            )
    
    def handle_manager_approval(self, article_id: int, decision: str):
        """Handle immediate actions after manager approval"""
        if decision == 'approved':
            try:
                # Send to sender for validation instead of immediate SOC delivery
                success = self.send_for_sender_validation(article_id)
                
                if success:
                    logger.info(f"Article {article_id} approved - sent for sender validation")
                    return True
                else:
                    logger.error(f"Failed to send article {article_id} for sender validation")
                    return False
                
            except Exception as e:
                logger.error(f"Error handling manager approval for article {article_id}: {str(e)}")
                return False
        return False
    
    def send_for_sender_validation(self, article_id: int):
        """Send approved article to sender for validation"""
        try:
            logger.info(f"🔄 SCHEDULER: Starting send_for_sender_validation for article {article_id}")
            # Get article details
            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, title, summary, content, url, source, relevance_score, keywords
                FROM news_articles 
                WHERE id = ?
            ''', (article_id,))
            
            article_data = cursor.fetchone()
            conn.close()
            
            if not article_data:
                logger.error(f"❌ SCHEDULER: Article {article_id} not found for sender validation")
                return False
            
            logger.info(f"📰 SCHEDULER: Found article {article_id}: {article_data[1][:50]}...")
            
            # Prepare article dict
            keywords_list = parse_keywords(article_data[7])
            
            article = {
                'id': article_data[0],
                'title': article_data[1],
                'summary': article_data[2],
                'content': article_data[3],
                'url': article_data[4],
                'source': article_data[5],
                'relevance_score': float(article_data[6]) if article_data[6] else 0,
                'keywords': keywords_list
            }
            
            # Format SOC report
            from soc_report_formatter_enhanced import enhanced_soc_formatter as soc_formatter
            soc_report = soc_formatter.format_soc_report(article)
            
            # ALWAYS send validation email - let sender decide on quality!
            # Even if quality is low, sender should review and decide
            if soc_report is None:
                logger.warning(f"⚠️ Low quality content for article {article_id}, but sending to sender for review")
                # Generate a basic report anyway for sender to review
                from soc_report_formatter import soc_formatter as backup_formatter
                soc_report = backup_formatter.format_soc_report(article)
            
            # Send validation email (ALWAYS, regardless of quality)
            logger.info(f"📧 SCHEDULER: Calling sender_validator.send_validation_email for article {article_id}")
            from sender_validation import sender_validator
            success = sender_validator.send_validation_email(article_id, soc_report)
            logger.info(f"📨 SCHEDULER: Sender validation email result: {success}")
            
            if success:
                logger.info(f"Validation email sent for article {article_id}")
                db.log_system_event(
                    'INFO',
                    f'Article {article_id} sent for sender validation',
                    'SENDER_VALIDATION'
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending article {article_id} for sender validation: {e}")
            return False
    
    
    def get_scheduler_status(self) -> Dict:
        """Get current scheduler status"""
        jobs = self.scheduler.get_jobs()
        
        status = {
            'scheduler_running': self.scheduler.running,
            'total_jobs': len(jobs),
            'jobs': []
        }
        
        for job in jobs:
            status['jobs'].append({
                'id': job.id,
                'name': job.name,
                'next_run_time': job.next_run_time.isoformat() if job.next_run_time else None,
                'trigger': str(job.trigger)
            })
        
        return status
    
    def run_immediate_test(self):
        """Run immediate test of the entire system"""
        try:
            logger.info("Running immediate system test...")
            
            # Run scraping
            scraping_results = scraper.run_scraping_session()
            
            if scraping_results.get('articles_saved_to_db', 0) > 0:
                # Get articles for manager
                articles = db.get_pending_articles_for_manager(5)  # Limit to 5 for testing
                
                if articles:
                    # Send test email to manager
                    success = email_system.send_manager_approval_email(articles)
                    
                    if success:
                        logger.info(f"Test completed: {len(articles)} articles sent to manager")
                        return {
                            'success': True,
                            'articles_scraped': scraping_results.get('total_found', 0),
                            'articles_sent_to_manager': len(articles),
                            'message': 'Test completed successfully'
                        }
                    else:
                        return {
                            'success': False,
                            'message': 'Failed to send manager email'
                        }
                else:
                    return {
                        'success': False,
                        'message': 'No relevant articles found for testing'
                    }
            else:
                return {
                    'success': False,
                    'message': 'No articles were scraped during test'
                }
        
        except Exception as e:
            logger.error(f"Error in immediate test: {str(e)}")
            return {
                'success': False,
                'message': f'Test failed: {str(e)}'
            }
    
    def shutdown(self):
        """Shutdown the scheduler"""
        try:
            self.scheduler.shutdown()
            logger.info("Threat Intelligence Scheduler shutdown completed")
        except Exception as e:
            logger.error(f"Error shutting down scheduler: {str(e)}")


# Create global scheduler instance
threat_scheduler = ThreatIntelScheduler()


if __name__ == "__main__":
    print("🚀 Starting Threat Intelligence Scheduler...")
    print(f"📅 Weekly scraping scheduled for {config.SCRAPING_DAY} at {config.SCRAPING_TIME}")
    print(f"📧 SOC delivery delay: {SOC_DELIVERY_DELAY_HOURS} hour(s)")
    print("📊 Daily SOC processing scheduled for 10:00 AM")
    print("\n🔄 Scheduler is running. Press Ctrl+C to stop.\n")
    
    try:
        # Print current status
        status = threat_scheduler.get_scheduler_status()
        print("📋 Current Jobs:")
        for job in status['jobs']:
            print(f"  - {job['name']}: {job['next_run_time']}")
        
        print("\n🧪 Running immediate test...")
        test_result = threat_scheduler.run_immediate_test()
        print(f"Test Result: {test_result}")
        
        # Keep the scheduler running
        try:
            while True:
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            print("\n🛑 Shutting down scheduler...")
            threat_scheduler.shutdown()
            print("✅ Scheduler stopped.")
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        threat_scheduler.shutdown()
