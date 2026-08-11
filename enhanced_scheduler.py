#!/usr/bin/env python3
"""
Enhanced Scheduler that actually delivers news at scheduled times
"""

import time
import threading
import sqlite3
from datetime import datetime, timedelta
import pytz
import logging
import config
from database import db

logger = logging.getLogger(__name__)

# Application timezone (TI_TIMEZONE, default Asia/Kolkata). Was hardcoded here;
# now shared with scheduler.py so there is a single place to change it.
IST = pytz.timezone(config.APP_TIMEZONE)

# Optional real-time notifier. The web layer (web_dashboard.py) registers a
# callable here so that when a delivery is sent from this background poller
# thread, connected dashboards are updated immediately (Socket.IO push)
# instead of waiting for their next poll. Processes without a running web
# server (e.g. callback_server.py) simply never register one, so the push
# is a safe no-op there.
delivery_notifier = None  # callable(dict) | None


def _push_delivery_update(article_id, delivery_id):
    """Push a real-time 'delivered' event to the dashboard, if a notifier is
    registered. Never raises — a failed push must not affect delivery."""
    notifier = delivery_notifier
    if notifier is None:
        return
    try:
        notifier({
            'status': 'delivered',
            'article_id': article_id,
            'delivery_id': delivery_id,
        })
    except Exception as e:  # pragma: no cover - best-effort UI update
        logger.warning(f"delivery notifier failed: {e}")


class EnhancedScheduler:
    # After this many consecutive failed send attempts, stop retrying and mark
    # the row 'failed' so the dashboard shows the problem instead of a row that
    # sits at PENDING forever (e.g. when SMTP credentials are wrong).
    MAX_SEND_RETRIES = 5

    def __init__(self):
        self.running = False
        # Poll frequently so a delivery fires within ~15s of its scheduled
        # time (and of any reschedule to an earlier time).
        self.check_interval = 15  # seconds
        
    def start(self):
        """Start the scheduler"""
        self.running = True
        self.thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.thread.start()
        logger.info("✅ Enhanced Scheduler started - checking every 30 seconds")
        
    def stop(self):
        """Stop the scheduler"""
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join()
        logger.info("🛑 Enhanced Scheduler stopped")
        
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                self._check_and_deliver_pending()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"❌ Scheduler error: {e}")
                time.sleep(self.check_interval)
                
    def _check_and_deliver_pending(self):
        """Check for pending deliveries that are due and deliver them"""
        current_time = datetime.now(IST)
        
        # Get all pending deliveries that are due
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT sd.id, sd.article_id, na.title, sd.scheduled_for, sd.position
            FROM soc_deliveries sd
            JOIN news_articles na ON sd.article_id = na.id
            WHERE sd.status = 'pending' AND sd.scheduled_for <= ?
            ORDER BY sd.scheduled_for
        ''', (current_time.isoformat(),))
        
        # Note: We only select 'pending' status, not 'sending' - this prevents duplicate processing
        
        due_deliveries = cursor.fetchall()
        
        if due_deliveries:
            logger.info(f"📨 Found {len(due_deliveries)} deliveries due for processing")
            
            for delivery in due_deliveries:
                delivery_id, article_id, title, scheduled_for, position = delivery
                try:
                    self._deliver_to_soc(delivery_id, article_id, title, scheduled_for)
                except Exception as e:
                    logger.error(f"❌ Failed to deliver article {article_id}: {e}")
        
        conn.close()
        
    def _deliver_to_soc(self, delivery_id, article_id, title, scheduled_for):
        """Actually deliver the article to SOC using Weekly Cyber Watch format.

        Atomically claims the delivery row before sending — if a concurrent
        poller (or a leftover APScheduler job) tries to grab the same row,
        only one of them wins, so the SOC team never gets duplicate emails.
        On send failure the row is returned to 'pending' with retry_count
        incremented; on success it's marked 'sent'.
        """
        logger.info(f"📤 Delivering Article {article_id} to SOC: {title[:50]}...")

        conn = sqlite3.connect(db.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        cursor = conn.cursor()

        # Atomic claim: only succeeds if status is still 'pending'.
        cursor.execute(
            "UPDATE soc_deliveries SET status = 'sending' WHERE id = ? AND status = 'pending'",
            (delivery_id,),
        )
        claimed = cursor.rowcount
        conn.commit()
        if not claimed:
            logger.warning(f"⚠️ Delivery {delivery_id} already claimed by another worker - skipping")
            conn.close()
            return False

        logger.info(f"🔒 Claimed delivery {delivery_id}")

        try:
            cursor.execute(
                'SELECT na.id, na.title, na.summary, na.content, na.url, na.source, na.relevance_score '
                'FROM news_articles na WHERE na.id = ?',
                (article_id,),
            )
            article_data = cursor.fetchone()
            if not article_data:
                logger.error(f"❌ Article {article_id} not found — returning delivery to pending")
                cursor.execute(
                    "UPDATE soc_deliveries SET status = 'pending' WHERE id = ?",
                    (delivery_id,),
                )
                conn.commit()
                return False

            article = {
                'id': article_data[0],
                'title': article_data[1],
                'summary': article_data[2],
                'content': article_data[3],
                'url': article_data[4],
                'source': article_data[5],
                'relevance_score': article_data[6],
            }

            from email_system import email_system
            delivery_date = datetime.fromisoformat(scheduled_for).strftime('%Y-%m-%d')
            delivery_time = datetime.fromisoformat(scheduled_for).strftime('%I:%M %p')
            logger.info(
                f"📧 Sending SOC email for article {article_id} "
                f"scheduled for {delivery_date} at {delivery_time}"
            )

            success = False
            try:
                success = email_system.send_soc_delivery_email([article], delivery_date)
            except Exception as e:
                logger.exception(f"❌ send_soc_delivery_email raised for article {article_id}: {e}")
                success = False

            if success:
                cursor.execute(
                    "UPDATE soc_deliveries SET status = 'sent', delivery_date = ? WHERE id = ?",
                    (datetime.now(IST).isoformat(), delivery_id),
                )
                conn.commit()
                db.log_system_event(
                    'INFO',
                    f'Article {article_id} successfully delivered to SOC at scheduled time',
                    'ENHANCED_SCHEDULER',
                )
                logger.info(f"✅ Article {article_id} successfully delivered to SOC!")
                # Push the new 'sent' state to any connected dashboards so the
                # UI flips to Published immediately (no wait for the next poll).
                _push_delivery_update(article_id, delivery_id)
                return True

            # Send failed. Capture the REAL reason (e.g. SMTP auth error) so the
            # dashboard can show why the delivery isn't going out.
            reason = getattr(email_system, '_last_error', None) or "Email delivery failed"

            # Current attempt count for this row.
            cursor.execute("SELECT retry_count FROM soc_deliveries WHERE id = ?", (delivery_id,))
            prev = cursor.fetchone()
            attempts = (prev[0] if prev and prev[0] is not None else 0) + 1

            if attempts >= self.MAX_SEND_RETRIES:
                # Stop the infinite retry loop — mark it failed and surface it.
                cursor.execute(
                    "UPDATE soc_deliveries "
                    "SET status = 'failed', retry_count = ?, last_retry = ?, error_message = ? "
                    "WHERE id = ?",
                    (attempts, datetime.now(IST).isoformat(), reason[:500], delivery_id),
                )
                conn.commit()
                db.log_system_event(
                    'ERROR',
                    f'Article {article_id} delivery marked FAILED after {attempts} attempts: {reason}',
                    'ENHANCED_SCHEDULER',
                )
                logger.error(f"❌ Article {article_id} FAILED after {attempts} attempts: {reason}")
                # Push so the row flips to 'failed' in the UI immediately.
                _push_delivery_update(article_id, delivery_id)
            else:
                # Return to 'pending' so the next poll retries.
                cursor.execute(
                    "UPDATE soc_deliveries "
                    "SET status = 'pending', retry_count = ?, last_retry = ?, error_message = ? "
                    "WHERE id = ?",
                    (attempts, datetime.now(IST).isoformat(), reason[:500], delivery_id),
                )
                conn.commit()
                logger.error(
                    f"❌ Failed to deliver Article {article_id} to SOC "
                    f"(attempt {attempts}/{self.MAX_SEND_RETRIES}) — will retry. Reason: {reason}"
                )
            return False
        except Exception as e:
            # Anything else unexpected: don't leave the row stuck in 'sending'.
            logger.exception(f"❌ Unexpected error delivering {delivery_id}: {e}")
            try:
                cursor.execute(
                    "UPDATE soc_deliveries "
                    "SET status = 'pending', retry_count = retry_count + 1, "
                    "    last_retry = ?, error_message = ? "
                    "WHERE id = ?",
                    (datetime.now(IST).isoformat(), str(e)[:500], delivery_id),
                )
                conn.commit()
            except Exception:
                pass
            return False
        finally:
            conn.close()
        
    def get_status(self):
        """Get scheduler status"""
        return {
            'running': self.running,
            'check_interval': self.check_interval,
            'current_time': datetime.now(IST).isoformat()
        }
        
    def test_immediate_delivery(self, article_id):
        """Test delivery of a specific article immediately"""
        logger.info(f"🧪 Testing immediate delivery for Article {article_id}")
        
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT sd.id, sd.article_id, na.title, sd.scheduled_for, sd.position
            FROM soc_deliveries sd
            JOIN news_articles na ON sd.article_id = na.id
            WHERE sd.article_id = ? AND sd.status = 'pending'
        ''', (article_id,))
        
        delivery = cursor.fetchone()
        conn.close()
        
        if delivery:
            delivery_id, article_id, title, scheduled_for, position = delivery
            return self._deliver_to_soc(delivery_id, article_id, title, scheduled_for)
        else:
            logger.error(f"❌ No pending delivery found for Article {article_id}")
            return False

# Global scheduler instance
enhanced_scheduler = EnhancedScheduler()

def start_enhanced_scheduler():
    """Start the enhanced scheduler"""
    enhanced_scheduler.start()
    return enhanced_scheduler

if __name__ == "__main__":
    print("🚀 Starting Enhanced Scheduler...")
    scheduler = start_enhanced_scheduler()
    
    try:
        # Keep running
        while True:
            time.sleep(60)
            status = scheduler.get_status()
            print(f"⏰ Scheduler Status: {status}")
    except KeyboardInterrupt:
        print("\n🛑 Stopping Enhanced Scheduler...")
        scheduler.stop()
        print("✅ Enhanced Scheduler stopped!")