"""Database module for Threat Intelligence Automation System"""

import sqlite3
import json
import hashlib
import logging
from datetime import datetime
import pytz
from typing import List, Dict, Optional, Tuple
from config import DATABASE_PATH

logger = logging.getLogger(__name__)

# Ceiling for the SQLite -wal sidecar, applied as journal_size_limit at connect
# time. 64 MB is far above any burst this workload produces, so it never forces
# an expensive mid-write truncation — it only stops the file idling at a size a
# one-off backlog pushed it to.
WAL_SIZE_LIMIT_BYTES = 64 * 1024 * 1024


def parse_keywords(raw):
    """Read back a news_articles.keywords value.

    The reader lives next to the writer on purpose: add_news_article stores this
    column with json.dumps, so json.loads is the matching reader. Two callers
    used `eval()` instead, which happens to work on a JSON list of strings but
    is an arbitrary-code-execution path the moment anything other than our own
    fixed keyword allowlist can reach that column. Never reintroduce eval here.

    Always returns a list — a malformed or legacy value degrades to empty rather
    than breaking a delivery.
    """
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return value if isinstance(value, list) else []


class ThreatIntelDB:
    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Enable WAL journaling — allows one writer concurrent with many
        # readers (the default 'delete' mode serializes everything and
        # causes "database is locked" under load). WAL is a persistent
        # file-level setting, so once set it survives across processes.
        try:
            mode = cursor.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if mode.lower() != 'wal':
                print(f"⚠️  Could not enable WAL mode (got {mode!r}); concurrency may be limited")
        except Exception as e:
            print(f"⚠️  WAL pragma failed: {e}")
        # Give writers up to 30s to acquire the lock instead of erroring instantly
        cursor.execute("PRAGMA busy_timeout=30000")

        # Cap the WAL sidecar. Without this, -wal grows to whatever the largest
        # burst needed (a full scrape writing hundreds of rows) and then STAYS
        # that size forever — checkpointing reuses the space rather than
        # returning it. On a small cloud volume that idle file is pure waste.
        # Like journal_mode, this is persistent once set.
        try:
            cursor.execute(f"PRAGMA journal_size_limit={WAL_SIZE_LIMIT_BYTES}")
        except Exception as e:
            print(f"⚠️  journal_size_limit pragma failed: {e}")


        # News articles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS news_articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                summary TEXT,
                content TEXT,
                url TEXT UNIQUE,
                source TEXT NOT NULL,
                keywords TEXT,
                relevance_score REAL DEFAULT 0.0,
                scraped_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                published_date TIMESTAMP,
                status TEXT DEFAULT 'pending',
                sender_validated INTEGER DEFAULT 0,
                sender_validation_date TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Manager approvals table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS manager_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER NOT NULL,
                decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
                decision_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                comments TEXT,
                manager_email TEXT,
                FOREIGN KEY (article_id) REFERENCES news_articles (id)
            )
        ''')
        
        # SOC deliveries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS soc_deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER NOT NULL,
                delivery_date TIMESTAMP,
                status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'scheduled', 'cancelled')),
                delivery_method TEXT DEFAULT 'email',
                position INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scheduled_for TIMESTAMP,
                retry_count INTEGER DEFAULT 0,
                last_retry TIMESTAMP,
                error_message TEXT,
                FOREIGN KEY (article_id) REFERENCES news_articles (id)
            )
        ''')
        
        # Scraping sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scraping_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sources_scraped TEXT,
                total_articles_found INTEGER DEFAULT 0,
                total_articles_saved INTEGER DEFAULT 0,
                status TEXT DEFAULT 'completed',
                error_log TEXT,
                session_type TEXT DEFAULT 'manual' CHECK (session_type IN ('manual', 'scheduled', 'fresh'))
            )
        ''')
        
        # Scraping session articles table - tracks which articles were scraped in each session
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scraping_session_articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                article_id INTEGER NOT NULL,
                scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES scraping_sessions (id),
                FOREIGN KEY (article_id) REFERENCES news_articles (id),
                UNIQUE(session_id, article_id)
            )
        ''')
        
        # System logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_level TEXT NOT NULL,
                message TEXT NOT NULL,
                component TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        
        # Table for sender validation history and remarks
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sender_validations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER NOT NULL,
                validation_type TEXT NOT NULL CHECK (validation_type IN ('approved', 'rejected')),
                remarks TEXT,
                validation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (article_id) REFERENCES news_articles (id)
            )
        ''')
        
        # Table for duplicate prevention across weeks
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scraped_articles_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                scraped_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                url_hash TEXT NOT NULL,
                title_hash TEXT NOT NULL,
                UNIQUE(url_hash)
            )
        ''')
        
        # Activity log table (for dashboard activity tracking)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                description TEXT NOT NULL,
                article_id INTEGER,
                details TEXT,
                component TEXT
            )
        ''')

        # Profile populated by the first-time onboarding form after Firebase
        # sign-in, OR created directly by an admin for a local account.
        #   auth_provider  'firebase' (identity owned by Firebase) or 'local'
        #                  (email+password checked against password_hash here).
        #   password_hash  set only for local accounts (werkzeug hash).
        #   active         0 disables sign-in without deleting the row.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_profiles (
                uid TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                display_name TEXT,
                role TEXT,
                department TEXT,
                phone TEXT,
                notification_email TEXT,
                auth_provider TEXT DEFAULT 'firebase',
                password_hash TEXT,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Access requests: someone tried to sign in but has no account yet.
        # Filing a row here grants NOTHING — it only puts the person in front of
        # an admin, who approves (which creates the profile) or rejects.
        #   email     one row per address, so repeat attempts can't spam admins
        #   provider  how they tried to get in: 'google' | 'password' | 'form'
        #   status    pending | approved | rejected
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                display_name TEXT,
                uid TEXT,
                provider TEXT DEFAULT 'google',
                status TEXT DEFAULT 'pending',
                note TEXT,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                reviewed_by TEXT,
                granted_role TEXT
            )
        ''')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_access_requests_status '
            'ON access_requests(status)'
        )

        # Update existing tables with new columns if they don't exist
        self.update_schema()

        conn.commit()
        conn.close()
    
    def update_schema(self):
        """Update database schema to add missing columns"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Add sender_validated column to news_articles if it doesn't exist
            cursor.execute("PRAGMA table_info(news_articles)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'sender_validated' not in columns:
                cursor.execute('ALTER TABLE news_articles ADD COLUMN sender_validated INTEGER DEFAULT 0')
                print("✅ Added sender_validated column to news_articles")
            
            if 'sender_validation_date' not in columns:
                cursor.execute('ALTER TABLE news_articles ADD COLUMN sender_validation_date TIMESTAMP')
                print("✅ Added sender_validation_date column to news_articles")
            
            # Add position column to soc_deliveries if it doesn't exist
            cursor.execute("PRAGMA table_info(soc_deliveries)")
            columns = [column[1] for column in cursor.fetchall()]

            if 'position' not in columns:
                cursor.execute('ALTER TABLE soc_deliveries ADD COLUMN position INTEGER DEFAULT 0')
                print("✅ Added position column to soc_deliveries")

            # Migration: keep the soc_deliveries.status CHECK constraint in sync with
            # the statuses the delivery code actually uses. 'sending' is the transient
            # atomic-claim status the scheduler/poller sets before an email goes out; a
            # constraint that omits it makes every claim fail with an IntegrityError,
            # which silently breaks BOTH Send-now and the background poller. SQLite
            # can't ALTER a CHECK constraint, so we rebuild the table whenever the live
            # constraint is missing 'sending' (or the older 'cancelled').
            row = cursor.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='soc_deliveries'"
            ).fetchone()
            if row and row[0] and ("'cancelled'" not in row[0] or "'sending'" not in row[0]):
                print("🔧 Migrating soc_deliveries status CHECK (adding 'sending'/'cancelled')…")
                cursor.executescript("""
                    CREATE TABLE soc_deliveries_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        article_id INTEGER NOT NULL,
                        delivery_date TIMESTAMP,
                        status TEXT DEFAULT 'pending'
                            CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'scheduled', 'cancelled')),
                        delivery_method TEXT DEFAULT 'email',
                        position INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        scheduled_for TIMESTAMP,
                        retry_count INTEGER DEFAULT 0,
                        last_retry TIMESTAMP,
                        error_message TEXT,
                        FOREIGN KEY (article_id) REFERENCES news_articles (id)
                    );
                    INSERT INTO soc_deliveries_new
                        (id, article_id, delivery_date, status, delivery_method,
                         position, created_at, scheduled_for, retry_count,
                         last_retry, error_message)
                    SELECT id, article_id, delivery_date, status, delivery_method,
                           position, created_at, scheduled_for, retry_count,
                           last_retry, error_message
                    FROM soc_deliveries;
                    DROP TABLE soc_deliveries;
                    ALTER TABLE soc_deliveries_new RENAME TO soc_deliveries;
                """)
                print("✅ soc_deliveries migrated; 'sending' + 'cancelled' statuses now allowed")
            
            # Check and add session_type column to scraping_sessions
            cursor.execute("PRAGMA table_info(scraping_sessions)")
            session_columns = [column[1] for column in cursor.fetchall()]
            
            if 'session_type' not in session_columns:
                cursor.execute('ALTER TABLE scraping_sessions ADD COLUMN session_type TEXT DEFAULT "manual"')
                print("✅ Added session_type column to scraping_sessions")
            
            # Check and add new columns to soc_deliveries
            cursor.execute("PRAGMA table_info(soc_deliveries)")
            soc_columns = [column[1] for column in cursor.fetchall()]
            
            if 'scheduled_for' not in soc_columns:
                cursor.execute('ALTER TABLE soc_deliveries ADD COLUMN scheduled_for TIMESTAMP')
                print("✅ Added scheduled_for column to soc_deliveries")
            
            if 'retry_count' not in soc_columns:
                cursor.execute('ALTER TABLE soc_deliveries ADD COLUMN retry_count INTEGER DEFAULT 0')
                print("✅ Added retry_count column to soc_deliveries")
            
            if 'last_retry' not in soc_columns:
                cursor.execute('ALTER TABLE soc_deliveries ADD COLUMN last_retry TIMESTAMP')
                print("✅ Added last_retry column to soc_deliveries")
            
            if 'error_message' not in soc_columns:
                cursor.execute('ALTER TABLE soc_deliveries ADD COLUMN error_message TEXT')
                print("✅ Added error_message column to soc_deliveries")

            # RBAC: local-account + role-management columns on user_profiles.
            cursor.execute("PRAGMA table_info(user_profiles)")
            profile_columns = [column[1] for column in cursor.fetchall()]

            if 'auth_provider' not in profile_columns:
                cursor.execute("ALTER TABLE user_profiles ADD COLUMN auth_provider TEXT DEFAULT 'firebase'")
                print("✅ Added auth_provider column to user_profiles")

            if 'password_hash' not in profile_columns:
                cursor.execute('ALTER TABLE user_profiles ADD COLUMN password_hash TEXT')
                print("✅ Added password_hash column to user_profiles")

            if 'active' not in profile_columns:
                cursor.execute('ALTER TABLE user_profiles ADD COLUMN active INTEGER DEFAULT 1')
                print("✅ Added active column to user_profiles")

            conn.commit()
            
        except sqlite3.Error as e:
            print(f"Schema update error: {e}")
        finally:
            conn.close()
    
    def add_news_article(self, title: str, summary: str, content: str, url: str, 
                        source: str, keywords: List[str], relevance_score: float,
                        published_date: datetime = None) -> int:
        """Add a new news article to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO news_articles 
                (title, summary, content, url, source, keywords, relevance_score, published_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (title, summary, content, url, source, json.dumps(keywords), 
                  relevance_score, published_date))
            
            article_id = cursor.lastrowid
            conn.commit()
            return article_id
        
        except sqlite3.IntegrityError:
            # URL already exists
            return None
        finally:
            conn.close()
    
    def get_pending_articles_for_manager(self, limit: int = 10) -> List[Dict]:
        """Get top articles for manager approval"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, title, summary, content, url, source, relevance_score, scraped_date
            FROM news_articles 
            WHERE status = 'pending'
            ORDER BY relevance_score DESC, scraped_date DESC
            LIMIT ?
        ''', (limit,))
        
        articles = []
        for row in cursor.fetchall():
            articles.append({
                'id': row[0],
                'title': row[1],
                'summary': row[2],
                'content': row[3],
                'url': row[4],
                'source': row[5],
                'relevance_score': row[6],
                'scraped_date': row[7]
            })
        
        conn.close()
        return articles
    
    def record_manager_decision(self, article_id: int, decision: str, 
                              manager_email: str, comments: str = None):
        """Record manager's approval/rejection decision"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Add approval record
        cursor.execute('''
            INSERT INTO manager_approvals (article_id, decision, manager_email, comments)
            VALUES (?, ?, ?, ?)
        ''', (article_id, decision, manager_email, comments))
        
        # Update article status - FIXED WORKFLOW: Don't skip sender validation
        if decision == 'approved':
            new_status = 'manager_approved'  # Goes to sender validation next
        else:
            new_status = 'rejected'
            
        cursor.execute('''
            UPDATE news_articles SET status = ? WHERE id = ?
        ''', (new_status, article_id))
        
        # DO NOT add to SOC delivery queue yet - must go through sender validation first!
        
        conn.commit()
        conn.close()
    
    def get_manager_approved_articles_for_sender(self, limit: int = 10) -> List[Dict]:
        """Get articles approved by manager, pending sender validation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT na.id, na.title, na.summary, na.content, na.url, na.source,
                   na.keywords, na.relevance_score, na.scraped_date, na.published_date,
                   na.status, na.sender_validated, na.sender_validation_date
            FROM news_articles na
            WHERE na.status = 'manager_approved'
            ORDER BY na.relevance_score DESC, na.scraped_date DESC
        '''
        
        if limit:
            query += f' LIMIT {limit}'
            
        cursor.execute(query)
        rows = cursor.fetchall()
        
        articles = []
        for row in rows:
            articles.append({
                'id': row[0],
                'title': row[1],
                'summary': row[2],
                'content': row[3],
                'url': row[4],
                'source': row[5],
                'keywords': row[6],
                'relevance_score': row[7],
                'scraped_date': row[8],
                'published_date': row[9],
                'status': row[10],
                'sender_validated': row[11],
                'sender_validation_date': row[12]
            })
        
        conn.close()
        return articles
    
    def record_sender_validation(self, article_id: int, approved: bool, sender_email: str, comments: str = None):
        """Record sender validation decision - ONLY THEN add to SOC delivery queue"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Add sender validation record
            cursor.execute('''
                INSERT INTO sender_validations (article_id, validation_type, remarks, 
                                               validation_date)
                VALUES (?, ?, ?, datetime('now'))
            ''', (article_id, 'approved' if approved else 'rejected', comments))
            
            if approved:
                # Update article status to fully approved
                cursor.execute('''
                    UPDATE news_articles 
                    SET status = 'approved', sender_validated = 1, sender_validation_date = datetime('now')
                    WHERE id = ?
                ''', (article_id,))
                
                # Check if already scheduled for SOC delivery (PREVENT DUPLICATES)
                cursor.execute('SELECT COUNT(*) FROM soc_deliveries WHERE article_id = ?', (article_id,))
                existing_delivery = cursor.fetchone()[0]
                
                if existing_delivery == 0:
                    # NOW add to SOC delivery queue (only if not already scheduled)
                    cursor.execute('''
                        INSERT INTO soc_deliveries (article_id, status, created_at)
                        VALUES (?, 'pending', datetime('now'))
                    ''', (article_id,))
                    print(f"✅ Article {article_id} added to SOC delivery queue")
                else:
                    print(f"⚠️ Article {article_id} already scheduled for SOC delivery")
            else:
                # Update article status to rejected by sender
                cursor.execute('''
                    UPDATE news_articles SET status = 'sender_rejected' WHERE id = ?
                ''', (article_id,))
            
            conn.commit()
            return True
            
        except Exception as e:
            print(f"Error recording sender validation: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def get_approved_articles_for_soc(self, limit: int = None) -> List[Dict]:
        """Get articles approved by BOTH manager AND sender, ready for SOC delivery"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT na.id, na.title, na.summary, na.content, na.url, na.source, 
                   na.relevance_score, ma.decision_date, sd.id as delivery_id
            FROM news_articles na
            JOIN manager_approvals ma ON na.id = ma.article_id
            JOIN soc_deliveries sd ON na.id = sd.article_id
            JOIN sender_validations sv ON na.id = sv.article_id
            WHERE na.status = 'approved' 
            AND na.sender_validated = 1
            AND ma.decision = 'approved'
            AND sv.validation_type = 'approved'
            AND sd.status = 'pending'
            ORDER BY ma.decision_date ASC
        '''
        
        if limit:
            query += f' LIMIT {limit}'
        
        cursor.execute(query)
        
        articles = []
        for row in cursor.fetchall():
            articles.append({
                'id': row[0],
                'title': row[1],
                'summary': row[2],
                'content': row[3],
                'url': row[4],
                'source': row[5],
                'relevance_score': row[6],
                'approved_date': row[7],
                'delivery_id': row[8]
            })
        
        conn.close()
        return articles
    
    def mark_soc_delivery_sent(self, delivery_id: int):
        """Mark SOC delivery as sent"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE soc_deliveries 
            SET status = 'sent', delivery_date = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (delivery_id,))
        
        conn.commit()
        conn.close()
    
    def add_scraping_session(self, sources: List[str], total_found: int, 
                           total_saved: int, error_log: str = None) -> int:
        """Add a new scraping session record"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scraping_sessions 
            (sources_scraped, total_articles_found, total_articles_saved, error_log)
            VALUES (?, ?, ?, ?)
        ''', (json.dumps(sources), total_found, total_saved, error_log))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id
    
    def log_system_event(self, level: str, message: str, component: str = None, 
                        details: str = None):
        """Log system events"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO system_logs (log_level, message, component, details)
                VALUES (?, ?, ?, ?)
            ''', (level, message, component, details))
            
            conn.commit()
            conn.close()
        except Exception as e:
            # This used to print() — which, with no file handler configured,
            # went nowhere on a server. A dropped audit row is exactly the kind
            # of failure that must not be invisible, so it goes to the real log.
            logger.error(
                f"Failed to write system_logs row (level={level!r}, "
                f"component={component!r}): {e} — original message: {message}"
            )
    
    def log_activity(self, action: str, description: str, article_id: int = None, details: str = None, component: str = 'SYSTEM'):
        """Log activity for dashboard activity log"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO activity_log (action, description, article_id, details, component)
                VALUES (?, ?, ?, ?, ?)
            ''', (action, description, article_id, details, component))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(
                f"Failed to write activity_log row (action={action!r}, "
                f"component={component!r}): {e} — original description: {description}"
            )
    
    def get_statistics(self) -> Dict:
        """Get system statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total articles scraped
        cursor.execute('SELECT COUNT(*) FROM news_articles')
        stats['total_articles'] = cursor.fetchone()[0]
        
        # Articles by status
        cursor.execute('''
            SELECT status, COUNT(*) 
            FROM news_articles 
            GROUP BY status
        ''')
        stats['articles_by_status'] = dict(cursor.fetchall())
        
        # Articles delivered to SOC
        cursor.execute('''
            SELECT COUNT(*) FROM soc_deliveries WHERE status = 'sent'
        ''')
        stats['articles_delivered_to_soc'] = cursor.fetchone()[0]
        
        # Recent scraping sessions
        cursor.execute('''
            SELECT COUNT(*) FROM scraping_sessions 
            WHERE session_date >= datetime('now', '-7 days')
        ''')
        stats['recent_scraping_sessions'] = cursor.fetchone()[0]
        
        conn.close()
        return stats
    
    def cleanup_old_records(self, days: int = 90, audit_days: int = None,
                            session_days: int = None, content_days: int = None,
                            vacuum: bool = True):
        """Prune everything that grows without bound, and report what went.

        Scheduled daily by scheduler.setup_log_retention. Before that it existed
        but was never called from anywhere, so nothing in the database was ever
        pruned — and activity_log was not covered here at all.

        Four windows rather than one, because these rows are not equally
        disposable:

          days          logs and rejected articles — pure noise once read
          audit_days    who approved what and when it shipped — an audit answer,
                        kept far longer, and never swept while still in flight
          session_days  scrape bookkeeping and its per-article join rows
          content_days  the article *body* only; the row itself survives

        Also sweeps orphans. The join and audit tables reference news_articles
        and scraping_sessions but SQLite does not enforce those foreign keys by
        default, so deleting a parent used to strand its children permanently —
        which is how scraping_session_articles became the largest table in the
        database while news_articles sat at zero rows.

        Returns a dict of table → rows affected.
        """
        # Fall back to the log window for anything not explicitly given, so an
        # older caller passing only `days` still gets a full sweep.
        audit_days = days if audit_days is None else audit_days
        session_days = days if session_days is None else session_days
        content_days = days if content_days is None else content_days

        deleted = {}
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            cursor = conn.cursor()

            # Parameterised rather than %-formatted: these reach this from
            # config values, and datetime() accepts a bound modifier string
            # just as well as a literal one.
            modifier = f'-{int(days)} days'
            audit_modifier = f'-{int(audit_days)} days'
            session_modifier = f'-{int(session_days)} days'

            # ── Logs: the disposable window ─────────────────────────────────
            cursor.execute('''
                DELETE FROM news_articles
                WHERE status = 'rejected'
                AND created_at < datetime('now', ?)
            ''', (modifier,))
            deleted['news_articles_rejected'] = cursor.rowcount

            cursor.execute('''
                DELETE FROM system_logs
                WHERE timestamp < datetime('now', ?)
            ''', (modifier,))
            deleted['system_logs'] = cursor.rowcount

            # activity_log was previously unbounded — it is the dashboard's
            # feed and grows on every workflow event.
            cursor.execute('''
                DELETE FROM activity_log
                WHERE timestamp < datetime('now', ?)
            ''', (modifier,))
            deleted['activity_log'] = cursor.rowcount

            # ── Audit trail: the long window, terminal rows only ────────────
            # A delivery still pending/sending/scheduled is future work, not
            # history: it survives no matter how old it is. Sweeping one would
            # silently cancel a queued send. delivery_date is NULL until a row
            # actually goes out, hence the COALESCE onto created_at.
            cursor.execute('''
                DELETE FROM soc_deliveries
                WHERE status IN ('sent', 'failed', 'cancelled')
                AND COALESCE(delivery_date, created_at) < datetime('now', ?)
            ''', (audit_modifier,))
            deleted['soc_deliveries'] = cursor.rowcount

            cursor.execute('''
                DELETE FROM manager_approvals
                WHERE decision_date < datetime('now', ?)
            ''', (audit_modifier,))
            deleted['manager_approvals'] = cursor.rowcount

            cursor.execute('''
                DELETE FROM sender_validations
                WHERE validation_date < datetime('now', ?)
            ''', (audit_modifier,))
            deleted['sender_validations'] = cursor.rowcount

            # ── Scrape bookkeeping ──────────────────────────────────────────
            # Join rows first, then their parents: the reverse order would make
            # every one of them an orphan for the length of this function.
            cursor.execute('''
                DELETE FROM scraping_session_articles
                WHERE scraped_at < datetime('now', ?)
            ''', (session_modifier,))
            deleted['scraping_session_articles'] = cursor.rowcount

            cursor.execute('''
                DELETE FROM scraping_sessions
                WHERE session_date < datetime('now', ?)
            ''', (session_modifier,))
            deleted['scraping_sessions'] = cursor.rowcount

            # ── Orphans: children whose parent is already gone ──────────────
            # Includes anything stranded by the deletes above, plus the backlog
            # left by every delete that ran before this sweep existed.
            cursor.execute('''
                DELETE FROM scraping_session_articles
                WHERE session_id NOT IN (SELECT id FROM scraping_sessions)
                   OR article_id NOT IN (SELECT id FROM news_articles)
            ''')
            deleted['orphaned_session_articles'] = cursor.rowcount

            # A delivery whose article no longer exists can never be sent — the
            # poller would pick it up and fail on the missing join every run.
            # Status is deliberately not checked here: unlike the audit sweep
            # above, there is no future work to protect.
            cursor.execute('''
                DELETE FROM soc_deliveries
                WHERE article_id NOT IN (SELECT id FROM news_articles)
            ''')
            deleted['orphaned_deliveries'] = cursor.rowcount

            cursor.execute('''
                DELETE FROM manager_approvals
                WHERE article_id NOT IN (SELECT id FROM news_articles)
            ''')
            deleted['orphaned_approvals'] = cursor.rowcount

            cursor.execute('''
                DELETE FROM sender_validations
                WHERE article_id NOT IN (SELECT id FROM news_articles)
            ''')
            deleted['orphaned_validations'] = cursor.rowcount

            # ── Article bodies ──────────────────────────────────────────────
            # The single largest column in the schema. Blanking it keeps the
            # title, URL, score and every audit row that points at this article
            # intact — only the full scraped text goes. 0 disables.
            if int(content_days) > 0:
                cursor.execute('''
                    UPDATE news_articles
                    SET content = NULL
                    WHERE content IS NOT NULL AND content != ''
                    AND created_at < datetime('now', ?)
                ''', (f'-{int(content_days)} days',))
                deleted['article_bodies_blanked'] = cursor.rowcount

            conn.commit()
        finally:
            conn.close()

        total = sum(deleted.values())
        if total:
            # Drop the zeros — a sweep touching two tables should not print
            # eleven "0"s into the log every single night.
            summary = {k: v for k, v in deleted.items() if v}
            logger.info(f"Retention sweep affected {total} rows: {summary}")
        else:
            logger.info("Retention sweep found nothing to remove")

        # Reclaim the freed pages. SQLite hands deleted pages back to its own
        # freelist, not to the filesystem — without this the .db file only ever
        # sits at its high-water mark, and the sweep above frees space the disk
        # never sees. Gated on having actually deleted something, because
        # VACUUM rewrites the whole file and takes an exclusive lock.
        if total and vacuum:
            self.vacuum(reason='retention sweep')

        return deleted

    def vacuum(self, reason: str = 'manual'):
        """Rebuild the database file, returning freed pages to the filesystem.

        Returns bytes reclaimed (0 if it could not run). Never raises: this is
        housekeeping, and a failed VACUUM must not take down the caller — the
        nightly sweep's actual work is already committed by the time it runs.
        """
        import os
        try:
            size_before = os.path.getsize(self.db_path)
            # isolation_level=None keeps sqlite3 from opening a transaction
            # around the statement; VACUUM cannot run inside one.
            conn = sqlite3.connect(self.db_path, timeout=60, isolation_level=None)
            try:
                conn.execute("PRAGMA busy_timeout=60000")
                conn.execute("VACUUM")
            finally:
                conn.close()
            freed = size_before - os.path.getsize(self.db_path)
            if freed > 0:
                logger.info(f"VACUUM ({reason}) reclaimed {freed / 1024:.1f} KB")
            return max(freed, 0)
        except Exception as e:
            logger.warning(f"VACUUM ({reason}) failed, database left as-is: {e}")
            return 0
    
    def create_hash(self, text: str) -> str:
        """Create SHA256 hash of text for duplicate detection"""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    def is_duplicate_article(self, url: str, title: str) -> bool:
        """Check if article already exists in scraped history"""
        url_hash = self.create_hash(url)
        title_hash = self.create_hash(title.lower().strip())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check for duplicate URL or very similar title
        cursor.execute('''
            SELECT COUNT(*) FROM scraped_articles_history 
            WHERE url_hash = ? OR title_hash = ?
        ''', (url_hash, title_hash))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0
    
    def add_to_scraped_history(self, url: str, title: str, source: str):
        """Add article to scraped history for duplicate prevention"""
        url_hash = self.create_hash(url)
        title_hash = self.create_hash(title.lower().strip())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO scraped_articles_history 
                (url, title, source, url_hash, title_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, title, source, url_hash, title_hash))
            
            conn.commit()
        except sqlite3.Error as e:
            print(f"Error adding to scraped history: {e}")
        finally:
            conn.close()
    
    def log_scraping_session(self, sources: List[str], found_count: int, saved_count: int, 
                           status: str = 'completed', error_log: str = None, session_type: str = 'manual') -> int:
        """Log a scraping session with correct Asia/Kolkata timezone"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Use Asia/Kolkata timezone for session_date
            from datetime import datetime
            import pytz
            kolkata_time = datetime.now(pytz.timezone('Asia/Kolkata')).isoformat()
            
            cursor.execute('''
                INSERT INTO scraping_sessions 
                (session_date, sources_scraped, total_articles_found, total_articles_saved, status, error_log, session_type)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (kolkata_time, json.dumps(sources), found_count, saved_count, status, error_log, session_type))
            
            session_id = cursor.lastrowid
            conn.commit()
            return session_id
        
        except sqlite3.Error as e:
            print(f"Error logging scraping session: {e}")
            return None
        finally:
            conn.close()
    
    def link_articles_to_session(self, session_id: int, article_ids: List[int]) -> bool:
        """Link articles to a scraping session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            for article_id in article_ids:
                cursor.execute('''
                    INSERT OR IGNORE INTO scraping_session_articles (session_id, article_id)
                    VALUES (?, ?)
                ''', (session_id, article_id))
            
            conn.commit()
            return True
        
        except sqlite3.Error as e:
            print(f"Error linking articles to session: {e}")
            return False
        finally:
            conn.close()
    
    def get_scraping_history(self, limit: int = 20) -> List[Dict]:
        """Get scraping session history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, session_date, sources_scraped, total_articles_found, 
                   total_articles_saved, status, error_log, session_type
            FROM scraping_sessions 
            ORDER BY session_date DESC 
            LIMIT ?
        ''', (limit,))
        
        sessions = []
        for row in cursor.fetchall():
            # Format session date for display
            session_date_str = row[1]
            try:
                from datetime import datetime
                import pytz
                # Parse the datetime and ensure it's formatted properly
                if 'T' in session_date_str:  # ISO format
                    if '+' in session_date_str or session_date_str.endswith('Z'):
                        # Already has timezone info
                        dt = datetime.fromisoformat(session_date_str.replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            dt = pytz.timezone('Asia/Kolkata').localize(dt)
                        else:
                            dt = dt.astimezone(pytz.timezone('Asia/Kolkata'))
                    else:
                        # Assume it's already in Kolkata time
                        dt = datetime.fromisoformat(session_date_str)
                        dt = pytz.timezone('Asia/Kolkata').localize(dt)
                else:
                    # Standard SQL datetime format
                    dt = datetime.strptime(session_date_str, '%Y-%m-%d %H:%M:%S')
                    dt = pytz.timezone('Asia/Kolkata').localize(dt)
                
                formatted_date = dt.strftime('%Y-%m-%d %H:%M:%S %Z')
            except Exception as e:
                # Display formatting only — any unparseable stored value falls
                # back to the raw string. `except Exception` rather than a bare
                # `except:` so Ctrl-C and SystemExit still propagate. Not
                # narrowed to pytz/ValueError because `import pytz` above is
                # function-local: naming it here would break if that ever moved.
                logger.debug(f"Could not format session_date {session_date_str!r}: {e}")
                formatted_date = session_date_str  # Fallback to original

            sessions.append({
                'id': row[0],
                'session_date': formatted_date,
                'sources_scraped': json.loads(row[2]) if row[2] else [],
                'total_articles_found': row[3],
                'total_articles_saved': row[4],
                'status': row[5],
                'error_log': row[6],
                'session_type': row[7] if row[7] else 'manual'
            })
        
        conn.close()
        return sessions
    
    def get_scraping_session_details(self, session_id: int) -> Dict:
        """Get detailed information about a specific scraping session including articles"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get session info
            cursor.execute('''
                SELECT id, session_date, sources_scraped, total_articles_found, 
                       total_articles_saved, status, error_log, session_type
                FROM scraping_sessions 
                WHERE id = ?
            ''', (session_id,))
            
            session_row = cursor.fetchone()
            if not session_row:
                return None
            
            # Format session date
            session_date_str = session_row[1]
            try:
                from datetime import datetime
                import pytz
                if 'T' in session_date_str:
                    if '+' in session_date_str or session_date_str.endswith('Z'):
                        dt = datetime.fromisoformat(session_date_str.replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            dt = pytz.timezone('Asia/Kolkata').localize(dt)
                        else:
                            dt = dt.astimezone(pytz.timezone('Asia/Kolkata'))
                    else:
                        dt = datetime.fromisoformat(session_date_str)
                        dt = pytz.timezone('Asia/Kolkata').localize(dt)
                else:
                    dt = datetime.strptime(session_date_str, '%Y-%m-%d %H:%M:%S')
                    dt = pytz.timezone('Asia/Kolkata').localize(dt)
                
                formatted_date = dt.strftime('%Y-%m-%d %H:%M:%S %Z')
            except Exception as e:
                # Display formatting only — see the note in get_scraping_sessions.
                logger.debug(f"Could not format session_date {session_date_str!r}: {e}")
                formatted_date = session_date_str

            session = {
                'id': session_row[0],
                'session_date': formatted_date,
                'sources_scraped': json.loads(session_row[2]) if session_row[2] else [],
                'total_articles_found': session_row[3],
                'total_articles_saved': session_row[4],
                'status': session_row[5],
                'error_log': session_row[6],
                'session_type': session_row[7] if session_row[7] else 'manual',
                'articles': []
            }
            
            # Get articles scraped in this session
            cursor.execute('''
                SELECT na.id, na.title, na.summary, na.source, na.status, na.scraped_date,
                       ssa.scraped_at
                FROM scraping_session_articles ssa
                JOIN news_articles na ON ssa.article_id = na.id
                WHERE ssa.session_id = ?
                ORDER BY ssa.scraped_at ASC
            ''', (session_id,))
            
            for article_row in cursor.fetchall():
                article = {
                    'id': article_row[0],
                    'title': article_row[1],
                    'summary': article_row[2],
                    'source': article_row[3],
                    'status': article_row[4],
                    'scraped_date': article_row[5],
                    'session_scraped_at': article_row[6]
                }
                session['articles'].append(article)
            
            return session
        
        except sqlite3.Error as e:
            print(f"Error getting scraping session details: {e}")
            return None
        finally:
            conn.close()
    
    def get_scheduled_deliveries(self, limit: int = 50) -> List[Dict]:
        """Get all scheduled deliveries that need to be processed (only those due now)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get current time in IST
            from datetime import datetime
            import pytz
            ist_tz = pytz.timezone('Asia/Kolkata')
            current_time = datetime.now(ist_tz).isoformat()
            
            cursor.execute('''
                SELECT sd.id, sd.article_id, sd.scheduled_for, sd.status, sd.retry_count,
                       na.title, na.summary, na.content, na.url, na.source
                FROM soc_deliveries sd
                JOIN news_articles na ON sd.article_id = na.id
                WHERE sd.status IN ('pending', 'failed')
                AND sd.scheduled_for <= ?
                ORDER BY sd.scheduled_for ASC
                LIMIT ?
            ''', (current_time, limit))
            
            deliveries = []
            for row in cursor.fetchall():
                delivery = {
                    'id': row[0],
                    'article_id': row[1],
                    'scheduled_for': row[2],
                    'status': row[3],
                    'retry_count': row[4],
                    'title': row[5],
                    'summary': row[6],
                    'content': row[7],
                    'url': row[8],
                    'source': row[9]
                }
                deliveries.append(delivery)
            
            return deliveries
        
        except sqlite3.Error as e:
            print(f"Error getting scheduled deliveries: {e}")
            return []
        finally:
            conn.close()
    
    def update_delivery_status(self, delivery_id: int, status: str, error_message: str = None) -> bool:
        """Update delivery status and retry information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if status == 'failed':
                cursor.execute('''
                    UPDATE soc_deliveries 
                    SET status = ?, retry_count = retry_count + 1, 
                        last_retry = datetime('now'), error_message = ?
                    WHERE id = ?
                ''', (status, error_message, delivery_id))
            else:
                cursor.execute('''
                    UPDATE soc_deliveries 
                    SET status = ?, delivery_date = datetime('now'), error_message = ?
                    WHERE id = ?
                ''', (status, error_message, delivery_id))
            
            conn.commit()
            return True
        
        except sqlite3.Error as e:
            print(f"Error updating delivery status: {e}")
            return False
        finally:
            conn.close()
    
    def schedule_delivery(self, article_id: int, scheduled_for: datetime, position: int = 0) -> int:
        """Schedule a delivery for a specific time"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO soc_deliveries 
                (article_id, scheduled_for, status, position, created_at)
                VALUES (?, ?, 'pending', ?, datetime('now'))
            ''', (article_id, scheduled_for.isoformat(), position))
            
            delivery_id = cursor.lastrowid
            conn.commit()
            return delivery_id
        
        except sqlite3.Error as e:
            print(f"Error scheduling delivery: {e}")
            return None
        finally:
            conn.close()
    
    # ─── User profile (onboarding) ──────────────────────────────
    def get_user_profile(self, uid: str):
        """Return the user_profiles row for a Firebase uid, or None."""
        if not uid:
            return None
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                'SELECT uid, email, display_name, role, department, phone, '
                'notification_email, auth_provider, active, '
                'created_at, updated_at, last_login '
                'FROM user_profiles WHERE uid = ?',
                (uid,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def touch_user_login(self, uid: str):
        """Bump last_login for a known user. Silently no-op if the row doesn't exist."""
        if not uid:
            return
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE user_profiles SET last_login = CURRENT_TIMESTAMP WHERE uid = ?",
                (uid,),
            )
            conn.commit()
        finally:
            conn.close()

    def upsert_user_profile(self, uid: str, email: str, display_name: str,
                            role: str = None, department: str = None,
                            phone: str = None, notification_email: str = None):
        """Insert a fresh profile or update the editable fields if one exists."""
        if not uid or not email:
            raise ValueError("uid and email are required to save a profile")
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('''
                INSERT INTO user_profiles
                    (uid, email, display_name, role, department, phone, notification_email,
                     created_at, updated_at, last_login)
                VALUES (?, ?, ?, ?, ?, ?, ?,
                        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(uid) DO UPDATE SET
                    email              = excluded.email,
                    display_name       = excluded.display_name,
                    role               = excluded.role,
                    department         = excluded.department,
                    phone              = excluded.phone,
                    notification_email = excluded.notification_email,
                    updated_at         = CURRENT_TIMESTAMP
            ''', (uid, email, display_name, role, department, phone, notification_email))
            conn.commit()
        finally:
            conn.close()

    # ─── RBAC: local accounts & role management ─────────────────
    @staticmethod
    def local_uid_for(email: str) -> str:
        """Deterministic uid for a local (non-Firebase) account."""
        return "local:" + (email or "").strip().lower()

    def get_user_profile_by_email(self, email: str):
        """Return the profile whose email matches (case-insensitive), or None."""
        email = (email or "").strip().lower()
        if not email:
            return None
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                'SELECT uid, email, display_name, role, department, phone, '
                'notification_email, auth_provider, active, '
                'created_at, updated_at, last_login '
                'FROM user_profiles WHERE LOWER(email) = ?',
                (email,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def list_users(self):
        """All user profiles, for the admin Users & Roles panel. Never returns
        the password hash."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                'SELECT uid, email, display_name, role, department, '
                'auth_provider, active, created_at, last_login '
                'FROM user_profiles ORDER BY LOWER(email)'
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def create_local_user(self, email: str, password: str, display_name: str,
                          role: str, department: str = None):
        """Create a local email+password account. Returns its uid.

        Raises ValueError if the email is already taken."""
        from werkzeug.security import generate_password_hash
        email = (email or "").strip().lower()
        if not email or not password:
            raise ValueError("email and password are required")
        uid = self.local_uid_for(email)
        pw_hash = generate_password_hash(password)
        conn = sqlite3.connect(self.db_path)
        try:
            if conn.execute('SELECT 1 FROM user_profiles WHERE LOWER(email) = ?',
                            (email,)).fetchone():
                raise ValueError("A user with that email already exists")
            conn.execute('''
                INSERT INTO user_profiles
                    (uid, email, display_name, role, department,
                     auth_provider, password_hash, active,
                     created_at, updated_at, last_login)
                VALUES (?, ?, ?, ?, ?, 'local', ?, 1,
                        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (uid, email, display_name or email.split("@")[0], role, department, pw_hash))
            conn.commit()
            return uid
        finally:
            conn.close()

    def verify_local_user(self, email: str, password: str):
        """Check a local account's credentials. Returns the profile dict on
        success (without the hash), or None on any failure — unknown email,
        wrong password, disabled account, or a Firebase-only account."""
        from werkzeug.security import check_password_hash
        email = (email or "").strip().lower()
        if not email or not password:
            return None
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                'SELECT * FROM user_profiles WHERE LOWER(email) = ?', (email,)
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        row = dict(row)
        if row.get("auth_provider") != "local" or not row.get("password_hash"):
            return None
        if not int(row.get("active", 1)):
            return None
        if not check_password_hash(row["password_hash"], password):
            return None
        row.pop("password_hash", None)
        return row

    def set_user_role(self, uid: str, role: str):
        """Change a user's role. No-op if the uid doesn't exist."""
        if not uid:
            return
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE user_profiles SET role = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE uid = ?",
                (role, uid),
            )
            conn.commit()
        finally:
            conn.close()

    def set_user_active(self, uid: str, active: bool):
        if not uid:
            return
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE user_profiles SET active = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE uid = ?",
                (1 if active else 0, uid),
            )
            conn.commit()
        finally:
            conn.close()

    def set_local_password(self, uid: str, password: str):
        """Reset the password on a local account. Raises for non-local rows."""
        from werkzeug.security import generate_password_hash
        if not uid or not password:
            raise ValueError("uid and password are required")
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT auth_provider FROM user_profiles WHERE uid = ?", (uid,)
            ).fetchone()
            if not row:
                raise ValueError("No such user")
            if row[0] != "local":
                raise ValueError("Password can only be set on local accounts")
            conn.execute(
                "UPDATE user_profiles SET password_hash = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE uid = ?",
                (generate_password_hash(password), uid),
            )
            conn.commit()
        finally:
            conn.close()

    def delete_user(self, uid: str):
        if not uid:
            return
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM user_profiles WHERE uid = ?", (uid,))
            conn.commit()
        finally:
            conn.close()

    def list_access_control_log(self, limit: int = 200):
        """The access-control audit trail: every role change, account created /
        disabled / deleted, password reset and access-request decision.

        These rows are written by web_dashboard under the ACCESS_CONTROL
        component. Read-only — nothing in the app edits or deletes them, so the
        trail stays trustworthy."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT id, timestamp, log_level, message FROM system_logs "
                "WHERE component = 'ACCESS_CONTROL' ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def count_admins(self, exclude_uid: str = None) -> int:
        """How many *active* admins exist, optionally ignoring one uid.

        Used to refuse the last-admin demotion/deactivation/deletion, which
        would otherwise lock everyone out of user management."""
        conn = sqlite3.connect(self.db_path)
        try:
            sql = ("SELECT COUNT(*) FROM user_profiles "
                   "WHERE LOWER(role) = 'admin' AND active = 1")
            params = []
            if exclude_uid:
                sql += " AND uid != ?"
                params.append(exclude_uid)
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()

    # ─── Access requests (self-service onboarding) ──────────────
    def record_access_request(self, email: str, display_name: str = None,
                              uid: str = None, provider: str = "google",
                              note: str = None) -> dict:
        """File (or re-open) a pending access request for someone with no account.

        Returns a dict with an `outcome` describing what happened, so the caller
        can tell the person something truthful:
            submitted       — a new pending request is now waiting for an admin
            already_pending — they already asked; we did not create a duplicate
            exists_active   — they already have a working account
            exists_inactive — account exists but is disabled; admin must re-enable

        Never grants access. `notify` in the return says whether an admin should
        actually be pinged (False for duplicates, so retries can't spam)."""
        email = (email or "").strip().lower()
        if not email:
            raise ValueError("email is required")
        display_name = (display_name or email.split("@")[0])[:200]

        profile = self.get_user_profile_by_email(email)
        if profile:
            active = int(profile.get("active", 1) or 0)
            return {
                "outcome": "exists_active" if active else "exists_inactive",
                "notify": False,
                "request": None,
            }

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            existing = conn.execute(
                "SELECT * FROM access_requests WHERE LOWER(email) = ?", (email,)
            ).fetchone()
            if existing and existing["status"] == "pending":
                return {
                    "outcome": "already_pending",
                    "notify": False,
                    "request": dict(existing),
                }
            # New request, or re-opening one that was previously reviewed.
            conn.execute('''
                INSERT INTO access_requests
                    (email, display_name, uid, provider, status, note, requested_at)
                VALUES (?, ?, ?, ?, 'pending', ?, CURRENT_TIMESTAMP)
                ON CONFLICT(email) DO UPDATE SET
                    display_name = excluded.display_name,
                    uid          = COALESCE(excluded.uid, access_requests.uid),
                    provider     = excluded.provider,
                    status       = 'pending',
                    note         = excluded.note,
                    requested_at = CURRENT_TIMESTAMP,
                    reviewed_at  = NULL,
                    reviewed_by  = NULL,
                    granted_role = NULL
            ''', (email, display_name, uid, provider, (note or None)))
            conn.commit()
            row = conn.execute(
                "SELECT * FROM access_requests WHERE LOWER(email) = ?", (email,)
            ).fetchone()
            return {"outcome": "submitted", "notify": True, "request": dict(row)}
        finally:
            conn.close()

    def list_access_requests(self, status: str = None, limit: int = 100):
        """Access requests, newest activity first. `status` filters to one state."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            if status:
                rows = conn.execute(
                    "SELECT * FROM access_requests WHERE status = ? "
                    "ORDER BY COALESCE(reviewed_at, requested_at) DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM access_requests "
                    "ORDER BY COALESCE(reviewed_at, requested_at) DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def count_pending_access_requests(self) -> int:
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM access_requests WHERE status = 'pending'"
            ).fetchone()[0]
        finally:
            conn.close()

    def approve_access_request(self, req_id: int, role: str, reviewer_email: str,
                               password: str = None, department: str = None) -> dict:
        """Approve a pending request and provision the account in one transaction.

        Two shapes of account come out of this:
          • the requester signed in with Google, so we know their verified
            Firebase uid → provision a firebase-backed profile keyed to it and
            they are in on their next sign-in, no password needed;
          • no verified uid (they used the request form) → a local account, so
            the admin must supply a starting password.

        Raises ValueError with a user-facing message on any refusal."""
        from werkzeug.security import generate_password_hash
        if not req_id:
            raise ValueError("Request id is required")
        role = (role or "").strip().lower()

        # isolation_level=None → we drive BEGIN/COMMIT/ROLLBACK ourselves.
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            # BEGIN IMMEDIATE takes the write lock up front, so two admins
            # clicking Approve at the same moment can't both provision.
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM access_requests WHERE id = ?", (req_id,)
            ).fetchone()
            if not row:
                raise ValueError("That request no longer exists")
            req = dict(row)
            if req["status"] != "pending":
                raise ValueError("This request has already been reviewed")

            email = (req["email"] or "").strip().lower()
            existing = conn.execute(
                "SELECT uid, active FROM user_profiles WHERE LOWER(email) = ?", (email,)
            ).fetchone()

            if existing:
                # Provisioned out-of-band since they asked — re-enable and
                # set the role rather than creating a duplicate row.
                uid = existing["uid"]
                conn.execute(
                    "UPDATE user_profiles SET role = ?, active = 1, "
                    "updated_at = CURRENT_TIMESTAMP WHERE uid = ?",
                    (role, uid),
                )
                created = False
            elif req.get("uid"):
                # Verified Firebase identity: no password lives on our side.
                uid = req["uid"]
                conn.execute('''
                    INSERT INTO user_profiles
                        (uid, email, display_name, role, department,
                         auth_provider, active, created_at, updated_at, last_login)
                    VALUES (?, ?, ?, ?, ?, 'firebase', 1,
                            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (uid, email, req.get("display_name") or email.split("@")[0],
                      role, department))
                created = True
            else:
                if not password:
                    raise ValueError(
                        "This request has no verified Google identity, so a "
                        "starting password is required to create the account"
                    )
                uid = self.local_uid_for(email)
                conn.execute('''
                    INSERT INTO user_profiles
                        (uid, email, display_name, role, department,
                         auth_provider, password_hash, active,
                         created_at, updated_at, last_login)
                    VALUES (?, ?, ?, ?, ?, 'local', ?, 1,
                            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (uid, email, req.get("display_name") or email.split("@")[0],
                      role, department, generate_password_hash(password)))
                created = True

            conn.execute(
                "UPDATE access_requests SET status = 'approved', "
                "reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ?, granted_role = ? "
                "WHERE id = ?",
                (reviewer_email, role, req_id),
            )
            conn.commit()
            return {"uid": uid, "email": email, "role": role, "created": created}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def reject_access_request(self, req_id: int, reviewer_email: str,
                              note: str = None) -> dict:
        """Mark a pending request rejected, keeping an optional reason."""
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM access_requests WHERE id = ?", (req_id,)
            ).fetchone()
            if not row:
                raise ValueError("That request no longer exists")
            if row["status"] != "pending":
                raise ValueError("This request has already been reviewed")
            conn.execute(
                "UPDATE access_requests SET status = 'rejected', note = ?, "
                "reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ?",
                ((note or None), reviewer_email, req_id),
            )
            conn.commit()
            return {"email": row["email"]}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def ensure_default_admin(self, email: str, password: str, display_name: str = None):
        """Seed a local admin account on a genuinely empty database, so a fresh
        install is usable out of the box.

        Only seeds when NO account exists at all. It used to seed whenever this
        particular address was absent, which meant deleting the default admin
        resurrected it — with its default password — on the very next restart.
        A deliberate deletion has to stay deleted, and any surviving account can
        create replacements, so an empty table is the only safe trigger.
        """
        email = (email or "").strip().lower()
        if not email or not password:
            return
        conn = sqlite3.connect(self.db_path)
        try:
            existing = conn.execute("SELECT COUNT(*) FROM user_profiles").fetchone()[0]
        finally:
            conn.close()
        if existing:
            return
        try:
            self.create_local_user(
                email=email,
                password=password,
                display_name=display_name or "Threat Intelligence Admin",
                role="admin",
                department="Security",
            )
            print(f"✅ Seeded default local admin account: {email}")
        except ValueError:
            pass

    def cleanup_old_scraped_history(self, days: int = 30):
        """Clean up old scraped history (keep last 30 days by default)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM scraped_articles_history 
            WHERE scraped_date < datetime('now', '-{} days')
        '''.format(days))
        
        conn.commit()
        conn.close()


# Create global database instance
db = ThreatIntelDB()

