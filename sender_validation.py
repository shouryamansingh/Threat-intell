#!/usr/bin/env python3
"""
Sender Validation System
Handles the new workflow where sender validates formatted SOC reports before delivery
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import logging

import config
from config import CALLBACK_BASE_URL
from database import db, parse_keywords
from link_tokens import make_token, internal_headers
from soc_report_formatter_enhanced import enhanced_soc_formatter as soc_formatter

logger = logging.getLogger(__name__)


def _render_validation_warnings(soc_report) -> str:
    """Render the formatter's accuracy warnings as a prominent HTML block so the
    sender sees them before approving. Safe for reports that have no warnings
    attribute (e.g. the legacy backup formatter)."""
    warnings = getattr(soc_report, "validation_warnings", None) or []
    if not warnings:
        return ""
    items = "".join(f"<li style='margin:6px 0;'>{w}</li>" for w in warnings)
    return f"""
    <div style="background:#fff3cd;border:2px solid #dc3545;border-left:6px solid #dc3545;
                color:#721c24;padding:16px 20px;margin:20px 0;border-radius:8px;">
        <div style="font-weight:700;font-size:15px;margin-bottom:8px;">
            ⚠️ Accuracy checks flagged {len(warnings)} item(s) — review before approving
        </div>
        <ul style="margin:0;padding-left:22px;">{items}</ul>
    </div>
    """


class SenderValidationSystem:
    """Handles sender validation workflow for SOC reports"""

    def __init__(self):
        # No cached SMTP/email values — read live from config on every call.
        pass

    def create_smtp_connection(self):
        """Create SMTP connection (reads live config each call)."""
        try:
            import ssl
            server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
            server.starttls(context=ssl.create_default_context())
            server.login(config.SENDER_EMAIL, config.SENDER_PASSWORD)
            logger.info(f"✅ SENDER VALIDATION: SMTP connection successful to {config.SENDER_EMAIL}")
            return server
        except Exception as e:
            logger.error(f"❌ SENDER VALIDATION: Failed to create SMTP connection: {e}")
            raise
    
    def send_batch_validation_email(self, approved_articles):
        """Send one email with all approved reports for validation"""
        try:
            if not approved_articles:
                return True
            
            # Generate all SOC reports
            reports = []
            for article in approved_articles:
                soc_report = soc_formatter.format_soc_report(article)
                html_content = soc_formatter.generate_soc_report_html(soc_report)
                reports.append({
                    'article_id': article['id'],
                    'report': soc_report,
                    'html_content': html_content
                })
            
            # Create batch validation email
            subject = f"🔍 SOC Reports Validation Required - {len(reports)} Reports"
            
            email_html = self._create_batch_validation_email_template(reports)
            
            # Send email
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = config.SENDER_EMAIL
            # If VALIDATOR_EMAIL is set, route the preview there. Falling back
            # to SENDER_EMAIL means self-send — Gmail/Workspace dedupes that
            # into the Sent folder and the message never appears in Inbox.
            message["To"] = config.VALIDATOR_EMAIL or config.SENDER_EMAIL

            html_part = MIMEText(email_html, "html")
            message.attach(html_part)
            
            with self.create_smtp_connection() as server:
                refused = server.send_message(message)

            if refused:
                logger.error(
                    f"❌ Batch validation email REJECTED by SMTP for recipients: {refused}"
                )
                return False

            logger.info(f"Batch validation email sent for {len(reports)} reports to {message['To']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send batch validation email: {e}")
            return False

    def send_validation_email(self, article_id, soc_report):
        """Send formatted SOC report to sender for validation with Excel attachment"""
        try:
            from email.mime.base import MIMEBase
            from email import encoders
            import os
            
            # Generate the SOC report HTML
            html_content = soc_formatter.generate_soc_report_html(soc_report)
            
            # Strip article numbering from title (like "02. ")
            import re
            clean_title = re.sub(r'^\s*#?\s*\(?\s*\d{1,3}\)?[\.:\)]\s*', '', str(soc_report.title)).strip()
            
            # Create validation email
            subject = f'Notable Global Cyber Threat – "{clean_title}"'
            
            email_html = self._create_validation_email_template(
                article_id, soc_report, html_content
            )
            
            # Send email with Excel attachment
            message = MIMEMultipart("mixed")  # Changed from "alternative" to "mixed" for attachments
            message["Subject"] = subject
            message["From"] = config.SENDER_EMAIL
            # If VALIDATOR_EMAIL is set, route the preview there. Falling back
            # to SENDER_EMAIL means self-send — Gmail/Workspace dedupes that
            # into the Sent folder and the message never appears in Inbox.
            message["To"] = config.VALIDATOR_EMAIL or config.SENDER_EMAIL

            html_part = MIMEText(email_html, "html")
            message.attach(html_part)
            
            # Generate and attach Excel file
            excel_filename = soc_formatter.generate_excel_attachment(soc_report, f"VALIDATION-{article_id}")
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
                    
                    logger.info(f"✅ Excel attachment added to validation email: {excel_filename}")
                    
                    # Clean up Excel file after attaching
                    os.remove(excel_filename)
                except Exception as e:
                    logger.warning(f"⚠️ Could not attach Excel file to validation email: {e}")
            
            with self.create_smtp_connection() as server:
                refused = server.send_message(message)

            if refused:
                logger.error(
                    f"❌ Validation email for article {article_id} REJECTED by SMTP for recipients: {refused}"
                )
                return False

            logger.info(
                f"Validation email sent for article {article_id} to {message['To']} with Excel attachment"
            )
            
            # Notify dashboard
            try:
                import requests
                requests.post(
                    f'{config.INTERNAL_DASHBOARD_URL}/api/notify_validation',
                    json={
                        'article_id': article_id,
                        'status': 'validation_sent',
                        'message': f'Validation email sent for article {article_id}'
                    },
                    headers=internal_headers(),
                    timeout=2,
                )
            except Exception as e:
                logger.debug(f"Dashboard validation push failed for {article_id}: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send validation email for article {article_id}: {e}")
            return False
    
    def _create_batch_validation_email_template(self, reports):
        """Create the batch validation email template"""
        
        reports_html = ""
        for i, report_data in enumerate(reports):
            reports_html += f"""
            <div class="report-section">
                <h4>📄 Report #{i+1}: {report_data['report'].title}</h4>
                <div class="report-info">
                    <p><strong>Source:</strong> {report_data['report'].source_name}</p>
                    <p><strong>Article ID:</strong> {report_data['article_id']}</p>
                </div>
                {_render_validation_warnings(report_data['report'])}
                <div class="report-preview">
                    {report_data['html_content']}
                </div>
                <div class="report-actions">
                    <a href="{CALLBACK_BASE_URL}/validate_approve/{report_data['article_id']}?token={make_token('validate_approve', report_data['article_id'])}" class="btn btn-approve">
                        ✅ APPROVE REPORT #{i+1}
                    </a>
                    <a href="{CALLBACK_BASE_URL}/validate_reject_form/{report_data['article_id']}?token={make_token('validate_reject', report_data['article_id'])}" class="btn btn-reject">
                        ❌ REJECT REPORT #{i+1}
                    </a>
                </div>
            </div>
            """
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>SOC Reports Batch Validation</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 0;
                    background: #f5f5f5;
                }}
                
                .container {{
                    max-width: 1000px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 10px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                
                .header {{
                    background: linear-gradient(135deg, #c41e3a 0%, #8b0000 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                
                .content {{
                    padding: 30px;
                }}
                
                .validation-notice {{
                    background: #f0f9ff;
                    border: 2px solid #93c5fd;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                    text-align: center;
                }}
                
                .report-section {{
                    border: 1px solid #dee2e6;
                    border-radius: 8px;
                    margin: 30px 0;
                    overflow: hidden;
                }}
                
                .report-section h4 {{
                    background: #f8f9fa;
                    margin: 0;
                    padding: 15px;
                    border-bottom: 1px solid #dee2e6;
                    color: #1e40af;
                }}
                
                .report-info {{
                    padding: 15px;
                    background: #fff3cd;
                    border-bottom: 1px solid #ffeaa7;
                }}
                
                .report-preview {{
                    background: #f8f9fa;
                    padding: 20px;
                    max-height: 400px;
                    overflow-y: auto;
                    border-bottom: 1px solid #dee2e6;
                }}
                
                .report-actions {{
                    padding: 20px;
                    text-align: center;
                    background: #f0f9ff;
                }}
                
                .btn {{
                    display: inline-block;
                    padding: 12px 30px;
                    margin: 0 10px;
                    border: none;
                    border-radius: 20px;
                    text-decoration: none;
                    font-weight: 600;
                    font-size: 14px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    text-transform: uppercase;
                }}
                
                .btn-approve {{
                    background: linear-gradient(135deg, #16a34a, #10b981);
                    color: white;
                }}
                
                .btn-approve:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(22, 163, 74, 0.3);
                    color: white;
                    text-decoration: none;
                }}
                
                .btn-reject {{
                    background: linear-gradient(135deg, #dc2626, #b91c1c);
                    color: white;
                }}
                
                .btn-reject:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(220, 38, 38, 0.3);
                    color: white;
                    text-decoration: none;
                }}
                
                .info-box {{
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    color: #856404;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 8px;
                    border-left: 4px solid #ffc107;
                }}
                
                .footer {{
                    padding: 20px;
                    text-align: center;
                    color: #6c757d;
                    font-size: 14px;
                    background: #f8f9fa;
                    border-top: 1px solid #dee2e6;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 SOC Reports Batch Validation</h1>
                    <p>Centralized Event Tracking Alert</p>
                    <p><strong>Validation Date:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
                </div>
                
                <div class="content">
                    <div class="validation-notice">
                        <h3>📋 Action Required: Validate {len(reports)} SOC Reports</h3>
                        <p>Please review all formatted SOC reports below and approve or reject each one individually.</p>
                        <p><strong>Total Reports:</strong> {len(reports)} reports from manager-approved articles</p>
                    </div>
                    
                    <div class="info-box">
                        <strong>⚠️ Important:</strong> Each approved report will be sent to the SOC team on Tuesday at 11:00 AM. 
                        If you reject any report, the system will automatically re-format it and send it back for validation on the same day.
                    </div>
                    
                    {reports_html}
                </div>
                
                <div class="footer">
                    <p><strong>Automated Threat Intelligence Batch Validation System</strong></p>
                    <p>This email contains {len(reports)} reports generated from manager-approved articles.</p>
                    <p>Please validate all reports promptly to ensure timely SOC delivery.</p>
                </div>
            </div>
        </body>
        </html>
        """

    def _create_validation_email_template(self, article_id, soc_report, html_content):
        """Create the validation email template"""
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>SOC Report Validation Required</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 0;
                    background: #f5f5f5;
                }}
                
                .container {{
                    max-width: 900px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 10px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                
                .header {{
                    background: linear-gradient(135deg, #c41e3a 0%, #8b0000 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                
                .content {{
                    padding: 30px;
                }}
                
                .validation-notice {{
                    background: #f0f9ff;
                    border: 2px solid #93c5fd;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                    text-align: center;
                }}
                
                .report-preview {{
                    background: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 30px 0;
                    max-height: 500px;
                    overflow-y: auto;
                }}
                
                .actions {{
                    text-align: center;
                    padding: 30px;
                    background: #f0f9ff;
                    border-top: 1px solid #93c5fd;
                }}
                
                .btn {{
                    display: inline-block;
                    padding: 15px 40px;
                    margin: 0 15px;
                    border: none;
                    border-radius: 25px;
                    text-decoration: none;
                    font-weight: 600;
                    font-size: 16px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                
                .btn-approve {{
                    background: linear-gradient(135deg, #16a34a, #10b981);
                    color: white;
                }}
                
                .btn-approve:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(22, 163, 74, 0.3);
                    color: white;
                    text-decoration: none;
                }}
                
                .btn-reject {{
                    background: linear-gradient(135deg, #dc2626, #b91c1c);
                    color: white;
                }}
                
                .btn-reject:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(220, 38, 38, 0.3);
                    color: white;
                    text-decoration: none;
                }}
                
                .info-box {{
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    color: #856404;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 8px;
                    border-left: 4px solid #ffc107;
                }}
                
                .footer {{
                    padding: 20px;
                    text-align: center;
                    color: #6c757d;
                    font-size: 14px;
                    background: #f8f9fa;
                    border-top: 1px solid #dee2e6;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 SOC Report Validation Required</h1>
                    <p>Centralized Event Tracking Alert</p>
                    <p><strong>Validation Date:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
                </div>
                
                <div class="content">
                    <div class="validation-notice">
                        <h3>📋 Action Required: Validate SOC Report</h3>
                        <p>Please review the formatted SOC report below and approve or reject it for delivery to the SOC team.</p>
                        <p><strong>Article:</strong> {soc_report.title}</p>
                        <p><strong>Source:</strong> {soc_report.source_name}</p>
                    </div>

                    {_render_validation_warnings(soc_report)}

                    <div class="info-box">
                        <strong>⚠️ Important:</strong> This report will be sent to the SOC team ({', '.join(config.SOC_EMAIL) if isinstance(config.SOC_EMAIL, list) else config.SOC_EMAIL}) after your approval.
                        If you reject it, the system will automatically re-format the report and send it back for validation on the same day.
                    </div>
                    
                    <h4>📄 SOC Report Preview:</h4>
                    <div class="report-preview">
                        {html_content}
                    </div>
                    
                    <div class="info-box">
                        <strong>📅 Delivery Schedule:</strong> Once approved, this report will be scheduled for delivery to the SOC team 
                        on Tuesday at 11:00 AM. Each approved report will be delivered on the next available Tuesday in sequence.
                    </div>
                </div>
                
                <div class="actions">
                    <h4>🎯 Validation Decision</h4>
                    <p>Review the report above and choose your action:</p>
                    
                    <a href="{CALLBACK_BASE_URL}/validate_approve/{article_id}?token={make_token('validate_approve', article_id)}" class="btn btn-approve">
                        ✅ APPROVE REPORT
                    </a>

                    <a href="{CALLBACK_BASE_URL}/validate_reject_form/{article_id}?token={make_token('validate_reject', article_id)}" class="btn btn-reject">
                        ❌ REJECT & RE-FORMAT
                    </a>
                </div>
                
                <div class="footer">
                    <p><strong>Automated Threat Intelligence Validation System</strong></p>
                    <p>This email was generated automatically. Please validate promptly to ensure timely SOC delivery.</p>
                    <p>For technical issues, contact the system administrator.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def handle_validation_approval(self, article_id):
        """Handle sender approval of SOC report"""
        try:
            # Mark as sender-approved
            import sqlite3
            import pytz
            ist = pytz.timezone("Asia/Kolkata")
            now_ist = datetime.now(ist).isoformat()

            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()

            # Transition: manager_approved → approved (sender has validated).
            # Also flip the boolean, stamp the time, and record an audit row in
            # sender_validations so get_approved_articles_for_soc() can find it.
            cursor.execute('''
                UPDATE news_articles
                SET status = 'approved',
                    sender_validated = 1,
                    sender_validation_date = ?
                WHERE id = ?
            ''', (now_ist, article_id))

            cursor.execute('''
                INSERT INTO sender_validations (article_id, validation_type, validation_date)
                VALUES (?, 'approved', ?)
            ''', (article_id, now_ist))
            
            conn.commit()
            conn.close()
            
            # Schedule SOC delivery with transaction-based logic
            # This will handle EVERYTHING: duplicate check, position assignment, date calculation, insertion
            from scheduler import threat_scheduler
            result = threat_scheduler.schedule_soc_delivery(article_id)
            
            if result:
                logger.info(f"✅ Article {article_id} validated and scheduled for SOC delivery")
                
                # Notify dashboard
                try:
                    import requests
                    requests.post(
                        f'{config.INTERNAL_DASHBOARD_URL}/api/notify_validation',
                        json={
                            'article_id': article_id,
                            'status': 'validation_approved',
                            'message': f'Article {article_id} validated and scheduled for SOC delivery'
                        },
                        headers=internal_headers(),
                        timeout=2,
                    )

                    requests.post(
                        f'{config.INTERNAL_DASHBOARD_URL}/api/notify_delivery',
                        json={
                            'article_id': article_id,
                            'status': 'scheduled',
                            'message': f'Article {article_id} scheduled for SOC delivery'
                        },
                        headers=internal_headers(),
                        timeout=2,
                    )
                except Exception as e:
                    logger.debug(f"Dashboard delivery push failed for {article_id}: {e}")
                
                return True
            else:
                logger.warning(f"⚠️ Article {article_id} could not be scheduled (may already exist)")
                return False
            
        except Exception as e:
            logger.error(f"❌ Error handling validation approval for article {article_id}: {e}")
            return False
    
    def handle_validation_rejection(self, article_id, remarks=""):
        """Handle sender rejection of SOC report - re-format and re-send"""
        try:
            # Store rejection with remarks in database
            import sqlite3
            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()
            
            # Record the rejection with remarks
            cursor.execute('''
                INSERT INTO sender_validations (article_id, validation_type, remarks)
                VALUES (?, 'rejected', ?)
            ''', (article_id, remarks))
            
            # Get article details
            cursor.execute('''
                SELECT id, title, summary, content, url, source, relevance_score, keywords
                FROM news_articles 
                WHERE id = ?
            ''', (article_id,))
            
            article_data = cursor.fetchone()
            conn.commit()
            conn.close()
            
            if not article_data:
                logger.error(f"Article {article_id} not found for re-formatting")
                return False
            
            # Prepare article dict
            article = {
                'id': article_data[0],
                'title': article_data[1],
                'summary': article_data[2],
                'content': article_data[3],
                'url': article_data[4],
                'source': article_data[5],
                'relevance_score': float(article_data[6]) if article_data[6] else 0,
                'keywords': parse_keywords(article_data[7])
            }
            
            # Add remarks to the article for improved formatting
            if remarks:
                article['rejection_remarks'] = remarks
            
            # Re-format the report with improved formatting based on remarks
            soc_report = soc_formatter.format_soc_report(article)
            
            # Send for validation again
            success = self.send_validation_email(article_id, soc_report)
            
            if success:
                logger.info(f"Article {article_id} rejected with remarks: '{remarks}' - re-formatted and re-sent for validation")
            
            return success
            
        except Exception as e:
            logger.error(f"Error handling validation rejection for article {article_id}: {e}")
            return False

# Global instance
sender_validator = SenderValidationSystem()
