"""SUPER SIMPLE Email system - NO fancy formatting"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from typing import List, Dict
import re
import logging

import config
from config import CALLBACK_BASE_URL, ENFORCE_NUMBERING_1_TO_10
from database import db
from link_tokens import make_token

# This module otherwise reports progress with print(), which only reaches the
# console. Swallowed-exception detail belongs in the log file that log_setup
# configures, so it survives to be read after the fact.
logger = logging.getLogger(__name__)


class EmailSystem:
    def __init__(self):
        # No cached SMTP settings — read at every connection so admin
        # panel changes apply immediately without restart.
        self._last_error = None  # Most recent send failure message (for UI surfacing)

    def create_smtp_connection(self):
        """Create and return SMTP connection (reads live config each call)."""
        try:
            server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
            server.starttls(context=ssl.create_default_context())
            server.login(config.SENDER_EMAIL, config.SENDER_PASSWORD)
            return server
        except Exception as e:
            db.log_system_event('ERROR', f'Failed to create SMTP connection: {str(e)}', 'EMAIL_SYSTEM')
            raise
    
    def _strip_leading_numbering(self, title: str) -> str:
        """Remove any existing leading numbering like '#01.', '01.', '1) ', etc."""
        if not title:
            return title
        try:
            # Remove patterns like '#01. ', '01. ', '1. ', '1) ', '(1) '
            title = re.sub(r'^\s*#?\s*\(?\s*\d{1,2}\)?[\.:\)]\s*', '', str(title)).strip()
        except Exception:
            pass
        return title
    
    def clean_summary(self, summary):
        """Clean summary text and create proper 2-3 line authentic summary"""
        if not summary:
            return "No summary available"
        
        # STEP 1: Remove ALL HTML content aggressively
        import re
        from bs4 import BeautifulSoup
        
        try:
            # Parse with BeautifulSoup to handle HTML properly
            soup = BeautifulSoup(summary, 'html.parser')
            
            # Remove ALL problematic elements
            for tag in soup(['img', 'figure', 'picture', 'svg', 'iframe', 'video', 'audio', 'script', 'style']):
                tag.decompose()
            
            # Remove divs with IDs that contain junk
            for div in soup.find_all('div'):
                div.decompose()
            
            # Get clean text
            summary = soup.get_text(separator=' ', strip=True)
        except Exception as e:
            # Fall through to the regex cleaning below, which handles the same
            # job less precisely. `summary` is deliberately left as-is.
            logger.debug(f"BeautifulSoup cleaning failed, using regex path: {e}")
        
        # STEP 2: Aggressive regex cleaning
        summary = re.sub(r'<[^>]*>', '', summary)  # Remove ALL HTML tags
        summary = re.sub(r'&[a-zA-Z0-9#]+;', ' ', summary)  # Remove HTML entities
        summary = re.sub(r'\[image[^\]]*\]', '', summary, flags=re.IGNORECASE)  # Image references
        summary = re.sub(r'image\s*:\s*[^\s]+', '', summary, flags=re.IGNORECASE)  # Image URLs
        summary = re.sub(r'src\s*=\s*["\'][^"\']*["\']', '', summary, flags=re.IGNORECASE)  # Image sources
        summary = re.sub(r'<div[^>]*>.*?</div>', '', summary, flags=re.IGNORECASE)  # Any remaining divs
        
        # STEP 3: Remove common junk patterns
        summary = re.sub(r'remove_no_follow', '', summary, flags=re.IGNORECASE)
        summary = re.sub(r'grid\s+gri[a-z]*', '', summary, flags=re.IGNORECASE)
        summary = re.sub(r'class\s*=\s*["\'][^"\']*["\']', '', summary)
        summary = re.sub(r'id\s*=\s*["\'][^"\']*["\']', '', summary)
        
        # STEP 4: Clean up whitespace and format
        summary = ' '.join(summary.split())  # Normalize whitespace
        summary = summary.strip()
        
        # STEP 5: If still contains HTML-like content or is too short, return default
        if len(summary) < 10 or '<' in summary or '>' in summary or 'div' in summary.lower():
            return "Summary not available - please check original article for details"
        
        # STEP 6: Create proper 2-3 line summary
        return self.create_concise_summary(summary)
    
    def create_concise_summary(self, text):
        """Create a concise 2-3 line summary from the text with enhanced authenticity"""
        if not text or len(text.strip()) < 20:
            return "Summary not available - please check original article for details"
        
        # Clean and process text first
        clean_text = self._clean_text_content(text)
        
        # Split into sentences
        sentences = re.split(r'[.!?]+', clean_text)
        clean_sentences = []
        
        for sentence in sentences:
            sentence = sentence.strip()
            # Enhanced filtering for more authentic content
            if (len(sentence) > 25 and 
                not any(junk in sentence.lower() for junk in [
                    'http', 'www.', 'click here', 'read more', 'continue reading',
                    'subscribe', 'newsletter', 'follow us', 'share this', 'comment',
                    'advertisement', 'sponsored', 'related articles'
                ]) and
                not sentence.isupper() and  # Avoid all-caps
                self._contains_meaningful_content(sentence)):
                clean_sentences.append(sentence)
        
        if not clean_sentences:
            return "Summary not available - please check original article for details"
        
        # Prioritize sentences with threat intelligence keywords
        prioritized_sentences = self._prioritize_threat_sentences(clean_sentences)
        
        # Take first 2-3 most relevant sentences
        selected_sentences = prioritized_sentences[:3]
        
        # Join and ensure proper punctuation
        summary = '. '.join(selected_sentences)
        if not summary.endswith('.'):
            summary += '.'
        
        # Limit to reasonable length (2-3 lines = ~200-300 characters)
        if len(summary) > 300:
            # Find a good breaking point
            truncated = summary[:300]
            last_period = truncated.rfind('.')
            if last_period > 200:
                summary = truncated[:last_period + 1]
            else:
                summary = truncated + "..."
        
        return summary if summary and len(summary) > 30 else "Threat intelligence report requiring detailed analysis for organizational security impact assessment."
    
    def _clean_text_content(self, text):
        """Clean text content for better processing"""
        # Remove extra whitespace and normalize
        text = ' '.join(text.split())
        
        # Remove common web artifacts
        text = re.sub(r'(Posted by|Written by|By:|Author:)[^.]*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'(Tags:|Categories:|Filed under:)[^.]*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\[.*?\]', '', text)  # Remove bracketed content
        text = re.sub(r'\(.*?\)', '', text)  # Remove parenthetical content if too long
        
        return text.strip()
    
    def _contains_meaningful_content(self, sentence):
        """Check if sentence contains meaningful threat intelligence content"""
        threat_indicators = [
            'vulnerability', 'exploit', 'malware', 'ransomware', 'attack', 'threat',
            'security', 'breach', 'compromise', 'exposure', 'risk', 'patch',
            'cve', 'critical', 'urgent', 'discovered', 'detected', 'identified',
            'researchers', 'analysts', 'impact', 'affected', 'targeted'
        ]
        
        sentence_lower = sentence.lower()
        return any(indicator in sentence_lower for indicator in threat_indicators)
    
    def _prioritize_threat_sentences(self, sentences):
        """Prioritize sentences based on threat intelligence relevance"""
        scored_sentences = []
        
        for sentence in sentences:
            score = 0
            sentence_lower = sentence.lower()
            
            # Score based on threat intelligence keywords
            high_priority_words = ['critical', 'urgent', 'zero-day', 'exploit', 'vulnerability', 'cve']
            medium_priority_words = ['malware', 'ransomware', 'attack', 'threat', 'security', 'breach']
            
            for word in high_priority_words:
                if word in sentence_lower:
                    score += 3
            
            for word in medium_priority_words:
                if word in sentence_lower:
                    score += 1
            
            # Bonus for specific technical terms
            if re.search(r'CVE-\d{4}-\d+', sentence, re.IGNORECASE):
                score += 5
            
            scored_sentences.append((score, sentence))
        
        # Sort by score (descending) and return sentences
        scored_sentences.sort(key=lambda x: x[0], reverse=True)
        return [sentence for score, sentence in scored_sentences]
    
    def generate_manager_approval_email(self, articles: List[Dict]) -> str:
        """Generate SUPER SIMPLE email with ENFORCED 1-10 numbering - NO page breaks, NO fancy formatting"""
        
        # ENFORCE 1-10 NUMBERING: Limit articles to exactly 10 if more are provided
        if ENFORCE_NUMBERING_1_TO_10:
            articles = articles[:config.MAX_NEWS_TO_MANAGER]  # Take only first N articles
        
        # Deployment accent colour. Was a hardcoded company navy in six places
        # below; email clients need a literal hex, so it is interpolated rather
        # than referenced as a CSS variable.
        brand = config.BRAND_COLOR

        # Start with basic email
        email_body = f"""
<html>
<body style="font-family: Arial; font-size: 14px; line-height: 1.4; max-width: 800px; margin: 0 auto;">

<h1 style="color: {brand}; text-align: center;">🛡️ Weekly Cyber Watch</h1>
<h2 style="color: #64748b; text-align: center;">Centralized Event Tracking & Management</h2>
<p style="text-align: center; color: #64748b;"><strong>Report Date:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>

<div style="background: #f8fafc; padding: 20px; margin: 20px 0; border-radius: 8px;">
    <h3 style="color: {brand};">📋 Executive Summary</h3>
    <p>Our system identified <strong>{len(articles)}</strong> cybersecurity articles (numbered 1-{len(articles)}) requiring your approval.</p>
    <p style="background: #fef3c7; padding: 10px; border-radius: 4px; color: #92400e;"><strong>⚠️ Action Required:</strong> Please review each article numbered 1-{len(articles)} and click APPROVE or REJECT</p>
            </div>
            
<hr style="border: 1px solid #e5e7eb; margin: 30px 0;">

"""
        
        # Add each article SIMPLY - NO complex layout, ENFORCED 1-10 numbering
        for i, article in enumerate(articles, 1):
            # Use actual article content for summary, not generic summary
            article_summary = article.get('summary', '') or article.get('content', '')
            clean_summary = self.clean_summary(article_summary)

            # Ensure title doesn't already contain numbering to avoid "01. 01." duplication
            safe_title = self._strip_leading_numbering(article.get('title', ''))
            
            # Get keywords simply
            keywords = ""
            if article.get('keywords'):
                keywords = ", ".join(article['keywords'][:5])  # Just 5 keywords
            
            email_body += f"""
<div style="border: 2px solid #e5e7eb; margin: 20px 0; padding: 20px; border-radius: 8px; background: white;">
    
    <h3 style="color: {brand}; margin: 0 0 10px 0;">{i}. {safe_title}</h3>
    
    <p style="margin: 5px 0; color: #64748b;">
                            <strong>Source:</strong> {article['source']} | 
        <strong>Score:</strong> {article['relevance_score']} | 
        <a href="{article['url']}" target="_blank" style="color: {brand};">View Original</a>
    </p>
    
    <div style="background: #f1f5f9; padding: 15px; margin: 15px 0; border-radius: 6px;">
        <strong style="color: {brand};">📄 Summary:</strong><br>
        {clean_summary}
                    </div>
                    
    {f'<p style="margin: 10px 0;"><strong style="color: {brand};">Keywords:</strong> {keywords}</p>' if keywords else ''}
                        
    <div style="text-align: center; margin: 20px 0; padding: 15px 0; border-top: 1px solid #e5e7eb;">
        <a href="{CALLBACK_BASE_URL}/approve/{article['id']}?token={make_token('approve', article['id'])}" style="background: #16a34a; color: white; padding: 12px 25px; text-decoration: none; border-radius: 6px; margin: 0 10px; font-weight: bold; display: inline-block;">✅ APPROVE</a>
        <a href="{CALLBACK_BASE_URL}/reject/{article['id']}?token={make_token('reject', article['id'])}" style="background: #dc2626; color: white; padding: 12px 25px; text-decoration: none; border-radius: 6px; margin: 0 10px; font-weight: bold; display: inline-block;">❌ REJECT</a>
                    </div>
                    
                </div>
            """
        
        email_body += f"""
<hr style="border: 1px solid #e5e7eb; margin: 30px 0;">

<div style="text-align: center; color: #64748b; padding: 20px;">
    <p><strong>🔐 Security Notice:</strong> This report contains sensitive information.</p>
    <p><strong>📧 System:</strong> Weekly Cyber Watch | <strong>📅 Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>

        </body>
        </html>
        """
        
        return email_body
    
    def send_manager_approval_email(self, articles: List[Dict]) -> bool:
        """Send approval email to manager (NO Excel attachments)"""
        try:
            if not articles:
                print("❌ No articles to send to manager")
                return False
            
            sender = config.SENDER_EMAIL
            recipient = config.MANAGER_EMAIL
            print(f"📧 Preparing to send {len(articles)} articles from {sender} -> {recipient} via {config.SMTP_SERVER}:{config.SMTP_PORT}", flush=True)
            print(f"📧 Article IDs: {[a['id'] for a in articles]}", flush=True)

            # Create message (simple alternative, no attachments)
            message = MIMEMultipart("alternative")
            message["Subject"] = f"Weekly Cyber Watch Report - {len(articles)} Articles ({datetime.now().strftime('%Y-%m-%d')})"
            message["From"] = sender
            message["To"] = recipient

            # Generate simple HTML content
            html_content = self.generate_manager_approval_email(articles)

            # Attach HTML only
            html_part = MIMEText(html_content, "html")
            message.attach(html_part)

            # Send email
            with self.create_smtp_connection() as server:
                server.send_message(message)

            print(f"✅ Manager email sent successfully to {recipient} ({len(articles)} articles)", flush=True)
            self._last_error = None
            return True

        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            print(f"❌ Manager email failed: {err}", flush=True)
            db.log_system_event('ERROR', f'Manager email send failed: {err}', 'EMAIL_SYSTEM')
            self._last_error = err
            return False
    
    def send_soc_delivery_email(self, articles: List[Dict], delivery_date: str) -> bool:
        """Send RED HEADER Weekly Cyber Watch report to SOC team - YOUR ORIGINAL FORMAT"""
        try:
            if not articles:
                return False
            
            # Create message with Notable Global Cyber Threat title (use "mixed" for attachments)
            message = MIMEMultipart("mixed")
            # Remove numbering (e.g., "01. ", "02. ") from title for subject
            clean_title = re.sub(r'^\d+\.\s*', '', articles[0]['title'])
            message["Subject"] = f"Notable Global Cyber Threat – \"{clean_title}\""
            message["From"] = config.SENDER_EMAIL
            message["To"] = config.SOC_EMAIL
            # Add CC recipients (read live)
            soc_cc = config.SOC_EMAIL_CC
            if soc_cc:
                message["Cc"] = ", ".join(soc_cc)
            
            # Generate SOC report using YOUR ORIGINAL SOC FORMATTER
            from soc_report_formatter_enhanced import enhanced_soc_formatter as soc_formatter
            import os
            
            # Convert each article to a structured SOC report
            soc_reports = []
            excel_files = []
            
            for article in articles:
                # Ensure proper keyword format
                if isinstance(article.get('keywords'), str):
                    article['keywords'] = article['keywords'].split(',') if article['keywords'] else []
                elif not article.get('keywords'):
                    article['keywords'] = []
                
                soc_report = soc_formatter.format_soc_report(article)
                
                # Skip if content quality is too low (enhanced formatter returns None)
                if soc_report is None:
                    print(f"   ⚠️ Skipping article due to low content quality: {article.get('title', 'Unknown')[:50]}...")
                    continue
                
                soc_reports.append(soc_report)
                
                # Generate Excel file for this report
                excel_filename = soc_formatter.generate_excel_attachment(soc_report, f"TI-{article.get('id', 1)}")
                if excel_filename:
                    excel_files.append(excel_filename)
            
            # Generate HTML for each report using YOUR ORIGINAL FORMAT
            full_html_content = ""
            for report in soc_reports:
                report_html = soc_formatter.generate_soc_report_html(report)
                full_html_content += report_html
            
            # Attach HTML
            html_part = MIMEText(full_html_content, "html")
            message.attach(html_part)
            
            # Attach Excel files
            for excel_file in excel_files:
                if os.path.exists(excel_file):
                    with open(excel_file, 'rb') as f:
                        excel_attachment = MIMEBase('application', 'vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                        excel_attachment.set_payload(f.read())
                        encoders.encode_base64(excel_attachment)
                        excel_attachment.add_header(
                            'Content-Disposition',
                            'attachment',
                            filename=os.path.basename(excel_file)
                        )
                        message.attach(excel_attachment)
                    
                    # Clean up Excel file after attaching. Already read into the
                    # message, so a failure here only leaves a temp file behind —
                    # worth a log line, never worth losing the email over.
                    try:
                        os.remove(excel_file)
                    except OSError as e:
                        logger.debug(f"Could not remove {excel_file}: {e}")
            
            # Send email
            with self.create_smtp_connection() as server:
                server.send_message(message)

            self._last_error = None
            return True

        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            self._last_error = err  # surfaced to the scheduler / dashboard
            print(f"❌ SOC email failed: {err}")
            try:
                from database import db as _db
                _db.log_system_event('ERROR', f'SOC email send failed: {err}', 'EMAIL_SYSTEM')
            except Exception:
                pass
            return False
    

# Create global instance
email_system = EmailSystem()
