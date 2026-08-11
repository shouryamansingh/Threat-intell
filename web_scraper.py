"""Web scraping module for Threat Intelligence Automation System"""

import requests
import feedparser
import json
import re
from datetime import datetime, timedelta
import pytz
from typing import List, Dict, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
import time
import threading
import urllib3
import ssl
import logging

# Disable SSL warnings for corporate networks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from config import NEWS_SOURCES, CYBERSECURITY_KEYWORDS, HIGH_PRIORITY_KEYWORDS, COMPANY_NAME
from database import db

# This module otherwise reports progress with print(), which only reaches the
# console. Swallowed-exception detail belongs in the log file that log_setup
# configures, so it survives to be read after the fact.
logger = logging.getLogger(__name__)

# Timezone configuration
KOLKATA_TZ = pytz.timezone('Asia/Kolkata')

def get_kolkata_time():
    """Get current time in Asia/Kolkata timezone"""
    return datetime.now(KOLKATA_TZ)


class ThreatIntelScraper:
    def __init__(self):
        self.ua = UserAgent()
        self.session = requests.Session()

        # Cooperative cancellation flag. A running session checks this between
        # sources; the dashboard sets it when the user clicks "Stop scrape".
        self.cancel_requested = threading.Event()

        # Errors from scrape_rss_feed / scrape_website_direct. Those methods
        # catch their own exceptions (so one bad source can't kill a session),
        # but sessions must still surface them — otherwise a fully-failed
        # scrape gets logged as 'completed' with 0 articles and nobody notices.
        self.session_errors = []

        # CRITICAL FIX: Disable SSL verification for corporate networks
        self.session.verify = False
        
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    
    def calculate_relevance_score(self, title: str, summary: str, content: str) -> float:
        """Calculate relevance score based on keywords with BOOSTED scoring for critical threats"""
        text = f"{title} {summary} {content}".lower()
        score = 0.0
        
        # CRITICAL PRIORITY BOOST: CVE identifiers (weight: +15.0)
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_matches = re.findall(cve_pattern, text, re.IGNORECASE)
        if cve_matches:
            score += 15.0  # Major boost for CVE articles
            print(f"   🔴 CRITICAL: CVE found ({', '.join(cve_matches)}) - Added +15.0 bonus")
        
        # CRITICAL PRIORITY BOOST: Active exploitation (weight: +20.0)
        active_exploitation_keywords = [
            'active exploitation', 'actively exploited', 'actively exploiting',
            'under active attack', 'being actively exploited', 'exploitation in the wild',
            'in-the-wild', 'zero-day exploit', 'attacks observed'
        ]
        for keyword in active_exploitation_keywords:
            if keyword in text:
                score += 20.0  # Massive boost for active threats
                print(f"   🔴 CRITICAL: Active exploitation detected - Added +20.0 bonus")
                break
        
        # CRITICAL PRIORITY BOOST: Critical/High severity (weight: +10.0)
        critical_severity_keywords = [
            'critical vulnerability', 'critical security', 'critical flaw',
            'severity 10', 'cvss 10', 'cvss 9', 'emergency patch'
        ]
        for keyword in critical_severity_keywords:
            if keyword in text:
                score += 10.0
                print(f"   🔴 CRITICAL: High severity threat - Added +10.0 bonus")
                break
        
        # Check for high priority keywords (weight: 3.0)
        for keyword in HIGH_PRIORITY_KEYWORDS:
            if keyword.lower() in text:
                score += 3.0
        
        # Check for regular keywords (weight: 1.0)
        for keyword in CYBERSECURITY_KEYWORDS:
            if keyword.lower() in text:
                score += 1.0
        
        # Bonus for multiple keyword matches
        keyword_count = sum(1 for keyword in CYBERSECURITY_KEYWORDS if keyword.lower() in text)
        if keyword_count > 5:
            score *= 1.5
        elif keyword_count > 10:
            score *= 2.0
        
        return round(score, 2)
    
    def extract_keywords_from_text(self, text: str) -> List[str]:
        """Extract relevant keywords from text"""
        text_lower = text.lower()
        found_keywords = []
        
        all_keywords = CYBERSECURITY_KEYWORDS + HIGH_PRIORITY_KEYWORDS
        for keyword in all_keywords:
            if keyword.lower() in text_lower:
                found_keywords.append(keyword)
        
        return list(set(found_keywords))  # Remove duplicates
    
    def _extract_threat_insights(self, content: str) -> str:
        """Extract key threat insights from content"""
        try:
            # Look for key threat indicators
            threat_indicators = [
                r'CVE-\d{4}-\d{4,7}',  # CVE IDs
                r'(\w+)\s+(malware|ransomware|trojan|vulnerability)',  # Threat types
                r'(affects|impacts|targets)\s+([^.]+)',  # Impact statements
                r'(researchers|experts|analysts)\s+(discovered|found|identified)\s+([^.]+)'  # Discovery info
            ]
            
            insights = []
            content_lower = content.lower()
            
            for pattern in threat_indicators:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches[:2]:  # Limit to 2 matches per pattern
                        if isinstance(match, tuple):
                            insight = ' '.join(match).strip()
                        else:
                            insight = match.strip()
                        if len(insight) > 10 and insight not in insights:
                            insights.append(insight)
            
            return '. '.join(insights[:2]) + '.' if insights else ""
        except Exception as e:
            # Insights are a nice-to-have on top of the article; a regex or
            # encoding surprise must not lose the article itself.
            logger.debug(f"Insight extraction failed: {e}")
            return ""
    
    def _analyze_threat_context(self, title: str) -> str:
        """Analyze title to provide specific threat context"""
        title_lower = title.lower()
        
        if any(word in title_lower for word in ['ransomware', 'encryption', 'crypto']):
            return "Ransomware threat detected affecting data encryption and system availability"
        elif any(word in title_lower for word in ['malware', 'trojan', 'virus']):
            return "Malicious software threat identified with potential system compromise"
        elif any(word in title_lower for word in ['vulnerability', 'exploit', 'cve']):
            return "Security vulnerability discovered requiring immediate patching"
        elif any(word in title_lower for word in ['phishing', 'social engineering']):
            return "Social engineering attack vector targeting user credentials"
        elif any(word in title_lower for word in ['api', 'cloud', 'saas']):
            return "Cloud infrastructure security threat affecting service availability"
        elif any(word in title_lower for word in ['financial', 'banking', 'payment']):
            return "Financial sector threat with potential monetary impact"
        else:
            return "Cybersecurity threat requiring organizational risk assessment"
    
    def create_professional_summary(self, title: str, original_summary: str, content: str) -> str:
        """Create professional 2-3 line summary for threat intelligence articles with enhanced authenticity"""
        try:
            # Prioritize original summary but also use full content for enrichment
            best_content = ""
            
            # Use original summary if substantial, otherwise use content
            if original_summary and len(original_summary.strip()) > 30:
                best_content = original_summary.strip()
                # Also add key insights from content if available
                if content and len(content.strip()) > 100:
                    # Extract key threat details from content
                    content_insights = self._extract_threat_insights(content)
                    if content_insights:
                        best_content = f"{best_content} {content_insights}"
            elif content and len(content.strip()) > 50:
                best_content = content.strip()
            else:
                # Create more specific fallback based on threat analysis
                threat_context = self._analyze_threat_context(title)
                return f"Security alert: {threat_context}. This threat intelligence report requires immediate review for potential impact assessment and remediation planning."
            
            # Clean the content
            import re
            from bs4 import BeautifulSoup
            
            # Remove HTML tags
            try:
                soup = BeautifulSoup(best_content, 'html.parser')
                best_content = soup.get_text(separator=' ', strip=True)
            except Exception as e:
                logger.debug(f"BeautifulSoup parse failed, stripping tags by regex: {e}")
                best_content = re.sub(r'<[^>]*>', '', best_content)
            
            # Remove extra whitespace
            best_content = ' '.join(best_content.split())
            
            # Extract meaningful sentences
            sentences = re.split(r'[.!?]+', best_content)
            clean_sentences = []
            
            for sentence in sentences:
                sentence = sentence.strip()
                if (len(sentence) > 20 and 
                    not any(junk in sentence.lower() for junk in ['http', 'www.', 'click here', 'read more', 'continue reading', 'subscribe', 'newsletter']) and
                    not sentence.isupper()):  # Avoid all-caps sentences
                    clean_sentences.append(sentence)
            
            if not clean_sentences:
                return f"Security alert regarding {title.lower()}. This threat intelligence report requires review for potential impact on organizational security posture."
            
            # Take first 2-3 meaningful sentences for summary
            selected_sentences = clean_sentences[:3]
            
            # Join and ensure proper punctuation
            summary = '. '.join(selected_sentences)
            if not summary.endswith('.'):
                summary += '.'
            
            # Limit to 2-3 lines (200-300 characters)
            if len(summary) > 300:
                truncated = summary[:300]
                last_period = truncated.rfind('.')
                if last_period > 200:
                    summary = truncated[:last_period + 1]
                else:
                    summary = truncated + "..."
            
            # Ensure minimum quality
            if len(summary.strip()) < 30:
                summary = f"Security alert regarding {title.lower()}. This threat intelligence report requires review for potential impact on organizational security posture."
            
            # Clean up the summary
            summary = re.sub(r'\s+', ' ', summary)  # Remove extra whitespace
            summary = summary.strip()
            
            return summary
            
        except Exception as e:
            print(f"   ⚠️ Error creating professional summary: {str(e)}")
            return f"Security alert regarding {title.lower()}. This threat intelligence report requires review for potential impact on organizational security posture."
    
    def scrape_rss_feed(self, source: Dict) -> List[Dict]:
        """Scrape news from RSS feed"""
        articles = []
        
        try:
            # Add headers to avoid being blocked
            self.session.headers.update({
                'User-Agent': self.ua.random,
                'Accept': 'application/rss+xml, application/xml, text/xml',
                'Cache-Control': 'no-cache'
            })
            
            # Get RSS feed with timeout and SSL bypass
            print(f"   🔗 Fetching RSS from: {source['rss']}")
            response = self.session.get(source['rss'], timeout=15, verify=False)
            response.raise_for_status()
            print(f"   ✅ RSS response received: {response.status_code}")
            
            feed = feedparser.parse(response.content)
            
            # Fixed window: last 7 days.
            start_dt = datetime.now(KOLKATA_TZ) - timedelta(days=7)
            end_dt = datetime.now(KOLKATA_TZ)
            print(f"   📅 Filtering articles from {start_dt.strftime('%Y-%m-%d')} onwards (last 7 days)…")
            print(f"   📰 Total entries in RSS feed: {len(feed.entries)}")
            
            for entry in feed.entries[:100]:  # Check up to 100 entries to get more recent articles
                # Stop promptly if the user clicked "Stop scrape": most of a
                # session's time is spent in this per-article loop, so we must
                # check here (not just between sources) to feel responsive.
                if self.cancel_requested.is_set():
                    print("   🛑 Stop requested — halting article fetch for this source")
                    break
                try:
                    # Extract basic information
                    title = entry.get('title', '').strip()
                    summary = entry.get('summary', '') or entry.get('description', '')
                    link = entry.get('link', '').strip()
                    
                    if not title or not link:
                        continue
                    
                    # Parse publication date
                    pub_date = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        try:
                            # Treat feed times as UTC if tz not provided, then convert to Kolkata
                            parsed = datetime(*entry.published_parsed[:6])
                            if parsed.tzinfo is None:
                                parsed = parsed.replace(tzinfo=pytz.utc)
                            pub_date = parsed.astimezone(KOLKATA_TZ)
                        except Exception:
                            pub_date = datetime.now(KOLKATA_TZ)
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        try:
                            parsed = datetime(*entry.updated_parsed[:6])
                            if parsed.tzinfo is None:
                                parsed = parsed.replace(tzinfo=pytz.utc)
                            pub_date = parsed.astimezone(KOLKATA_TZ)
                        except Exception:
                            pub_date = datetime.now(KOLKATA_TZ)
                    else:
                        pub_date = datetime.now(KOLKATA_TZ)
                    
                    # Only include articles inside the requested window
                    if pub_date < start_dt or pub_date > end_dt:
                        continue
                    
                    # Clean and validate URL
                    if link.startswith('//'):
                        link = 'https:' + link
                    elif not link.startswith('http'):
                        link = urljoin(source['url'], link)
                    
                    # Get full content if available
                    content = self.get_article_content(link, source)
                    if not content:
                        content = summary
                    
                    # Calculate relevance
                    relevance_score = self.calculate_relevance_score(title, summary, content)
                    
                    # Include all articles from The Hacker News (general cybersecurity news)
                    # For other sources, filter by relevance score > 0
                    include_article = (source['name'] == 'The Hacker News') or (relevance_score > 0)
                    
                    if include_article:
                        keywords = self.extract_keywords_from_text(f"{title} {summary} {content}")
                        
                        # For The Hacker News, ensure minimum score of 1.0 if it's a cybersecurity article
                        if source['name'] == 'The Hacker News' and relevance_score == 0:
                            # It's from a cybersecurity news site, so give it a base score
                            relevance_score = 1.0
                        
                        # ENHANCED SUMMARY PROCESSING
                        professional_summary = self.create_professional_summary(title, summary, content)
                        
                        articles.append({
                            'title': title,
                            'summary': professional_summary,  # Use enhanced summary
                            'content': content[:2000] if content else '',  # Limit content length
                            'url': link,
                            'source': source['name'],
                            'published_date': pub_date,
                            'relevance_score': relevance_score,
                            'keywords': keywords
                        })
                        
                        print(f"   ✅ Found relevant article: {title[:50]}... (Score: {relevance_score})")
                
                except Exception as e:
                    print(f"   ⚠️ Error processing RSS entry: {str(e)}")
                    continue
        
        except Exception as e:
            print(f"   ❌ Error scraping RSS feed {source['name']}: {str(e)}")
            self.session_errors.append(f"RSS feed {source['name']}: {str(e)}")
            db.log_system_event('ERROR', f'Error scraping RSS feed {source["name"]}: {str(e)}', 'RSS_SCRAPER')

        return articles
    
    def get_article_content(self, url: str, source: Dict) -> str:
        """Get full article content from URL using newspaper3k with BeautifulSoup fallback"""
        try:
            # PRIMARY METHOD: Use newspaper3k for intelligent article extraction
            try:
                from newspaper import Article, Config
                import requests
                
                # Configure newspaper3k
                config = Config()
                config.browser_user_agent = self.ua.random
                config.request_timeout = 10
                config.fetch_images = False
                
                article = Article(url, config=config)
                
                # Use requests with SSL disabled to avoid certificate errors
                response = self.session.get(url, timeout=10)
                response.raise_for_status()
                
                # Set HTML content and parse
                article.set_html(response.text)
                article.parse()
                
                # newspaper3k extracts only the main article content, ignoring ads/sidebars
                content = article.text
                
                if content and len(content.strip()) > 100:
                    print(f"   ✅ Extracted article using newspaper3k: {len(content)} chars")
                    # Clean and validate
                    content = self._clean_scraped_content(content)
                    if content and len(content.strip()) > 100:
                        # Return full content (increased limit for AI processing)
                        return content[:5000]
            
            except Exception as e:
                print(f"   ⚠️ newspaper3k failed: {str(e)}, falling back to BeautifulSoup")
            
            # FALLBACK METHOD: BeautifulSoup with improved CSS selectors
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # STRATEGY 1: Remove known promotional elements first
            for ad in soup.find_all(class_=re.compile('ad|promo|sponsor', re.IGNORECASE)):
                ad.decompose()
            for ad in soup.find_all(id=re.compile('ad|promo|sponsor', re.IGNORECASE)):
                ad.decompose()
            
            # STRATEGY 2: Try to find article content using improved selectors (prioritize specific ones)
            content_selectors = [
                '.articlebody',  # The Hacker News specific
                '#articlebody',   # The Hacker News specific
                '.article-content', 
                '.post-content', 
                '.entry-content',
                '.content', 
                'main', 
                '.main-content', 
                '.story-body', 
                '.post-body',
                'article'
            ]
            
            content = ""
            for selector in content_selectors:
                elem = soup.select_one(selector)
                if elem:
                    test_content = elem.get_text(separator=' ', strip=True)
                    # Ensure we got substantial content, not just ads
                    if len(test_content) > 300:
                        content = test_content
                        print(f"   ✅ Found content with selector: {selector} ({len(content)} chars)")
                        break
            
            # STRATEGY 3: If no content found, extract paragraphs but filter promotional ones
            if not content or len(content) < 300:
                print("   ⚠️ No good selector found, extracting paragraphs...")
                paragraphs = soup.find_all('p')
                valid_paragraphs = []
                for p in paragraphs:
                    text = p.get_text(strip=True)
                    # Skip if too short or contains promotional keywords
                    if len(text) > 50 and not any(promo in text.lower() for promo in ['cheat sheet', 'download', 'click here', 'subscribe', 'sign up']):
                        valid_paragraphs.append(text)
                
                if valid_paragraphs:
                    content = ' '.join(valid_paragraphs)
                    print(f"   ✅ Extracted {len(valid_paragraphs)} valid paragraphs ({len(content)} chars)")
            
            # CRITICAL: Filter out placeholder and advertisement content
            if content:
                content = self._clean_scraped_content(content)
            
            # AGGRESSIVE: Reject advertisement/sponsored/promotional content
            bad_content_indicators = [
                # Placeholder content
                'kubernetes errors 101',
                'practical guide for cloud',
                'troubleshoot faster',
                'lorem ipsum',
                'sample content',
                'placeholder text',
                
                # Advertisement indicators
                'this new cheat sheet',
                'download our guide',
                'free cheat sheet',
                'get your free',
                'download now',
                'click to download',
                'sponsored content',
                'advertisement',
                'promotional material',
                
                # Generic marketing phrases
                'walks you through',
                'step-by-step guide',
                'comprehensive guide',
                'ultimate guide',
                'complete guide',
                'best practices guide',
                
                # CI/CD promotional content (your specific issue)
                'ci/cd pipeline security best practices',
                'owasp top 10 ci/cd',
                'reduce your attack surface',
                'strengthen your delivery processes',
                
                # Newsletter/subscription prompts
                'subscribe to our newsletter',
                'sign up for free',
                'join our mailing list',
                'get updates delivered'
            ]
            
            content_lower = content.lower()
            
            # Count how many bad indicators found
            bad_indicators_found = []
            for indicator in bad_content_indicators:
                if indicator in content_lower:
                    bad_indicators_found.append(indicator)
            
            # Only reject if content is VERY SHORT and has promotional content
            # This catches pure advertisement pages but allows legitimate articles with some promotional text
            if len(content) < 500 and len(bad_indicators_found) >= 2:
                db.log_system_event('WARNING', f'Short content with multiple advertisement indicators detected in {url}: {bad_indicators_found[:3]}, rejecting', 'CONTENT_FETCHER')
                return ""
            elif len(bad_indicators_found) >= 5:
                # Many indicators even in long content = advertisement page
                db.log_system_event('WARNING', f'Multiple advertisement indicators detected in {url}: {bad_indicators_found[:3]}, rejecting', 'CONTENT_FETCHER')
                return ""
            elif len(bad_indicators_found) > 0:
                db.log_system_event('INFO', f'Some promotional phrases detected in {url}: {bad_indicators_found}, but keeping for sender review', 'CONTENT_FETCHER')
            
            return content[:5000]  # Increased limit for AI processing
        
        except Exception as e:
            db.log_system_event('WARNING', f'Could not fetch content from {url}: {str(e)}', 'CONTENT_FETCHER')
            return ""
    
    def _clean_scraped_content(self, content: str) -> str:
        """AGGRESSIVELY clean scraped content to remove ads and promotional noise"""
        import re
        
        # AGGRESSIVE: Remove advertisement and promotional patterns
        noise_patterns = [
            # Kubernetes/CI-CD promotional content
            r'Kubernetes Errors 101.*?troubleshoot.*?smoothly',
            r'practical guide for cloud.*?platform teams.*?looking to troubleshoot',
            r'CI/CD Pipeline Security.*?Best Practices.*?',
            r'This new cheat sheet.*?OWASP.*?',
            r'walks you through.*?security risks.*?',
            r'reduce your attack surface.*?strengthen.*?processes',
            
            # Generic advertisements
            r'advertisement[^.]*',
            r'sponsored content[^.]*',
            r'promotional material[^.]*',
            
            # Download/subscription prompts
            r'download.*?(?:guide|cheat sheet|ebook|whitepaper)[^.]*',
            r'get your free.*?(?:guide|report|ebook)[^.]*',
            r'subscribe.*?newsletter[^.]*',
            r'sign up for.*?updates[^.]*',
            r'join our.*?mailing list[^.]*',
            
            # Social media/sharing
            r'read more[^.]*',
            r'follow us on[^.]*',
            r'share this article[^.]*',
            r'tweet this[^.]*',
            r'share on facebook[^.]*',
            
            # Call-to-action phrases
            r'click here to[^.]*',
            r'learn more about[^.]*',
            r'visit our website[^.]*',
            r'contact us for[^.]*'
        ]
        
        for pattern in noise_patterns:
            content = re.sub(pattern, '', content, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove extra whitespace
        content = ' '.join(content.split())
        
        return content.strip()
    
    def scrape_website_direct(self, source: Dict) -> List[Dict]:
        """Direct website scraping as backup"""
        articles = []
        
        try:
            response = self.session.get(source['url'], timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find article elements based on selectors
            title_elements = soup.select(source['selectors']['title'])
            
            for element in title_elements[:15]:  # Limit to 15 articles
                # Same cooperative-cancel check as the RSS path.
                if self.cancel_requested.is_set():
                    print("   🛑 Stop requested — halting article fetch for this source")
                    break
                try:
                    title = element.get_text(strip=True)
                    
                    # Find associated link
                    link_element = element.find('a') or element.find_parent('a')
                    if link_element:
                        url = urljoin(source['url'], link_element.get('href', ''))
                    else:
                        continue
                    
                    # Get summary if available
                    summary = ""
                    if 'summary' in source['selectors']:
                        summary_element = element.find_next(source['selectors']['summary'])
                        if summary_element:
                            summary = summary_element.get_text(strip=True)
                    
                    # Get full content
                    content = self.get_article_content(url, source)
                    if not content:
                        content = summary
                    
                    # Calculate relevance
                    relevance_score = self.calculate_relevance_score(title, summary, content)
                    
                    if relevance_score > 0:
                        keywords = self.extract_keywords_from_text(f"{title} {summary} {content}")
                        
                        # ENHANCED SUMMARY PROCESSING
                        professional_summary = self.create_professional_summary(title, summary, content)
                        
                        articles.append({
                            'title': title,
                            'summary': professional_summary,  # Use enhanced summary
                            'content': content[:2000],
                            'url': url,
                            'source': source['name'],
                            'published_date': datetime.now(pytz.timezone("Asia/Kolkata")),
                            'relevance_score': relevance_score,
                            'keywords': keywords
                        })
                
                except Exception as e:
                    continue
        
        except Exception as e:
            self.session_errors.append(f"Direct scrape {source['name']}: {str(e)}")
            db.log_system_event('ERROR', f'Error scraping website {source["name"]}: {str(e)}', 'WEB_SCRAPER')

        return articles
    
    def scrape_all_sources(self) -> Tuple[List[Dict], Dict]:
        """Scrape all configured news sources with duplicate prevention"""
        all_articles = []
        self.session_errors = []
        scraping_stats = {
            'total_found': 0,
            'total_saved': 0,
            'sources_scraped': [],
            'errors': [],
            'duplicates_filtered': 0
        }

        for source in NEWS_SOURCES:
            print(f"Scraping {source['name']} for articles from past 7 days...")
            
            try:
                # Try RSS first, fallback to direct scraping
                articles = self.scrape_rss_feed(source)
                if not articles:
                    print(f"RSS failed for {source['name']}, trying direct scraping...")
                    articles = self.scrape_website_direct(source)
                
                # Additional filter for past 7 days (double check)
                if articles:
                    one_week_ago = datetime.now(KOLKATA_TZ) - timedelta(days=7)
                    recent_articles = []
                    for article in articles:
                        try:
                            article_date = article.get('published_date')
                            if isinstance(article_date, str):
                                # Try ISO parse then fallback to DB format
                                try:
                                    article_date = datetime.fromisoformat(article_date)
                                except Exception:
                                    article_date = datetime.strptime(article_date, '%Y-%m-%d %H:%M:%S')
                            if article_date.tzinfo is None:
                                article_date = article_date.replace(tzinfo=KOLKATA_TZ)
                            if article_date >= one_week_ago:
                                recent_articles.append(article)
                            else:
                                print(f"   ❌ Filtering old article: {article['title'][:50]}... (Date: {article_date.strftime('%Y-%m-%d')})")
                        except (ValueError, TypeError, AttributeError, KeyError) as e:
                            # If date parsing fails, include the article (benefit of doubt)
                            logger.debug(f"Date filter skipped for an article: {e}")
                            recent_articles.append(article)
                    articles = recent_articles
                    print(f"   📅 Kept {len(articles)} articles from past 7 days")
                
                # Duplicate detection temporarily disabled to get all articles from last week
                # Filter out duplicates from previous weeks
                # new_articles = []
                # for article in articles:
                #     if not db.is_duplicate_article(article['url'], article['title']):
                #         new_articles.append(article)
                #         # Add to scraped history for future duplicate prevention
                #         db.add_to_scraped_history(article['url'], article['title'], source['name'])
                #     else:
                #         scraping_stats['duplicates_filtered'] += 1
                #         print(f"   ⚠️ Filtered duplicate: {article['title'][:50]}...")
                
                # For now, include all articles without duplicate filtering
                all_articles.extend(articles)
                scraping_stats['sources_scraped'].append(source['name'])
                scraping_stats['total_found'] += len(articles)
                
                print(f"   ✅ Found {len(articles)} articles from past 7 days")
                
                # Rate limiting
                time.sleep(2)
            
            except Exception as e:
                error_msg = f"Failed to scrape {source['name']}: {str(e)}"
                scraping_stats['errors'].append(error_msg)
                db.log_system_event('ERROR', error_msg, 'SCRAPER')

        # Surface errors that scrape_rss_feed/scrape_website_direct caught
        # internally, so the session status reflects them.
        scraping_stats['errors'].extend(self.session_errors)

        # Remove duplicates within current session (URL-based)
        unique_articles = {}
        for article in all_articles:
            if article['url'] not in unique_articles:
                unique_articles[article['url']] = article

        final_articles = list(unique_articles.values())
        
        # Sort by relevance score
        final_articles.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        scraping_stats['total_saved'] = len(final_articles)
        
        print(f"📊 Session summary: {scraping_stats['total_found']} found, {scraping_stats['total_saved']} unique, {scraping_stats['duplicates_filtered']} duplicates filtered")
        
        return final_articles, scraping_stats
    
    def save_articles_to_database(self, articles: List[Dict]) -> List[int]:
        """Save articles to database"""
        saved_ids = []
        
        for article in articles:
            article_id = db.add_news_article(
                title=article['title'],
                summary=article['summary'],
                content=article['content'],
                url=article['url'],
                source=article['source'],
                keywords=article['keywords'],
                relevance_score=article['relevance_score'],
                published_date=article['published_date']
            )
            
            if article_id:
                saved_ids.append(article_id)
        
        return saved_ids
    
    def run_scraping_session(self) -> Dict:
        """Run a complete scraping session with enhanced duplicate prevention"""
        session_start = datetime.now(pytz.timezone("Asia/Kolkata"))
        print(f"🔍 Starting enhanced scraping session at {session_start}")
        
        # Scrape all sources with duplicate prevention
        articles, stats = self.scrape_all_sources()
        
        if articles:
            # Save to database
            saved_ids = self.save_articles_to_database(articles)
            stats['articles_saved_to_db'] = len(saved_ids)
            
            # Log scraping session with enhanced stats
            error_log = '; '.join(stats['errors']) if stats['errors'] else None
            session_status = 'completed' if not stats['errors'] else 'completed_with_errors'
            
            session_id = db.log_scraping_session(
                sources=stats['sources_scraped'],
                found_count=stats['total_found'],
                saved_count=len(saved_ids),
                status=session_status,
                error_log=error_log,
                session_type='manual'
            )
            
            # Link articles to this session
            if session_id and saved_ids:
                db.link_articles_to_session(session_id, saved_ids)
            
            stats['session_id'] = session_id
            
            # Enhanced logging
            db.log_system_event('INFO', 
                f'Enhanced scraping session completed. Found: {stats["total_found"]}, Saved: {len(saved_ids)}, Duplicates filtered: {stats.get("duplicates_filtered", 0)}',
                'ENHANCED_SCRAPING_SESSION')
        else:
            # Log empty session
            session_id = db.log_scraping_session(
                sources=stats['sources_scraped'],
                found_count=stats['total_found'],
                saved_count=0,
                status='completed' if not stats['errors'] else 'failed',
                error_log='; '.join(stats['errors']) if stats['errors'] else None
            )
            stats['session_id'] = session_id
        
        session_end = datetime.now(pytz.timezone("Asia/Kolkata"))
        stats['duration'] = str(session_end - session_start)
        
        print(f"✅ Enhanced scraping session completed in {stats['duration']}")
        print(f"📊 Final stats: Found: {stats['total_found']}, Saved: {stats.get('articles_saved_to_db', 0)}, Duplicates filtered: {stats.get('duplicates_filtered', 0)}")
        
        # Cleanup old history (keep last 30 days)
        db.cleanup_old_scraped_history(30)
        
        return stats

    def run_scraping_session_limited(self, limit: int = 10) -> Dict:
        """Run a limited scraping session.

        Always filters to the last 7 days (the RSS feeds we ingest only carry
        a fixed window of recent entries, so a longer window doesn't actually
        return older articles).
        """
        session_start = datetime.now(pytz.timezone("Asia/Kolkata"))

        end_dt = datetime.now(KOLKATA_TZ)
        start_dt = end_dt - timedelta(days=7)
        window_desc = "past 7 days"

        print(f"🔍 Starting LIMITED scraping session (target: {limit} articles, window: {window_desc}) at {session_start}")

        # Start from a clean cancellation state so a stale "stop" from a previous
        # session can never abort this one. The stop button sets this flag again
        # once we're inside the source loop below.
        self.cancel_requested.clear()
        self.session_errors = []

        all_articles = []
        scraping_stats = {
            'total_found': 0,
            'total_saved': 0,
            'sources_scraped': [],
            'errors': [],
            'duplicates_filtered': 0,
            'window': window_desc,
        }

        # FIXED: Scrape ALL sources first, then pick best articles
        print(f"📰 Scraping ALL {len(NEWS_SOURCES)} sources to get best {limit} articles...")

        for source in NEWS_SOURCES:
            # Cooperative cancellation: bail out before starting the next source
            # if the user asked to stop. We finish the source already in flight
            # rather than tearing down an in-progress request.
            if self.cancel_requested.is_set():
                print("🛑 Scrape cancelled by user — stopping before the next source")
                scraping_stats['cancelled'] = True
                break

            print(f"Scraping {source['name']} for articles from {window_desc}...")

            try:
                # Try RSS first, fallback to direct scraping (both filter to
                # the last 7 days internally — see scrape_rss_feed).
                articles = self.scrape_rss_feed(source)
                if not articles:
                    print(f"RSS failed for {source['name']}, trying direct scraping...")
                    articles = self.scrape_website_direct(source)

                # Safety-net filter for scrape_website_direct (it doesn't have
                # its own date filter, unlike scrape_rss_feed).
                if articles:
                    recent_articles = []
                    for article in articles:
                        try:
                            article_date = article.get('published_date', datetime.now(KOLKATA_TZ))
                            if start_dt <= article_date <= end_dt:
                                recent_articles.append(article)
                        except Exception:
                            recent_articles.append(article)
                    articles = recent_articles
                    print(f"   📅 Kept {len(articles)} articles from {window_desc}")
                
                # Add ALL articles from this source (no limit yet)
                all_articles.extend(articles)
                
                scraping_stats['sources_scraped'].append(source['name'])
                scraping_stats['total_found'] += len(articles)
                
                print(f"   ✅ Found {len(articles)} articles from {source['name']}, Total collected: {len(all_articles)}")
                
                # Rate limiting
                time.sleep(1)
            
            except Exception as e:
                error_msg = f"Failed to scrape {source['name']}: {str(e)}"
                scraping_stats['errors'].append(error_msg)
                db.log_system_event('ERROR', error_msg, 'SCRAPER')

        # Surface errors that scrape_rss_feed/scrape_website_direct caught
        # internally, so the session status reflects them.
        scraping_stats['errors'].extend(self.session_errors)

        # If the user stopped the scrape, abort here: don't save partial results
        # or send anything to the manager. (The fresh scrape already cleared the
        # DB in step 1, so a stopped run intentionally leaves no articles.)
        if self.cancel_requested.is_set() or scraping_stats.get('cancelled'):
            scraping_stats['cancelled'] = True
            scraping_stats['articles_saved_to_db'] = 0
            session_id = db.log_scraping_session(
                sources=scraping_stats['sources_scraped'],
                found_count=scraping_stats['total_found'],
                saved_count=0,
                status='cancelled',
                error_log='Stopped by user',
                session_type='fresh'
            )
            scraping_stats['session_id'] = session_id
            session_end = datetime.now(pytz.timezone("Asia/Kolkata"))
            scraping_stats['duration'] = str(session_end - session_start)
            print(f"🛑 Scraping session cancelled after {scraping_stats['duration']}")
            return scraping_stats

        # Remove duplicates within current session (URL-based)
        print(f"\n📊 Collected {len(all_articles)} total articles from {len(scraping_stats['sources_scraped'])} sources")
        unique_articles = {}
        for article in all_articles:
            if article['url'] not in unique_articles:
                unique_articles[article['url']] = article
        
        final_articles = list(unique_articles.values())
        print(f"📊 After removing duplicates: {len(final_articles)} unique articles")
        
        # Sort by relevance score and take exactly the limit
        final_articles.sort(key=lambda x: x['relevance_score'], reverse=True)
        final_articles = final_articles[:limit]
        print(f"📊 Selecting top {limit} articles by relevance score")
        print(f"📊 Final articles from sources: {', '.join(set(a['source'] for a in final_articles))}")
        
        if final_articles:
            # Save to database
            saved_ids = self.save_articles_to_database(final_articles)
            scraping_stats['articles_saved_to_db'] = len(saved_ids)
            
            # Log scraping session
            error_log = '; '.join(scraping_stats['errors']) if scraping_stats['errors'] else None
            session_status = 'completed' if not scraping_stats['errors'] else 'completed_with_errors'
            
            session_id = db.log_scraping_session(
                sources=scraping_stats['sources_scraped'],
                found_count=scraping_stats['total_found'],
                saved_count=len(saved_ids),
                status=session_status,
                error_log=error_log,
                session_type='fresh'
            )
            
            # Link articles to this session
            if session_id and saved_ids:
                db.link_articles_to_session(session_id, saved_ids)
            
            scraping_stats['session_id'] = session_id
            
            # Enhanced logging
            db.log_system_event('INFO', 
                f'LIMITED scraping session completed. Target: {limit}, Found: {scraping_stats["total_found"]}, Saved: {len(saved_ids)}, Duplicates filtered: {scraping_stats.get("duplicates_filtered", 0)}',
                'LIMITED_SCRAPING_SESSION')
        else:
            # Log empty session
            session_id = db.log_scraping_session(
                sources=scraping_stats['sources_scraped'],
                found_count=scraping_stats['total_found'],
                saved_count=0,
                status='completed' if not scraping_stats['errors'] else 'failed',
                error_log='; '.join(scraping_stats['errors']) if scraping_stats['errors'] else None,
                session_type='fresh'
            )
            scraping_stats['session_id'] = session_id
        
        session_end = datetime.now(pytz.timezone("Asia/Kolkata"))
        scraping_stats['duration'] = str(session_end - session_start)
        
        print(f"✅ LIMITED scraping session completed in {scraping_stats['duration']}")
        print(f"📊 Final stats: Target: {limit}, Found: {scraping_stats['total_found']}, Saved: {scraping_stats.get('articles_saved_to_db', 0)}, Duplicates filtered: {scraping_stats.get('duplicates_filtered', 0)}")
        
        return scraping_stats


# Create global scraper instance
scraper = ThreatIntelScraper()


if __name__ == "__main__":
    # Test scraping
    print("Running test scraping session...")
    results = scraper.run_scraping_session()
    print(f"Scraping results: {results}")
