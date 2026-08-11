"""SOC Report Formatter for Threat Intelligence System"""

from datetime import datetime
from typing import Dict, List, Optional
import re
from dataclasses import dataclass

from config import COMPANY_NAME, SOC_EMAIL, ENFORCE_NUMBERING_1_TO_10
from database import db


@dataclass
class ThreatReport:
    """Data class for structured threat report"""
    title: str
    threat_type: str
    date_identified: str
    threat_summary: str
    attack_outcome: str
    tactics_used: str
    data_loss_exposure: str
    financial_impact: str
    reputational_risk: str
    cve_id: Optional[str]
    description: str
    exploited_systems: str
    severity_rating: str
    patch_availability: str
    mitigation_measures: str
    source_url: str
    source_name: str


class SOCReportFormatter:
    def __init__(self):
        self.report_id_counter = 1
        self.daily_counter = 1  # Counter for 1-10 numbering per day
    
    def extract_cve_information(self, content: str) -> Optional[str]:
        """Extract CVE IDs from content"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, content, re.IGNORECASE)
        return cves[0] if cves else None
    
    def determine_threat_type(self, title: str, content: str, keywords: List[str]) -> str:
        """Determine the type of threat based on content analysis"""
        text = f"{title} {content}".lower()
        
        # Priority mapping for threat types
        threat_types = {
            'ransomware': ['ransomware', 'crypto', 'encryption', 'ransom'],
            'malware': ['malware', 'trojan', 'virus', 'backdoor', 'spyware'],
            'phishing': ['phishing', 'spear phishing', 'email attack', 'social engineering'],
            'data breach': ['data breach', 'data leak', 'information disclosure', 'database'],
            'vulnerability': ['vulnerability', 'exploit', 'zero-day', 'cve', 'patch'],
            'ddos': ['ddos', 'denial of service', 'botnet'],
            'supply chain': ['supply chain', 'third party', 'vendor'],
            'insider threat': ['insider', 'employee', 'internal'],
            'api security': ['api', 'rest', 'endpoint'],
            'cloud security': ['cloud', 'aws', 'azure', 'saas'],
            'mobile security': ['mobile', 'android', 'ios', 'app'],
            'payment fraud': ['payment', 'financial', 'banking', 'card', 'transaction']
        }
        
        for threat_type, indicators in threat_types.items():
            if any(indicator in text for indicator in indicators):
                return threat_type.title() + " Attack"
        
        return "Cybersecurity Threat"
    
    def assess_severity_rating(self, relevance_score: float, keywords: List[str], content: str) -> str:
        """Assess severity rating based on multiple factors"""
        severity_score = float(relevance_score) if relevance_score else 0
        
        high_severity_indicators = [
            'critical', 'emergency', 'urgent', 'immediate', 'active exploitation',
            'zero-day', 'widespread', 'nation-state', 'apt'
        ]
        
        medium_severity_indicators = [
            'medium', 'moderate', 'significant', 'important'
        ]
        
        content_lower = content.lower()
        
        # Boost score for high severity indicators
        for indicator in high_severity_indicators:
            if indicator in content_lower:
                severity_score += 2
        
        # Determine CVSS-like score and rating
        if severity_score >= 8:
            return "Critical (CVSS 9.0+)"
        elif severity_score >= 6:
            return "High (CVSS 7.0-8.9)"
        elif severity_score >= 4:
            return "Medium (CVSS 4.0-6.9)"
        else:
            return "Low (CVSS 0.1-3.9)"
    
    def determine_impact_assessment(self, content: str, keywords: List[str]) -> Dict[str, str]:
        """Determine various impact assessments"""
        content_lower = content.lower()
        
        # Financial Impact Assessment
        if any(term in content_lower for term in ['financial loss', 'revenue', 'cost', 'million', 'billion']):
            financial_impact = "High — potential significant financial losses, operational disruption, and recovery costs."
        elif any(term in content_lower for term in ['business', 'operations', 'service']):
            financial_impact = "Medium — potential business disruption and moderate recovery costs."
        else:
            financial_impact = "Low to Medium — limited direct financial impact, monitoring and response costs."
        
        # Data Loss/Exposure Assessment
        if any(term in content_lower for term in ['data breach', 'data leak', 'personal information', 'customer data']):
            data_exposure = "High — enables unauthorized data access that can lead to privacy violations, data breaches, and regulatory compliance issues."
        elif any(term in content_lower for term in ['information', 'access', 'disclosure']):
            data_exposure = "Medium — potential for limited data exposure and privacy concerns."
        else:
            data_exposure = "Low — minimal risk of direct data exposure, primarily system security concerns."
        
        # Reputational Risk Assessment
        if any(term in content_lower for term in ['public', 'customers', 'trust', 'brand']):
            reputational_risk = "High — impacts organizations relying on customer trust and brand reputation, especially in financial services."
        elif any(term in content_lower for term in ['service', 'availability', 'business']):
            reputational_risk = "Medium — potential impact on service reliability and customer confidence."
        else:
            reputational_risk = "Low to Medium — limited direct reputational impact, primarily operational concerns."
        
        return {
            'financial': financial_impact,
            'data_exposure': data_exposure,
            'reputational': reputational_risk
        }
    
    def extract_attack_methodology(self, content: str, keywords: List[str]) -> Dict[str, str]:
        """Extract attack methodology details from actual article content"""
        import re
        from bs4 import BeautifulSoup
        
        # Clean content
        if '<' in content and '>' in content:
            soup = BeautifulSoup(content, 'html.parser')
            content = soup.get_text(separator=' ', strip=True)
        
        content = re.sub(r'\s+', ' ', content).strip()
        content_lower = content.lower()
        
        # Extract Attack Outcome from actual content
        outcome_sentences = []
        sentences = re.split(r'(?<=[.!?])\s+', content)
        
        for sentence in sentences[:10]:  # Check first 10 sentences
            sentence_lower = sentence.lower()
            # Look for sentences about impact/outcome
            if any(word in sentence_lower for word in ['attackers', 'exploit', 'compromise', 'breach', 'gain', 'allows', 'enables', 'lead to', 'result in']):
                if len(sentence) > 30 and sentence.endswith(('.', '!', '?')):
                    outcome_sentences.append(sentence.strip())
                    if len(' '.join(outcome_sentences)) > 150:
                        break
        
        if outcome_sentences:
            outcome = ' '.join(outcome_sentences[:2])  # Use 1-2 sentences
        else:
            outcome = "Attack methodology details not specified in the source article."
        
        # Extract Tactics from actual content
        tactics_found = []
        tactics_patterns = {
            'phishing': ['phishing', 'spear phishing', 'email attack'],
            'social engineering': ['social engineering', 'social manipulation'],
            'malware deployment': ['malware', 'payload', 'backdoor', 'trojan'],
            'vulnerability exploitation': ['exploit', 'vulnerability', 'zero-day', 'CVE'],
            'ransomware': ['ransomware', 'encryption', 'ransom'],
            'supply chain attack': ['supply chain', 'third party', 'vendor compromise'],
            'credential theft': ['credentials', 'password', 'authentication bypass'],
            'remote code execution': ['remote code execution', 'RCE', 'arbitrary code']
        }
        
        for tactic_name, patterns in tactics_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                tactics_found.append(tactic_name)
        
        if tactics_found:
            tactics_text = ", ".join(tactics_found[:4])  # Limit to 4 tactics
        else:
            tactics_text = "Tactics not specified in the source article"
        
        return {
            'outcome': outcome,
            'tactics': tactics_text.capitalize()
        }
    
    def determine_mitigation_measures(self, threat_type: str, content: str) -> str:
        """Extract mitigation measures from actual article content"""
        import re
        from bs4 import BeautifulSoup
        
        # Clean content
        if '<' in content and '>' in content:
            soup = BeautifulSoup(content, 'html.parser')
            content = soup.get_text(separator=' ', strip=True)
        
        content = re.sub(r'\s+', ' ', content).strip()
        content_lower = content.lower()
        
        # Look for mitigation/recommendation sections in the article
        mitigation_sentences = []
        sentences = re.split(r'(?<=[.!?])\s+', content)
        
        for sentence in sentences:
            sentence_lower = sentence.lower()
            # Look for sentences about recommendations/mitigations
            if any(word in sentence_lower for word in [
                'recommend', 'should', 'advise', 'update', 'patch', 'fix', 
                'mitigate', 'protect', 'secure', 'implement', 'enable', 
                'disable', 'configure', 'upgrade', 'install'
            ]):
                if len(sentence) > 30 and sentence.endswith(('.', '!', '?')):
                    # Skip sentences with junk
                    if not re.match(r'^(By |Credit|Source|Posted|Advertisement)', sentence, re.IGNORECASE):
                        mitigation_sentences.append(sentence.strip())
                        if len(' '.join(mitigation_sentences)) > 300:
                            break
        
        if mitigation_sentences:
            # Join 2-3 mitigation sentences
            return ' '.join(mitigation_sentences[:3])
        else:
            # Minimal fallback if no recommendations found
            if 'patch' in content_lower or 'update' in content_lower:
                return "Apply available security patches and updates immediately."
            elif 'vulnerability' in content_lower:
                return "Review and assess impact on systems, apply vendor recommendations."
            else:
                return "Monitor for updates and follow vendor security advisories."
    
    def create_enhanced_summary(self, title: str, content: str, threat_type: str, keywords: List[str]) -> str:
        """Create clear, understandable summary - what is the news about in few lines"""
        try:
            import re
            from bs4 import BeautifulSoup
            
            # Check if content exists
            if not content or len(content.strip()) < 50:
                return f"Security threat identified: {title}."
            
            # Clean HTML tags if present
            if '<' in content and '>' in content:
                soup = BeautifulSoup(content, 'html.parser')
                content = soup.get_text(separator=' ', strip=True)
            
            # Clean up content - remove junk
            content = re.sub(r'(By|Author|Posted by|Written by|Credit|Source):\s*[^.!?]*[.!?]', '', content, flags=re.IGNORECASE)
            content = re.sub(r'(Advertisement|Sponsored|Subscribe|Click here|Read more)[^.!?]*[.!?]', '', content, flags=re.IGNORECASE)
            content = re.sub(r'\[[^\]]*\]', '', content)  # Remove [brackets]
            content = re.sub(r'\s+', ' ', content)  # Clean multiple spaces
            content = content.strip()
            
            # Split into clean sentences
            sentences = re.split(r'(?<=[.!?])\s+', content)
            
            # Filter and collect meaningful sentences
            good_sentences = []
            for sentence in sentences:
                sentence = sentence.strip()
                
                # Skip short or junk sentences
                if len(sentence) < 30:
                    continue
                
                # Skip sentences that start with junk
                if re.match(r'^(By |Credit|Source|Posted|Written|Subscribe|Click|Read more|Advertisement)', sentence, re.IGNORECASE):
                    continue
                
                # Must end with proper punctuation
                if not sentence.endswith(('.', '!', '?')):
                    continue
                
                # Skip if it's mostly numbers/dates without context
                if len(re.findall(r'\d', sentence)) > len(sentence) * 0.3:
                    continue
                
                good_sentences.append(sentence)
                
                # Stop after 2-3 good sentences (summary should be concise)
                if len(good_sentences) >= 3:
                    break
            
            if good_sentences:
                # Join with proper spacing
                summary = ' '.join(good_sentences)
                
                # Ensure proper ending
                if not summary.endswith(('.', '!', '?')):
                    summary += '.'
                
                # Keep reasonable length (2-3 sentences max)
                if len(summary) > 400:
                    # Truncate at last sentence within 400 chars
                    truncated = summary[:400]
                    last_end = max(truncated.rfind('.'), truncated.rfind('!'), truncated.rfind('?'))
                    if last_end > 150:
                        summary = summary[:last_end + 1]
                
                return summary
            else:
                # Fallback to title if no good sentences found
                return f"{title}."
            
        except Exception as e:
            return f"{title}."
    
    def create_authentic_description(self, title: str, content: str, threat_type: str) -> str:
        """Create detailed, understandable description - explain the news in more detail"""
        try:
            import re
            from bs4 import BeautifulSoup
            
            if not content or len(content.strip()) < 50:
                return f"Security threat identified: {title}."
            
            # Clean HTML tags if present
            if '<' in content and '>' in content:
                soup = BeautifulSoup(content, 'html.parser')
                content = soup.get_text(separator=' ', strip=True)
            
            # Clean up content thoroughly
            content = re.sub(r'(By|Author|Posted by|Written by|Credit|Source):\s*[^.!?]*[.!?]', '', content, flags=re.IGNORECASE)
            content = re.sub(r'(Advertisement|Sponsored|Subscribe|Click here|Read more)[^.!?]*[.!?]', '', content, flags=re.IGNORECASE)
            content = re.sub(r'Flipboard|Reddit|Whatsapp|Email', '', content, flags=re.IGNORECASE)
            content = re.sub(r'\[[^\]]*\]', '', content)  # Remove [brackets]
            content = re.sub(r'\s+', ' ', content)  # Clean multiple spaces
            content = content.strip()
            
            # Split into sentences
            sentences = re.split(r'(?<=[.!?])\s+', content)
            
            # Collect meaningful sentences for description (more than summary)
            good_sentences = []
            for sentence in sentences:
                sentence = sentence.strip()
                
                # Skip short sentences
                if len(sentence) < 30:
                    continue
                
                # Skip junk
                if re.match(r'^(By |Credit|Source|Posted|Written|Subscribe|Click|Read more|Advertisement)', sentence, re.IGNORECASE):
                    continue
                
                # Must end properly
                if not sentence.endswith(('.', '!', '?')):
                    continue
                
                # Skip if mostly numbers without context
                if len(re.findall(r'\d', sentence)) > len(sentence) * 0.3:
                    continue
                
                # Prefer sentences about security/threat content
                security_keywords = ['security', 'threat', 'vulnerability', 'attack', 'exploit', 'malware', 'breach', 'cve', 'patch', 'fix', 'update', 'risk', 'impact']
                sentence_lower = sentence.lower()
                
                # Add sentence if it has security context
                if any(keyword in sentence_lower for keyword in security_keywords):
                    good_sentences.append(sentence)
                elif len(good_sentences) < 3:  # Add first few sentences even without keywords
                    good_sentences.append(sentence)
                
                # Stop after 5-7 sentences (detailed but not too long)
                if len(good_sentences) >= 7:
                    break
            
            if good_sentences:
                # Join with proper spacing
                description = ' '.join(good_sentences)
                
                # Ensure proper ending
                if not description.endswith(('.', '!', '?')):
                    description += '.'
                
                # Keep reasonable length (more than summary, less than full article)
                if len(description) > 800:
                    # Truncate at last sentence within 800 chars
                    truncated = description[:800]
                    last_end = max(truncated.rfind('.'), truncated.rfind('!'), truncated.rfind('?'))
                    if last_end > 300:
                        description = description[:last_end + 1]
                
                return description
            else:
                # Fallback
                return f"Security threat identified: {title}."
            
        except Exception as e:
            return f"Security threat identified: {title}."
    
    def _clean_content_for_description(self, content: str) -> str:
        """Clean content for description generation"""
        import re
        from bs4 import BeautifulSoup
        
        # Remove HTML if present
        if '<' in content and '>' in content:
            soup = BeautifulSoup(content, 'html.parser')
            content = soup.get_text(separator=' ', strip=True)
        
        # Remove web artifacts
        content = re.sub(r'(Posted by|Written by|By:|Author:|Source:)[^.]*', '', content, flags=re.IGNORECASE)
        content = re.sub(r'(Tags:|Categories:|Filed under:)[^.]*', '', content, flags=re.IGNORECASE)
        content = re.sub(r'\[.*?\]', '', content)
        content = re.sub(r'(Advertisement|Sponsored)[^.]*', '', content, flags=re.IGNORECASE)
        
        # Clean whitespace
        content = ' '.join(content.split())
        
        return content.strip()
    
    def _clean_authentic_content(self, content: str) -> str:
        """Clean content to ensure authenticity - remove any placeholder text"""
        import re
        from bs4 import BeautifulSoup
        
        # Remove HTML if present
        if '<' in content and '>' in content:
            soup = BeautifulSoup(content, 'html.parser')
            content = soup.get_text(separator=' ', strip=True)
        
        # CRITICAL: Remove any placeholder/sample content patterns
        placeholders_to_remove = [
            r'Kubernetes Errors 101.*?troubleshoot.*?clusters.*?smoothly',
            r'practical guide for cloud.*?platform teams',
            r'sample.*?content.*?placeholder',
            r'lorem ipsum.*?dolor sit amet',
            r'this is a test.*?content',
            r'example.*?placeholder.*?text'
        ]
        
        for pattern in placeholders_to_remove:
            content = re.sub(pattern, '', content, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove common noise patterns
        content = re.sub(r'(Posted by|Written by|By:|Author:|Source:)[^.]*', '', content, flags=re.IGNORECASE)
        content = re.sub(r'(Share|Tweet|LinkedIn|Facebook)[^.]*', '', content, flags=re.IGNORECASE)
        content = re.sub(r'Read more.*|Continue reading.*', '', content, flags=re.IGNORECASE)
        content = re.sub(r'\s+', ' ', content)  # Normalize whitespace
        
        return content.strip()
    
    def _extract_authentic_threat_info(self, content: str, title: str, threat_type: str) -> str:
        """Extract authentic threat intelligence information from real content"""
        import re
        
        # Ensure content is clean and authentic
        if any(placeholder in content.lower() for placeholder in ['kubernetes errors', 'practical guide', 'troubleshooting', 'sample content']):
            return ""  # Reject any placeholder content
        
        threat_details = []
        
        # Extract CVE information
        cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', content, re.IGNORECASE)
        if cve_matches:
            threat_details.append(f"Vulnerability ID: {cve_matches[0]}")
        
        # Extract real impact information from actual content
        impact_patterns = [
            r'(affects|impacts|targets)\s+([^.]{20,80})',
            r'(allows|enables)\s+([^.]{20,80})',
            r'(researchers|experts|security teams)\s+(discovered|found|identified)\s+([^.]{20,80})'
        ]
        
        for pattern in impact_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches[:1]:  # Take first match
                    if isinstance(match, tuple):
                        detail = ' '.join(match).strip()
                        if len(detail) > 25 and not any(skip in detail.lower() for skip in ['kubernetes', 'troubleshoot', 'guide']):
                            threat_details.append(detail)
        
        # Extract technical details from authentic content
        tech_patterns = [
            r'(exploit|vulnerability|flaw)\s+in\s+([^.]{20,60})',
            r'(CVSS\s*(?:score)?[:\s]*\d+\.?\d*)',
            r'(critical|high|medium|low)\s+(severity|priority|risk)'
        ]
        
        for pattern in tech_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches[:1]:
                    if isinstance(match, tuple):
                        detail = ' '.join(match).strip()
                    else:
                        detail = match.strip()
                    if len(detail) > 10 and not any(skip in detail.lower() for skip in ['kubernetes', 'troubleshoot', 'guide']):
                        threat_details.append(detail)
        
        # Combine details into coherent summary using only authentic content
        if threat_details:
            return f"Security researchers have identified this {threat_type.lower()}. " + " ".join(threat_details[:3])
        else:
            # Use first two sentences of authentic content
            sentences = content.split('. ')[:2]
            authentic_summary = '. '.join(sentences)
            if len(authentic_summary) > 50:
                return authentic_summary
        
        return ""
    
    def _extract_key_threat_info(self, content: str, title: str, threat_type: str) -> str:
        """Extract key threat intelligence information"""
        import re
        
        threat_details = []
        
        # Extract CVE information
        cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', content, re.IGNORECASE)
        if cve_matches:
            threat_details.append(f"Vulnerability ID: {cve_matches[0]}")
        
        # Extract impact information
        impact_patterns = [
            r'(affects|impacts|targets)\s+([^.]{20,80})',
            r'(allows|enables)\s+([^.]{20,80})',
            r'(researchers|experts)\s+(discovered|found|identified)\s+([^.]{20,80})'
        ]
        
        for pattern in impact_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches[:1]:  # Take first match
                    if isinstance(match, tuple):
                        detail = ' '.join(match).strip()
                        if len(detail) > 25:
                            threat_details.append(detail)
        
        # Extract technical details
        tech_patterns = [
            r'(exploit|vulnerability|flaw)\s+in\s+([^.]{20,60})',
            r'(CVSS\s*(?:score)?[:\s]*\d+\.?\d*)',
            r'(critical|high|medium|low)\s+(severity|priority|risk)'
        ]
        
        for pattern in tech_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches[:1]:
                    if isinstance(match, tuple):
                        detail = ' '.join(match).strip()
                    else:
                        detail = match.strip()
                    if len(detail) > 10:
                        threat_details.append(detail)
        
        # Combine details into coherent summary
        if threat_details:
            summary = f"{threat_type} identified in {title}. "
            summary += '. '.join(threat_details[:3]) + '.'
            
            # Ensure reasonable length
            if len(summary) > 500:
                summary = summary[:500] + "..."
            
            return summary
        
        return ""
    
    def format_soc_report(self, article: Dict) -> ThreatReport:
        """Format article into structured SOC report"""
        
        # Extract basic information
        title = article.get('title', 'Unknown Threat')
        content = article.get('content', article.get('summary', ''))
        keywords = article.get('keywords', [])
        source_name = article.get('source', 'Unknown Source')
        source_url = article.get('url', '')
        relevance_score = article.get('relevance_score', 0)
        
        # Determine threat characteristics
        threat_type = self.determine_threat_type(title, content, keywords)
        cve_id = self.extract_cve_information(content)
        severity_rating = self.assess_severity_rating(relevance_score, keywords, content)
        
        # Impact assessments
        impacts = self.determine_impact_assessment(content, keywords)
        
        # Attack methodology
        attack_info = self.extract_attack_methodology(content, keywords)
        
        # Determine patch availability
        if cve_id:
            if any(term in content.lower() for term in ['patch', 'update', 'fixed', 'resolved']):
                patch_status = f"Security patches available (requires prompt deployment)"
            else:
                patch_status = f"Under investigation - monitor vendor advisory for updates"
        else:
            patch_status = "Review security configurations and implement recommended protections"
        
        # Determine exploited systems
        if any(term in content.lower() for term in ['windows', 'microsoft']):
            exploited_systems = "Windows-based systems, enterprise environments"
        elif any(term in content.lower() for term in ['linux', 'unix']):
            exploited_systems = "Linux/Unix systems, server environments"
        elif any(term in content.lower() for term in ['web', 'browser', 'online']):
            exploited_systems = "Web applications, online services, browser-based systems"
        elif any(term in content.lower() for term in ['mobile', 'android', 'ios']):
            exploited_systems = "Mobile devices, mobile applications"
        else:
            exploited_systems = f"{COMPANY_NAME} systems, enterprise infrastructure, networked environments"
        
        # Enhanced summary processing
        enhanced_summary = self.create_enhanced_summary(title, content, threat_type, keywords)
        
        # Create structured report
        report = ThreatReport(
            title=title,
            threat_type=threat_type,
            date_identified=datetime.now().strftime('%B %Y'),
            threat_summary=enhanced_summary,  # Use enhanced summary
            attack_outcome=attack_info['outcome'],
            tactics_used=attack_info['tactics'],
            data_loss_exposure=impacts['data_exposure'],
            financial_impact=impacts['financial'],
            reputational_risk=impacts['reputational'],
            cve_id=cve_id,
            description=self.create_authentic_description(title, content, threat_type),
            exploited_systems=exploited_systems,
            severity_rating=severity_rating,
            patch_availability=patch_status,
            mitigation_measures=self.determine_mitigation_measures(threat_type, content),
            source_url=source_url,
            source_name=source_name
        )
        
        return report
    
    def generate_soc_report_html(self, report: ThreatReport) -> str:
        """Generate professional Word-document style HTML SOC report"""
        
        # Generate unique report ID with ENFORCED 1-10 numbering
        if ENFORCE_NUMBERING_1_TO_10:
            # Reset counter daily and limit to 10
            today = datetime.now().strftime('%Y%m%d')
            report_num = ((self.daily_counter - 1) % 10) + 1  # Cycle 1-10
            report_id = f"TI-{today}-{report_num:02d}"
            self.daily_counter = (self.daily_counter % 10) + 1
        else:
            report_id = f"TI-{datetime.now().strftime('%Y%m%d')}-{self.report_id_counter:03d}"
            self.report_id_counter += 1
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Threat Intelligence Report - {report_id}</title>
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Calibri:wght@400;600;700&display=swap');
                
                body {{
                    font-family: 'Calibri', 'Segoe UI', Tahoma, sans-serif;
                    line-height: 1.4;
                    color: #1f1f1f;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 40px;
                    background: #ffffff;
                    font-size: 11pt;
                }}
                
                .document-container {{
                    background: white;
                    border: 1px solid #d4d4d4;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.08);
                    padding: 50px;
                    margin: 20px 0;
                }}
                
                .alert-header {{
                    background: linear-gradient(135deg, #c41e3a 0%, #8b0000 100%);
                    color: white;
                    padding: 20px;
                    text-align: center;
                    margin: -50px -50px 30px -50px;
                    font-weight: 700;
                    font-size: 14pt;
                    border-bottom: 4px solid #8b0000;
                }}
                
                .document-title {{
                    text-align: center;
                    color: #c41e3a;
                    font-size: 18pt;
                    font-weight: 700;
                    margin: 30px 0;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    border-bottom: 3px solid #c41e3a;
                    padding-bottom: 15px;
                }}
                
                .intro-section {{
                    background: #f8f9fa;
                    border-left: 6px solid #c41e3a;
                    padding: 25px;
                    margin: 30px 0;
                    font-size: 11pt;
                    line-height: 1.6;
                }}
                
                .intro-greeting {{
                    font-weight: 600;
                    color: #2c3e50;
                    margin-bottom: 15px;
                }}
                
                .shield-icon {{
                    font-size: 24px;
                    color: #c41e3a;
                    margin-right: 10px;
                    vertical-align: middle;
                }}
                
                .section-header {{
                    background: #93c5fd;
                    border-left: 4px solid #60a5fa;
                    padding: 15px;
                    margin: 25px 0 15px 0;
                    font-weight: 700;
                    color: #1e3a8a;
                    font-size: 12pt;
                }}
                
                .threat-overview {{
                    background: #f0f9ff;
                    border: 2px solid #93c5fd;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                }}
                
                .overview-title {{
                    color: #1e40af;
                    font-weight: 700;
                    font-size: 12pt;
                    margin-bottom: 15px;
                    display: flex;
                    align-items: center;
                }}
                
                .info-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 15px 0;
                    font-size: 10.5pt;
                }}
                
                .info-table td {{
                    padding: 8px 12px;
                    border-bottom: 1px solid #e9ecef;
                    vertical-align: top;
                }}
                
                .info-label {{
                    font-weight: 600;
                    color: #1e40af;
                    width: 180px;
                    background: #f0f9ff;
                }}
                
                .info-value {{
                    color: #212529;
                }}
                
                .severity-critical {{
                    background: #dc3545;
                    color: white;
                    padding: 6px 12px;
                    border-radius: 15px;
                    font-weight: 600;
                    font-size: 9pt;
                    display: inline-block;
                    text-transform: uppercase;
                }}
                
                .severity-high {{
                    background: #fd7e14;
                    color: white;
                    padding: 6px 12px;
                    border-radius: 15px;
                    font-weight: 600;
                    font-size: 9pt;
                    display: inline-block;
                    text-transform: uppercase;
                }}
                
                .severity-medium {{
                    background: #ffc107;
                    color: #000;
                    padding: 6px 12px;
                    border-radius: 15px;
                    font-weight: 600;
                    font-size: 9pt;
                    display: inline-block;
                    text-transform: uppercase;
                }}
                
                .cve-highlight {{
                    background: #f8d7da;
                    border: 2px solid #dc3545;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 15px 0;
                    font-weight: 600;
                    color: #721c24;
                }}
                
                .mitigation-box {{
                    background: #d1ecf1;
                    border: 2px solid #17a2b8;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                }}
                
                .mitigation-title {{
                    color: #0c5460;
                    font-weight: 700;
                    margin-bottom: 10px;
                }}
                
                .source-box {{
                    background: #e2e3e5;
                    border: 1px solid #6c757d;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 20px 0;
                }}
                
                .reference-note {{
                    background: #f0f9ff;
                    border-left: 4px solid #93c5fd;
                    padding: 20px;
                    margin: 25px 0;
                    font-style: italic;
                    color: #1e40af;
                }}
                
                .footer-section {{
                    border-top: 2px solid #dee2e6;
                    padding-top: 20px;
                    margin-top: 40px;
                    text-align: center;
                    color: #6c757d;
                    font-size: 10pt;
                }}
                
                .signature {{
                    font-weight: 600;
                    color: #2c3e50;
                    margin-bottom: 10px;
                }}
                
                .classification {{
                    background: #dc3545;
                    color: white;
                    padding: 8px 15px;
                    border-radius: 5px;
                    display: inline-block;
                    font-weight: 600;
                    margin: 10px 0;
                    font-size: 9pt;
                }}
                
                .clickable-button {{
                    background: #007bff;
                    color: white;
                    padding: 8px 15px;
                    text-decoration: none;
                    border-radius: 5px;
                    display: inline-block;
                    font-weight: 600;
                    margin: 5px 10px 5px 0;
                }}
                
                .page-break {{
                    page-break-before: always;
                }}
                
                @media print {{
                    body {{ margin: 0; padding: 20px; }}
                    .document-container {{ box-shadow: none; border: none; }}
                }}
            </style>
        </head>
        <body>
            <div class="document-container">
                <div class="alert-header">
                    🚨 WEEKLY CYBER WATCH 🚨
                </div>
                
                <div class="document-title">
                    <span class="shield-icon">🛡️</span>
                    Notable Global Cyber Threat – "{report.title}"
                </div>
                
                <div class="intro-section">
                    <div class="intro-greeting">Infosec Team,</div>
                    <p>As part of our ongoing effort to strengthen our security posture, please find below the summary of notable global cyber threats identified this week. The goal is to proactively identify vulnerabilities, assess and implement necessary measures (if applicable) to mitigate risks. Kindly review the details and ensure that our systems are safeguarded against these potential threats.</p>
                </div>
                
                <div class="section-header">
                    <span class="shield-icon">🛡️</span> Key Cyber Threats Overview
                </div>
                
                <div class="threat-overview">
                    <div class="overview-title">
                        <span style="margin-right: 10px;">1.</span>Threat Summary & Attack Methodology:
                    </div>
                    
                    <table class="info-table">
                        <tr>
                            <td class="info-label">Threat Type</td>
                            <td class="info-value">: {report.threat_type}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Date Identified</td>
                            <td class="info-value">: {report.date_identified}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Threat Summary</td>
                            <td class="info-value">: {report.threat_summary}</td>
                        </tr>
                    </table>
                </div>
                
                <div class="threat-overview">
                    <div class="overview-title">
                        <span style="margin-right: 10px;">2.</span>Realized Attacks & Potential Impacts:
                    </div>
                    
                    <table class="info-table">
                        <tr>
                            <td class="info-label">Attack Outcome</td>
                            <td class="info-value">: {report.attack_outcome}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Tactics Used</td>
                            <td class="info-value">: {report.tactics_used}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Data Loss/Exposure</td>
                            <td class="info-value">: {report.data_loss_exposure}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Financial Impact</td>
                            <td class="info-value">: {report.financial_impact}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Reputational Risk</td>
                            <td class="info-value">: {report.reputational_risk}</td>
                        </tr>
                    </table>
                </div>
                
                <div class="threat-overview">
                    <div class="overview-title">
                        <span style="margin-right: 10px;">3.</span>CVE & Mitigation Strategy:
                    </div>
                    
                    <table class="info-table">
                        <tr>
                            <td class="info-label">CVE-ID</td>
                            <td class="info-value">: {report.cve_id or 'Not yet assigned / Multiple vulnerabilities'}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Description</td>
                            <td class="info-value">: {report.description}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Exploited Systems</td>
                            <td class="info-value">: {report.exploited_systems}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Severity Rating</td>
                            <td class="info-value">: <span class="{'severity-critical' if 'Critical' in report.severity_rating else 'severity-high' if 'High' in report.severity_rating else 'severity-medium'}">{report.severity_rating}</span></td>
                        </tr>
                        <tr>
                            <td class="info-label">Patch Availability</td>
                            <td class="info-value">: {report.patch_availability}</td>
                        </tr>
                    </table>
                    
                    <div class="mitigation-box">
                        <div class="mitigation-title">Mitigation measures include</div>
                        <div>{report.mitigation_measures}</div>
                    </div>
                    
                    {f'<div class="cve-highlight"><strong>CVE Reference:</strong> {report.cve_id} - Monitor vendor advisories for updates and patches.</div>' if report.cve_id else ''}
                </div>
                
                <div class="source-box">
                    <div style="font-weight: 700; margin-bottom: 10px; color: #495057;">📎 Source Information:</div>
                    <table class="info-table">
                        <tr>
                            <td class="info-label">Source</td>
                            <td class="info-value">: {report.source_name}</td>
                        </tr>
                        <tr>
                            <td class="info-label">Original URL</td>
                            <td class="info-value">: <a href="{report.source_url}" class="clickable-button" target="_blank">View Original Article</a></td>
                        </tr>
                    </table>
                </div>
                
                <div class="reference-note">
                    <strong><a href="{report.source_url}" target="_blank" style="color: #0563C1; text-decoration: none;">Click, To know more →</a></strong><br><br>
                    Refer to the attached Excel document for detailed analysis of this threat. Should you have any questions, or if any assistance is needed to address the identified threats, feel free to reach out. Thank you for your continued attention to this matter and for your efforts in maintaining our security posture.
                </div>
                
                <div class="footer-section">
                    <div class="signature">
                        Best Regards,<br>
                        IA Team
                    </div>
                    
                    <div class="classification">
                        INTERNAL USE ONLY
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_template
    
    def generate_soc_report_text(self, report: ThreatReport) -> str:
        """Generate plain text version of SOC report"""
        
        # Generate unique report ID with ENFORCED 1-10 numbering
        if ENFORCE_NUMBERING_1_TO_10:
            # Reset counter daily and limit to 10
            today = datetime.now().strftime('%Y%m%d')
            report_num = ((self.daily_counter - 1) % 10) + 1  # Cycle 1-10
            report_id = f"TI-{today}-{report_num:02d}"
            self.daily_counter = (self.daily_counter % 10) + 1
        else:
            report_id = f"TI-{datetime.now().strftime('%Y%m%d')}-{self.report_id_counter:03d}"
        
        text_report = f"""
🔴 NOTABLE GLOBAL CYBER THREAT – "{report.title}"

{COMPANY_NAME} Security Operations Center
Report ID: {report_id}
Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}

=====================================================================

🛡️ Key Cyber Threats Overview

1. Threat Summary & Attack Methodology:

Threat Type        : {report.threat_type}
Date Identified    : {report.date_identified}
Threat Summary     : {report.threat_summary}

2. Realized Attacks & Potential Impacts:

Attack Outcome     : {report.attack_outcome}
Tactics Used       : {report.tactics_used}
Data Loss/Exposure : {report.data_loss_exposure}
Financial Impact   : {report.financial_impact}
Reputational Risk  : {report.reputational_risk}

3. CVE & Mitigation Strategy:

CVE-ID             : {report.cve_id or 'Not yet assigned / Multiple vulnerabilities'}
Description        : {report.description}
Exploited Systems  : {report.exploited_systems}
Severity Rating    : {report.severity_rating}
Patch Availability : {report.patch_availability}

Mitigation measures include{report.mitigation_measures}

📎 Source Information:
Source: {report.source_name}
URL: {report.source_url}

📋 Reference: Refer to the attached document to get more information about this threat. Should you have any questions, or if any assistance is needed to address the identified threats, feel free to reach out. Thank you for your continued attention to this matter and for your efforts in maintaining our security posture.

Best Regards,
{COMPANY_NAME} Information Security Team

=====================================================================
Classification: Internal Use Only
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """
        
        return text_report.strip()
    
    def generate_excel_attachment(self, report: ThreatReport, report_id: str) -> str:
        """
        Generate Excel file attachment for threat report
        Returns: Path to generated Excel file
        """
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
            from openpyxl.utils import get_column_letter
            import re
            
            # Create workbook
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Threat Analysis"
            
            # Define headers
            headers = [
                'Area', 'Issues', 'Issue Summary', 'Attack Methodology',
                'Potential Impact', 'Realized Impact', 'Recommendation',
                'Source', 'CVE', 'Date'
            ]
            
            # Add headers to first row
            for col_num, header in enumerate(headers, 1):
                cell = ws.cell(row=1, column=col_num)
                cell.value = header
                # Header styling - Blue background, white text, bold
                cell.fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
                cell.font = Font(bold=True, color="FFFFFF", size=11)
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
                cell.border = Border(
                    left=Side(style='thin'),
                    right=Side(style='thin'),
                    top=Side(style='thin'),
                    bottom=Side(style='thin')
                )
            
            # Prepare data for row 2
            # Column A: Area (Product name from title)
            area = self._extract_area_from_title(report.title)
            
            # Column B: Issues (CVE + severity + exploitation status)
            issues = self._format_issues(report.cve_id, report.severity_rating, report.threat_summary)
            
            # Column C: Issue Summary (threat summary)
            issue_summary = report.threat_summary
            
            # Column D: Attack Methodology (tactics used)
            attack_methodology = report.tactics_used
            
            # Column E: Potential Impact
            potential_impact = self._format_potential_impact(
                report.financial_impact,
                report.data_loss_exposure,
                report.reputational_risk
            )
            
            # Column F: Realized Impact
            realized_impact = self._extract_realized_impact(report.threat_summary, report.attack_outcome)
            
            # Column G: Recommendation (mitigation measures)
            recommendation = report.mitigation_measures
            
            # Column H: Source (URL)
            source = report.source_url
            
            # Column I: CVE
            cve = report.cve_id if report.cve_id else "N/A"
            
            # Column J: Date
            date = datetime.now().strftime('%B %d, %Y')
            
            # Add data to row 2
            data_row = [
                area, issues, issue_summary, attack_methodology,
                potential_impact, realized_impact, recommendation,
                source, cve, date
            ]
            
            for col_num, value in enumerate(data_row, 1):
                cell = ws.cell(row=2, column=col_num)
                cell.value = value
                # Data cell styling
                cell.font = Font(size=10)
                cell.alignment = Alignment(horizontal='left', vertical='top', wrap_text=True)
                cell.border = Border(
                    left=Side(style='thin'),
                    right=Side(style='thin'),
                    top=Side(style='thin'),
                    bottom=Side(style='thin')
                )
                
                # Add hyperlink to Source column (column 8)
                if col_num == 8 and source:
                    cell.hyperlink = source
                    cell.font = Font(size=10, color="0563C1", underline="single")
            
            # Set column widths
            column_widths = [25, 35, 50, 50, 40, 40, 45, 40, 18, 15]
            for i, width in enumerate(column_widths, 1):
                ws.column_dimensions[get_column_letter(i)].width = width
            
            # Set row heights
            ws.row_dimensions[1].height = 30  # Header row
            ws.row_dimensions[2].height = 100  # Data row (tall for wrapped text)
            
            # Generate filename from title
            safe_title = re.sub(r'[^\w\s-]', '', report.title)
            safe_title = re.sub(r'[-\s]+', '_', safe_title)
            safe_title = safe_title[:50]  # Limit length
            filename = f"{safe_title}_Threat_Analysis.xlsx"
            
            # Save file
            wb.save(filename)
            
            return filename
            
        except Exception as e:
            print(f"Error generating Excel file: {e}")
            return None
    
    def _extract_area_from_title(self, title: str) -> str:
        """Extract area/product name from title"""
        # Try to extract product name
        import re
        
        # Common patterns: "Product Name Vulnerability", "CVE in Product"
        patterns = [
            r'^([A-Za-z0-9\s/]+?)\s+(?:Vulnerability|CVE|Security)',
            r'in\s+([A-Za-z0-9\s/]+)',
            r'^([\w\s]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, title, re.IGNORECASE)
            if match:
                area = match.group(1).strip()
                if len(area) > 5:  # Reasonable length
                    return area + " Vulnerability"
        
        # Fallback
        return title[:50] + " Vulnerability"
    
    def _format_issues(self, cve_id: str, severity: str, summary: str) -> str:
        """Format issues column"""
        issues = []
        
        # Add severity
        if 'Critical' in severity:
            issues.append("Critical vulnerability")
        elif 'High' in severity:
            issues.append("High severity vulnerability")
        
        # Add CVE
        if cve_id:
            issues.append(f"({cve_id})")
        
        # Check for active exploitation
        if any(keyword in summary.lower() for keyword in ['actively exploit', 'active exploitation', 'being exploited']):
            issues.append("actively exploited")
        
        return " ".join(issues) if issues else "Security vulnerability"
    
    def _format_potential_impact(self, financial: str, data: str, reputational: str) -> str:
        """Format potential impact column"""
        impacts = []
        
        # Extract key points from each impact type
        if 'High' in financial:
            impacts.append("significant financial losses")
        if 'High' in data:
            impacts.append("data theft/exposure")
        if 'High' in reputational:
            impacts.append("reputational damage")
        
        # Add generic impacts
        impacts.extend([
            "business process disruption",
            "operational downtime",
            "regulatory penalties"
        ])
        
        return ", ".join(impacts[:6]) + "."
    
    def _extract_realized_impact(self, summary: str, outcome: str) -> str:
        """Extract realized impact (actual exploitation observed)"""
        text = f"{summary} {outcome}".lower()
        
        # Check for active exploitation keywords
        exploitation_keywords = [
            'actively exploited', 'active exploitation', 'being exploited',
            'exploited in the wild', 'attacks observed', 'attacks detected',
            'exploitation detected', 'confirmed exploitation'
        ]
        
        for keyword in exploitation_keywords:
            if keyword in text:
                # Try to extract more context
                sentences = (summary + " " + outcome).split('.')
                for sent in sentences:
                    if any(kw in sent.lower() for kw in exploitation_keywords):
                        return sent.strip() + "."
                
                return "Active exploitation observed in the wild; attackers able to compromise systems and gain unauthorized access."
        
        # No active exploitation mentioned
        return "No active exploitation reported"


# Create global formatter instance
soc_formatter = SOCReportFormatter()


if __name__ == "__main__":
    # Test the formatter
    test_article = {
        'id': 1,
        'title': 'Critical Cursor AI Code Editor Vulnerability Enables RCE via Malicious MCP File Swaps',
        'summary': 'A critical vulnerability (CVE-2025-54136) was discovered in the Cursor AI code editor that allows attackers to execute remote and persistent code by modifying a trusted MCP configuration file after it has been approved.',
        'content': 'A critical vulnerability (CVE-2025-54136) was discovered in the Cursor AI code editor that allows attackers to execute remote and persistent code by modifying a trusted MCP configuration file after it has been approved. The flaw exploits the trust model of MCP configurations, enabling attackers to silently replace a benign MCP file with a malicious payload, leading to undetected command execution.',
        'url': 'https://example.com/cursor-vulnerability',
        'source': 'Security Research',
        'relevance_score': 8.5,
        'keywords': ['cursor', 'vulnerability', 'rce', 'malicious', 'code execution']
    }
    
    report = soc_formatter.format_soc_report(test_article)
    html_report = soc_formatter.generate_soc_report_html(report)
    text_report = soc_formatter.generate_soc_report_text(report)
    
    print("SOC Report Generated Successfully!")
    print(f"Report Title: {report.title}")
    print(f"Threat Type: {report.threat_type}")
    print(f"Severity: {report.severity_rating}")
    
    # Save test reports
    with open('test_soc_report.html', 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    with open('test_soc_report.txt', 'w', encoding='utf-8') as f:
        f.write(text_report)
    
    print("Test reports saved as 'test_soc_report.html' and 'test_soc_report.txt'")
