"""Enhanced SOC Report Formatter - Authentic Content Only
Focuses on extracting REAL content from articles with clear, understandable summaries
"""

from datetime import datetime
from typing import Dict, List, Optional
import re
from dataclasses import dataclass, field
from bs4 import BeautifulSoup

from config import (
    COMPANY_NAME,
    SOC_EMAIL,
    ENFORCE_NUMBERING_1_TO_10,
    INFERENCE_URL,
    INFERENCE_TOKEN,
    INFERENCE_TIMEOUT,
    INFERENCE_FAILURE_LIMIT,
    INFERENCE_COOLDOWN_SECONDS,
)
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
    content_quality_score: float  # New field to track content quality
    # Quality/accuracy metadata (defaults keep all existing constructors working)
    is_roundup: bool = False  # True when source is a multi-threat digest/recap
    validation_warnings: List[str] = field(default_factory=list)  # Human-facing accuracy flags


class EnhancedSOCReportFormatter:
    """
    Enhanced report formatter that extracts AUTHENTIC content from articles
    Ensures summaries and descriptions clearly explain what the news is about
    """
    
    def __init__(self):
        self.report_id_counter = 1
        self.daily_counter = 1
        
        # Initialize AI models (lazy loading to avoid startup delay).
        # Unused when config.INFERENCE_URL is set — the models then live on a
        # separate host and these two calls go over HTTP instead. See
        # deploy/SPLIT-DEPLOYMENT.md.
        self._summarizer = None
        self._sentence_model = None
        self._ai_available = True

        # Remote-inference state. The Session is reused so a 50-article scrape
        # does one TCP handshake instead of fifty.
        self._inference_session = None
        self._inference_failures = 0
        self._inference_cooldown_until = 0.0
    
    def _get_summarizer(self):
        """Lazy load the AI summarization model"""
        if self._summarizer is None and self._ai_available:
            try:
                from transformers import pipeline
                print("🤖 Loading AI summarization model...")
                self._summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
                print("✅ AI summarization model loaded successfully")
            except Exception as e:
                print(f"⚠️ AI summarization unavailable: {e}")
                db.log_system_event('WARNING', f'AI summarization model failed to load: {e}', 'AI_FORMATTER')
                self._ai_available = False
                self._summarizer = False  # Mark as failed
        return self._summarizer if self._summarizer else None
    
    def _get_sentence_model(self):
        """Lazy load the sentence transformer model"""
        if self._sentence_model is None and self._ai_available:
            try:
                from sentence_transformers import SentenceTransformer
                print("🤖 Loading sentence similarity model...")
                self._sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
                print("✅ Sentence similarity model loaded successfully")
            except Exception as e:
                print(f"⚠️ Sentence similarity unavailable: {e}")
                db.log_system_event('WARNING', f'Sentence model failed to load: {e}', 'AI_FORMATTER')
                self._ai_available = False
                self._sentence_model = False  # Mark as failed
        return self._sentence_model if self._sentence_model else None
    
    def _inference_post(self, path: str, payload: dict) -> Optional[dict]:
        """POST to the remote inference service, or None if it is unusable.

        Returning None (rather than raising) keeps the existing contract: the
        caller falls back to a non-AI summary for this one article and the scrape
        continues.

        Two deliberate choices about failure:

        * `self._ai_available` is NOT flipped to False on a network error. That
          flag means "the models could not be loaded in this process", and it is
          sticky for the process lifetime — appropriate for a failed import, but
          a single blip on a peered VPC link should not disable AI summaries
          until someone restarts the dashboard.
        * Instead, a run of consecutive failures opens a cooldown. A dead
          inference box costs INFERENCE_FAILURE_LIMIT timeouts and then stops
          being asked for INFERENCE_COOLDOWN_SECONDS, rather than costing one
          timeout per article. It recovers on its own.
        """
        import time

        now = time.monotonic()
        if now < self._inference_cooldown_until:
            return None

        try:
            import requests

            if self._inference_session is None:
                self._inference_session = requests.Session()
                self._inference_session.headers.update(
                    {
                        "Authorization": f"Bearer {INFERENCE_TOKEN}",
                        "Content-Type": "application/json",
                    }
                )

            response = self._inference_session.post(
                f"{INFERENCE_URL}{path}",
                json=payload,
                timeout=INFERENCE_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

            self._inference_failures = 0
            return data

        except Exception as e:
            self._inference_failures += 1
            print(f"   ⚠️ Inference service call to {path} failed: {e}")

            if self._inference_failures >= INFERENCE_FAILURE_LIMIT:
                self._inference_cooldown_until = now + INFERENCE_COOLDOWN_SECONDS
                self._inference_failures = 0
                msg = (
                    f"Inference service unreachable after {INFERENCE_FAILURE_LIMIT} "
                    f"attempts ({e}). Falling back to non-AI summaries for "
                    f"{INFERENCE_COOLDOWN_SECONDS}s."
                )
                print(f"   ⚠️ {msg}")
                db.log_system_event('WARNING', msg, 'AI_FORMATTER')

            return None

    def _ai_summarize_article(self, content: str, max_length: int = 150) -> Optional[str]:
        """Use AI to generate authentic summary from article content"""
        try:
            # Prepare content (BART works best with 500-1024 tokens). Done here
            # in both modes — it is regex and BeautifulSoup, so the inference box
            # never needs this logic and never needs redeploying when it changes.
            content_clean = self.clean_article_content(content)
            if len(content_clean) < 100:
                return None

            # Truncate to reasonable length for summarization
            input_text = content_clean[:2000]

            if INFERENCE_URL:
                data = self._inference_post(
                    "/summarize",
                    {
                        "text": input_text,
                        "max_length": max_length,
                        "min_length": 50,
                    },
                )
                return (data or {}).get("summary") or None

            summarizer = self._get_summarizer()
            if not summarizer:
                return None

            # Generate summary
            summary = summarizer(input_text, max_length=max_length, min_length=50, do_sample=False)

            if summary and len(summary) > 0:
                return summary[0]['summary_text']

            return None

        except Exception as e:
            print(f"   ⚠️ AI summarization failed: {e}")
            db.log_system_event('WARNING', f'AI summarization error: {e}', 'AI_FORMATTER')
            return None

    def _extract_relevant_sentences(self, content: str, query: str, top_k: int = 3) -> List[str]:
        """Use semantic similarity to extract most relevant sentences for a given query"""
        try:
            # Clean and split content. Note this happens before either branch:
            # the remote service ranks candidate sentences, it does not parse
            # articles, so only the strings and the query cross the wire.
            content_clean = self.clean_article_content(content)
            sentences = self.extract_meaningful_sentences(content_clean, max_sentences=20)

            if not sentences:
                return []

            if INFERENCE_URL:
                data = self._inference_post(
                    "/rank",
                    {
                        "query": query,
                        "sentences": sentences,
                        "top_k": top_k,
                        "threshold": 0.3,
                    },
                )
                ranked = (data or {}).get("sentences") or []
                return [str(s) for s in ranked if str(s).strip()]

            model = self._get_sentence_model()
            if not model:
                return []

            import numpy as np
            from sklearn.metrics.pairwise import cosine_similarity

            # Encode query and sentences
            query_embedding = model.encode([query])
            sentence_embeddings = model.encode(sentences)

            # Calculate similarity
            similarities = cosine_similarity(query_embedding, sentence_embeddings)[0]

            # Get top K most similar sentences
            top_indices = np.argsort(similarities)[-top_k:][::-1]

            return [sentences[i] for i in top_indices if similarities[i] > 0.3]  # Threshold

        except Exception as e:
            print(f"   ⚠️ Semantic extraction failed: {e}")
            return []
    
    def _strip_article_numbering(self, title: str) -> str:
        """Remove article numbering like '02. ' or '1. ' from beginning of title"""
        if not title:
            return title
        import re
        # Remove patterns like '#01. ', '01. ', '1. ', '1) ', '(1) ', '02. ', etc.
        title = re.sub(r'^\s*#?\s*\(?\s*\d{1,3}\)?[\.:\)]\s*', '', str(title)).strip()
        return title
    
    # ========================================================================
    # CONTENT CLEANING - Remove noise, keep authentic content
    # ========================================================================
    
    def clean_article_content(self, content: str) -> str:
        """Deep clean article content to get only authentic text"""
        if not content:
            return ""
        
        # Remove HTML tags
        if '<' in content and '>' in content:
            soup = BeautifulSoup(content, 'html.parser')
            content = soup.get_text(separator=' ', strip=True)
        
        # Remove common web noise patterns
        noise_patterns = [
            r'(By|Author|Posted by|Written by|Credit|Source):\s*[^.!?]*[.!?]',
            r'(Advertisement|Sponsored|Subscribe|Click here|Read more)[^.!?]*[.!?]',
            r'Flipboard|Reddit|Whatsapp|Email|Tweet|Share|LinkedIn',
            r'Continue reading.*',
            r'\[[^\]]*\]',  # Remove [brackets]
            r'Tags?:\s*[^.!?]*',
            r'Categories?:\s*[^.!?]*',
            r'Filed under:\s*[^.!?]*',
        ]
        
        for pattern in noise_patterns:
            content = re.sub(pattern, '', content, flags=re.IGNORECASE)
        
        # Clean whitespace
        content = re.sub(r'\s+', ' ', content).strip()
        
        return content
    
    def extract_meaningful_sentences(self, content: str, min_sentences: int = 3, max_sentences: int = 10) -> List[str]:
        """Extract meaningful sentences from content"""
        if not content:
            return []
        
        # Split into sentences
        sentences = re.split(r'(?<=[.!?])\s+', content)
        
        meaningful_sentences = []
        for sentence in sentences:
            sentence = sentence.strip()
            
            # Quality checks
            if len(sentence) < 30:  # Too short
                continue
            
            if not sentence.endswith(('.', '!', '?')):  # No proper ending
                continue
            
            # Skip junk sentences
            junk_patterns = [
                r'^(By |Credit|Source|Posted|Written|Subscribe|Click|Read more|Advertisement)',
                r'^\d+\s*$',  # Just numbers
            ]
            if any(re.match(pattern, sentence, re.IGNORECASE) for pattern in junk_patterns):
                continue
            
            # Skip if mostly numbers without context
            if len(re.findall(r'\d', sentence)) > len(sentence) * 0.4:
                continue
            
            # This is a meaningful sentence
            meaningful_sentences.append(sentence)
            
            if len(meaningful_sentences) >= max_sentences:
                break
        
        return meaningful_sentences
    
    def assess_content_quality(self, content: str, title: str) -> float:
        """Assess the quality of extracted content (0.0 to 10.0)"""
        if not content or len(content.strip()) < 50:
            return 0.0
        
        content_lower = content.lower()
        
        score = 5.0  # Start with baseline
        
        # Check for promotional/advertisement content (penalize but don't auto-reject)
        # This allows sender to validate borderline content
        high_promotional_indicators = [
            'this new cheat sheet',
            'download our guide',
            'ci/cd pipeline security best practices',
            'owasp top 10 ci/cd',
            'get your free',
            'free guide download'
        ]
        
        mild_promotional_indicators = [
            'walks you through',
            'comprehensive guide',
            'best practices guide',
            'subscribe to our newsletter'
        ]
        
        # Penalize high promotional content (major penalty)
        for indicator in high_promotional_indicators:
            if indicator in content_lower:
                score -= 4.0  # Heavy penalty (will likely be < 1.5 and rejected)
                break
        
        # Penalize mild promotional content (minor penalty)  
        for indicator in mild_promotional_indicators:
            if indicator in content_lower:
                score -= 1.5  # Minor penalty (may still reach validation)
                break
        
        # Length check (good articles have substantial content)
        if len(content) > 500:
            score += 2.0
        elif len(content) > 200:
            score += 1.0
        
        # Sentence structure (good articles have multiple complete sentences)
        sentences = self.extract_meaningful_sentences(content)
        if len(sentences) >= 5:
            score += 2.0
        elif len(sentences) >= 3:
            score += 1.0
        
        # Technical indicators (good threat intel has specific details)
        technical_indicators = [
            r'CVE-\d{4}-\d{4,7}',  # CVE IDs
            r'CVSS',  # Severity scores
            r'vulnerability|exploit|malware|ransomware|phishing',
            r'patch|update|mitigation',
            r'attack|threat|breach|compromise',
        ]
        
        indicator_count = sum(1 for pattern in technical_indicators if re.search(pattern, content, re.IGNORECASE))
        score += min(indicator_count * 0.5, 2.0)  # Max 2 points
        
        # Cap at 10.0
        return min(score, 10.0)
    
    # ========================================================================
    # AUTHENTIC SUMMARY CREATION
    # ========================================================================
    
    def create_clear_summary(self, title: str, content: str, threat_type: str) -> tuple[str, float]:
        """
        Create clear, understandable summary that explains what the news is about
        Uses AI summarization with fallback to regex extraction
        Returns: (summary, quality_score)
        """
        # Clean content first
        clean_content = self.clean_article_content(content)
        
        # Assess quality
        quality_score = self.assess_content_quality(clean_content, title)
        
        if quality_score < 3.0:
            # Content quality too low - use title with minimal enhancement
            return f"{title}. Please refer to the original article for complete details.", quality_score
        
        # TRY AI SUMMARIZATION FIRST (most authentic)
        ai_summary = self._ai_summarize_article(clean_content, max_length=130)
        if ai_summary and len(ai_summary.strip()) > 50:
            print(f"   🤖 AI-generated authentic summary: {ai_summary[:80]}...")
            # Ensure proper ending
            if not ai_summary.endswith(('.', '!', '?')):
                ai_summary += '.'
            return ai_summary, quality_score
        
        # FALLBACK: Extract meaningful sentences (original method)
        print(f"   📝 Using fallback sentence extraction")
        sentences = self.extract_meaningful_sentences(clean_content, min_sentences=2, max_sentences=5)
        
        if not sentences:
            return f"{title}. Please refer to the original article for complete details.", quality_score
        
        # Build summary from first 2-3 sentences (this is the core of the news)
        summary_sentences = sentences[:3]
        summary = ' '.join(summary_sentences)
        
        # Ensure proper ending
        if not summary.endswith(('.', '!', '?')):
            summary += '.'
        
        # Keep reasonable length (2-3 sentences, ~400 chars)
        if len(summary) > 400:
            truncated = summary[:400]
            last_period = max(truncated.rfind('.'), truncated.rfind('!'), truncated.rfind('?'))
            if last_period > 150:
                summary = summary[:last_period + 1]
            else:
                # If we can't truncate nicely, take first 2 sentences
                summary = ' '.join(sentences[:2])
                if not summary.endswith(('.', '!', '?')):
                    summary += '.'
        
        return summary, quality_score
    
    def create_detailed_description(self, title: str, content: str, threat_type: str) -> str:
        """
        Create detailed description that explains the news in depth
        Uses AI for longer summarization with fallback to sentence extraction
        """
        # Clean content first
        clean_content = self.clean_article_content(content)
        
        # TRY AI SUMMARIZATION FIRST (longer version for description)
        ai_description = self._ai_summarize_article(clean_content, max_length=250)
        if ai_description and len(ai_description.strip()) > 100:
            print(f"   🤖 AI-generated detailed description: {ai_description[:80]}...")
            if not ai_description.endswith(('.', '!', '?')):
                ai_description += '.'
            return ai_description
        
        # FALLBACK: Extract meaningful sentences (original method)
        print(f"   📝 Using fallback sentence extraction for description")
        sentences = self.extract_meaningful_sentences(clean_content, min_sentences=5, max_sentences=15)
        
        if len(sentences) < 3:
            # Not enough content - use what we have
            if sentences:
                return ' '.join(sentences)
            else:
                return f"{title}. This is a security threat that requires immediate attention. Please refer to the original article for complete details."
        
        # FIXED: Build comprehensive description from DIFFERENT parts of article
        # Extract from beginning, middle, and end to avoid duplication with threat_summary
        total_sentences = len(sentences)
        
        # Take sentences from different positions
        description_sentences = []
        
        if total_sentences >= 7:
            # Take from beginning (1-2 sentences)
            description_sentences.extend(sentences[0:2])
            # Take from middle (2-3 sentences)
            mid_start = total_sentences // 2
            description_sentences.extend(sentences[mid_start:mid_start+3])
            # Take from end (1-2 sentences)
            description_sentences.extend(sentences[-2:])
        elif total_sentences >= 5:
            # Take every other sentence for variety
            description_sentences = sentences[::2][:5]
        else:
            # Use all available sentences
            description_sentences = sentences
        
        description = ' '.join(description_sentences)
        
        # Ensure proper ending
        if not description.endswith(('.', '!', '?')):
            description += '.'
        
        # Keep reasonable length (500-800 chars)
        if len(description) > 800:
            truncated = description[:800]
            last_period = max(truncated.rfind('.'), truncated.rfind('!'), truncated.rfind('?'))
            if last_period > 400:
                description = description[:last_period + 1]
        
        return description
    
    # ========================================================================
    # EXTRACT SPECIFIC THREAT DETAILS
    # ========================================================================
    
    # Section markers used by news roundups/digests (e.g. The Hacker News
    # "Weekly Recap"). Used both to detect digests and to isolate the lead item.
    _ROUNDUP_LEAD_MARKERS = [
        'threat of the week', 'top story', 'story of the week',
    ]
    _ROUNDUP_NEXT_SECTION_MARKERS = [
        'top news', 'other news', 'around the cyber world', 'trending cves',
        'cybersecurity webinars', 'expert webinar', 'cybersecurity tools',
        'tip of the week', 'patch tuesday', 'in other news',
    ]
    _ROUNDUP_TITLE_MARKERS = [
        'weekly recap', 'recap:', 'roundup', 'week in review', 'in review',
        'top news', 'this week in', 'cybersecurity recap',
    ]

    def extract_cve_ids(self, content: str) -> List[str]:
        """Extract unique CVE IDs from content, preserving first-seen order.

        IMPORTANT: order must be deterministic. The previous implementation
        returned list(set(...)), whose order is arbitrary, which caused the
        wrong CVE to be reported as the primary one.
        """
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, content, re.IGNORECASE)
        # Normalise to upper-case and de-dupe while keeping first-seen order.
        return list(dict.fromkeys(c.upper() for c in cves))

    def select_primary_cve(self, content: str) -> Optional[str]:
        """Pick the CVE the article is actually *about*, deterministically.

        Articles often mention several CVEs in passing (related advisories,
        historical fixes, other items in a digest). We score each CVE by how
        strongly the prose ties it to the main subject:
          - directly introduced with "tracked as" / "identified as"           (+10)
          - immediately followed by a CVSS score, e.g. "CVE-… (CVSS 8.8)"      (+6)
          - number of times it is mentioned                                   (+1 each)
          - appears early in the text                                         (+2)
        Ties break toward the earliest mention.
        """
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        matches = list(re.finditer(cve_pattern, content, re.IGNORECASE))
        if not matches:
            return None

        text_lower = content.lower()
        total_len = max(len(content), 1)

        # Count occurrences per CVE (case-insensitive).
        counts: Dict[str, int] = {}
        for m in matches:
            key = m.group(0).upper()
            counts[key] = counts.get(key, 0) + 1

        best_cve = None
        best_score = float('-inf')
        best_pos = None

        seen_for_first_pos = {}
        for m in matches:
            cve = m.group(0).upper()
            start, end = m.start(), m.end()
            if cve not in seen_for_first_pos:
                seen_for_first_pos[cve] = start

            score = counts[cve]  # base: frequency

            # Look just before the CVE for an introducing phrase.
            before = text_lower[max(0, start - 30):start]
            if any(p in before for p in ('tracked as', 'identified as', 'assigned', 'designated', 'dubbed')):
                score += 10

            # Look just after for a CVSS score binding.
            after = text_lower[end:end + 25]
            if 'cvss' in after:
                score += 6

            # Earlier mentions are more likely to be the headline subject.
            if seen_for_first_pos[cve] < total_len * 0.34:
                score += 2

            pos = seen_for_first_pos[cve]
            if score > best_score or (score == best_score and (best_pos is None or pos < best_pos)):
                best_score = score
                best_cve = cve
                best_pos = pos

        return best_cve

    def detect_roundup(self, title: str, content: str) -> bool:
        """Detect multi-threat digest/recap articles that must NOT be rendered
        as a single-threat report without isolating one item first."""
        title_lower = (title or '').lower()
        content_lower = (content or '').lower()

        if any(marker in title_lower for marker in self._ROUNDUP_TITLE_MARKERS):
            return True

        # Structural digest markers in the body.
        if any(marker in content_lower for marker in self._ROUNDUP_LEAD_MARKERS):
            return True
        if 'scroll through' in content_lower and 'recap' in content_lower:
            return True

        # Several distinct CVEs is a strong signal of a digest.
        if len(self.extract_cve_ids(content)) >= 3:
            return True

        return False

    def scope_to_lead_item(self, content: str, primary_cve: Optional[str] = None) -> str:
        """For a digest, return only the lead item's text so every downstream
        extractor (summary, CVE, attack outcome, mitigation, systems) operates
        on ONE coherent threat instead of bleeding across stories/CVEs.

        Two isolation strategies, tried in order:
          1. Inline multi-CVE bulletins (e.g. "CISA adds N flaws to KEV", where
             CVEs are listed as "CVE-A (CVSS) - … CVE-B (CVSS) - …") have no
             newsletter section headers, so marker slicing below can't help.
             Isolate the segment describing the PRIMARY CVE specifically.
          2. Newsletter recaps (e.g. Hacker News Weekly Recap) use section
             headers ("threat of the week" … "in other news"); slice between them.

        Falls back to the original content if neither applies.
        """
        if not content:
            return content

        # Strategy 1: isolate the primary CVE's own text from an inline CVE list.
        cve_scoped = self._scope_to_cve_segment(content, primary_cve)
        if cve_scoped is not None:
            return cve_scoped

        # Strategy 2: newsletter section-marker slicing.
        lower = content.lower()

        # Find the start of the lead item.
        lead_start = -1
        for marker in self._ROUNDUP_LEAD_MARKERS:
            idx = lower.find(marker)
            if idx != -1:
                lead_start = idx + len(marker)
                break

        if lead_start == -1:
            # No explicit lead marker. As a safe fallback, keep text up to the
            # first "next section" marker so we at least drop later stories.
            for marker in self._ROUNDUP_NEXT_SECTION_MARKERS:
                idx = lower.find(marker)
                if idx != -1:
                    return content[:idx].strip()
            return content

        # Find where the lead item ends (next section marker after lead_start).
        lead_end = len(content)
        for marker in self._ROUNDUP_NEXT_SECTION_MARKERS:
            idx = lower.find(marker, lead_start)
            if idx != -1:
                lead_end = min(lead_end, idx)

        lead = content[lead_start:lead_end].strip(' -–—:\n\t')
        # Guard against a too-short slice (bad parse) — fall back to full text.
        return lead if len(lead) >= 80 else content

    def _scope_to_cve_segment(self, content: str, primary_cve: Optional[str] = None) -> Optional[str]:
        """Isolate the text describing ONE CVE from an inline multi-CVE bulletin.

        Advisories like "CISA adds N flaws to KEV" enumerate several CVEs
        back-to-back with no section headers:

            … listed below - CVE-A (CVSS 10.0) - <A desc>. CVE-B (CVSS 6.1) -
            <B desc>. CVE-C - <C desc>. …

        Running the field extractors over that whole blob makes each field bind
        to a different CVE (wrong product, mixed attack outcome). Here we keep
        only the intro framing plus the PRIMARY CVE's own segment — from its
        first mention up to the next DIFFERENT CVE — dropping the other stories.

        Returns None when the content is not an inline list of >=2 distinct CVEs,
        so the caller can fall back to other scoping strategies.
        """
        matches = list(re.finditer(r'CVE-\d{4}-\d{4,7}', content, re.IGNORECASE))
        positions = [(m.group(0).upper(), m.start()) for m in matches]
        distinct = list(dict.fromkeys(cve for cve, _ in positions))
        if len(distinct) < 2:
            return None  # single-CVE (or none) — nothing to isolate here

        first_pos: Dict[str, int] = {}
        for cve, pos in positions:
            first_pos.setdefault(cve, pos)

        primary = (primary_cve or '').upper()
        if primary not in first_pos:
            primary = distinct[0]  # deterministic fallback: earliest-mentioned

        first_cve_start = min(first_pos.values())
        p_start = first_pos[primary]
        # The primary CVE's description ends at the next DIFFERENT CVE mention.
        next_start = min(
            (pos for cve, pos in positions if cve != primary and pos > p_start),
            default=len(content),
        )

        if p_start <= first_cve_start:
            # Primary is the first CVE: intro + its segment are already contiguous.
            focus = content[:next_start]
        else:
            # Primary appears later: keep the intro framing + the primary's segment.
            intro = content[:first_cve_start].strip()
            segment = content[p_start:next_start].strip()
            focus = (intro + ' ' + segment) if intro else segment

        focus = focus.strip(' -–—:\n\t')
        # Guard against a bad/too-short slice — fall back to full text.
        return focus if len(focus) >= 60 else content

    def extract_attack_details_from_content(self, content: str) -> Dict[str, str]:
        """Extract actual attack details from article content using AI semantic search"""
        # Clean content first (needed for fallback)
        clean_content = self.clean_article_content(content)
        
        # TRY AI SEMANTIC SEARCH FIRST
        outcome_query = "What is the attack outcome? What can attackers do with this vulnerability?"
        outcome_sentences = self._extract_relevant_sentences(content, outcome_query, top_k=2)
        
        if outcome_sentences:
            print(f"   🤖 AI-extracted attack outcome: {outcome_sentences[0][:80]}...")
            attack_outcome = ' '.join(outcome_sentences)
        else:
            # FALLBACK: Keyword-based extraction
            print(f"   📝 Using fallback keyword-based attack extraction")
            sentences = self.extract_meaningful_sentences(clean_content, max_sentences=20)
            
            if not sentences:
                return {
                    'outcome': 'Details available in the original article.',
                    'tactics': 'Attack methodology described in source material.'
                }
            
            # Find sentences about attack outcomes/impacts
            outcome_keywords = ['allows', 'enables', 'results in', 'leads to', 'attackers can', 
                               'exploit', 'compromise', 'gain access', 'execute', 'breach']
            outcome_sentences_fb = []
            
            for sentence in sentences:
                if any(keyword in sentence.lower() for keyword in outcome_keywords):
                    outcome_sentences_fb.append(sentence)
                    if len(' '.join(outcome_sentences_fb)) > 200:
                        break
            
            # FIXED: If no outcome keywords found, use MIDDLE sentences (not first sentence)
            if outcome_sentences_fb:
                attack_outcome = ' '.join(outcome_sentences_fb[:2])
            elif len(sentences) > 3:
                # Use middle sentences (skip first 2, take next 2)
                attack_outcome = ' '.join(sentences[2:4])
            elif sentences:
                attack_outcome = sentences[0]
            else:
                attack_outcome = 'Details available in the original article.'
        
        # Strip a leading connective so the outcome doesn't read as a mid-paragraph
        # fragment (e.g. "However, successful exploitation hinges on...").
        attack_outcome = self._strip_leading_connective(attack_outcome)

        # Extract tactics/techniques mentioned (use cleaned content)
        tactic_keywords = {
            'phishing': ['phishing', 'spear phishing'],
            'malware': ['malware', 'trojan', 'backdoor'],
            'ransomware': ['ransomware', 'encryption'],
            'vulnerability exploitation': ['exploit', 'vulnerability', 'zero-day'],
            'social engineering': ['social engineering'],
            'supply chain attack': ['supply chain'],
            'remote code execution': ['remote code execution', 'rce', 'arbitrary code']
        }

        content_lower = clean_content.lower()
        found_tactics = []
        for tactic_name, keywords in tactic_keywords.items():
            if any(keyword in content_lower for keyword in keywords):
                found_tactics.append(tactic_name)

        # Credential theft is only a real tactic when credentials are STOLEN,
        # not when valid credentials are merely a precondition for exploiting an
        # authenticated bug. Require an explicit theft/abuse signal.
        if self._mentions_credential_theft(content_lower):
            found_tactics.append('credential theft')

        tactics_used = ', '.join(found_tactics) if found_tactics else 'Attack techniques described in source material'

        return {
            'outcome': attack_outcome,
            'tactics': tactics_used.capitalize()
        }

    # Leading connectives that make an extracted sentence read as a torn-out
    # fragment (e.g. "However, successful exploitation...").
    _LEADING_CONNECTIVE_RE = re.compile(
        r'^\s*(?:however|but|moreover|furthermore|additionally|that said|'
        r'nevertheless|nonetheless|in addition|also)\b[\s,]*',
        flags=re.IGNORECASE,
    )

    @classmethod
    def _strip_leading_connective(cls, text: str) -> str:
        """Remove a dangling leading connective so the sentence reads standalone.

        Only the FIRST character is upper-cased — we must NOT use str.capitalize(),
        which lower-cases the rest and would mangle acronyms like CVE / CVSS and
        proper nouns mid-sentence.
        """
        if not text or not cls._LEADING_CONNECTIVE_RE.match(text):
            return text
        stripped = cls._LEADING_CONNECTIVE_RE.sub('', text, count=1).strip()
        if not stripped:
            return text
        return stripped[0].upper() + stripped[1:]

    @staticmethod
    def _mentions_credential_theft(content_lower: str) -> bool:
        """True only when the text indicates credentials are stolen/abused —
        NOT when valid credentials are a precondition of exploitation."""
        theft_signals = [
            'steal credential', 'stolen credential', 'credential theft',
            'credential harvest', 'harvest credential', 'dump credential',
            'credential dump', 'leaked credential', 'credential stuffing',
            'phish for credential', 'capture credential', 'exfiltrate credential',
            'compromised credential', 'password theft', 'steal password',
            'stolen password', 'infostealer', 'info-stealer', 'stealer malware',
        ]
        return any(sig in content_lower for sig in theft_signals)
    
    # Newsletter / navigational boilerplate that must never be presented as a
    # mitigation step (this is what produced the "Scroll through the full
    # Monday Cybersecurity Recap..." mitigation).
    _FILLER_MARKERS = [
        'scroll through', 'recap below', 'recap for', 'this week is the same',
        'threat of the week', 'top news', 'worth your time', 'newsletter',
        'subscribe', 'read more', 'catch up', "here's what", 'let us dive',
        "let's dive", 'tl;dr', 'stay tuned', 'in this article', 'full story',
        'below for the news', 'lesson in a new form', 'stuff broke',
    ]

    def _is_filler_sentence(self, sentence: str) -> bool:
        s = sentence.lower()
        return any(marker in s for marker in self._FILLER_MARKERS)

    def extract_mitigation_from_content(self, content: str) -> str:
        """Extract actionable mitigation guidance, filtering out newsletter/recap
        boilerplate and preferring concrete patch/upgrade instructions."""
        clean_content = self.clean_article_content(content)

        # 1) Most actionable: concrete upgrade targets stated in the article.
        fixed_versions = self._extract_fixed_versions(clean_content)
        patch_instruction = ''
        if fixed_versions:
            patch_instruction = (
                "Apply the vendor security update — upgrade to a fixed release: "
                + ', '.join(fixed_versions[:8]) + ". "
            )

        # 2) Candidate recommendation sentences (AI semantic first, then keyword).
        candidates = self._extract_relevant_sentences(
            content, "What are the recommended mitigation steps, patches, updates, or security measures?",
            top_k=4,
        )
        if not candidates:
            sentences = self.extract_meaningful_sentences(clean_content, max_sentences=25)
            mitigation_keywords = [
                'recommend', 'should', 'advise', 'update', 'patch', 'fix',
                'mitigate', 'protect', 'secure', 'implement', 'apply',
                'disable', 'enable', 'configure', 'upgrade', 'install', 'audit',
            ]
            candidates = [s for s in sentences
                          if any(k in s.lower() for k in mitigation_keywords)]

        # 3) Drop filler/boilerplate sentences.
        candidates = [s for s in candidates if not self._is_filler_sentence(s)]

        # 3b) Drop status/disclosure sentences (KEV cataloging, "citing evidence
        # of active exploitation") — they describe an agency action, not an
        # actionable remediation step.
        catalog_markers = (
            'known exploited vulnerabilities', 'kev catalog', 'to its known exploited',
            'citing evidence', 'added a maximum-severity', 'added a maximum severity',
            'added to its', 'to its catalog',
        )
        candidates = [s for s in candidates
                      if not any(m in s.lower() for m in catalog_markers)]

        guidance = ''
        if candidates:
            guidance = ' '.join(candidates[:3])

        result = (patch_instruction + guidance).strip()
        if result:
            return result

        # 4) Minimal safe fallback.
        if 'patch' in clean_content.lower() or 'update' in clean_content.lower():
            return 'Apply available security patches and updates. Refer to the vendor advisory for specific steps.'
        return 'Review vendor security advisories for mitigation guidance.'
    
    def extract_exploited_systems(self, content: str, title: str) -> str:
        """Extract the affected product (and affected versions) from content.

        Returns a product-centric string and NEVER a torn fragment such as
        "Chrome 0" (which the old version produced from "Chrome 0-Day").
        """
        clean_content = self.clean_article_content(content)

        product = self._extract_affected_product(clean_content)
        affected_versions = self._extract_affected_versions(clean_content)

        if product and affected_versions:
            return f"{product} (Release {', '.join(affected_versions[:6])} and earlier)"
        if product:
            return product
        if affected_versions:
            return f"Affected releases: {', '.join(affected_versions[:6])} and earlier"

        # Headlines usually name the product ("...Joomla JCE Flaw...").
        title_product = self._product_from_title(title)
        if title_product:
            return title_product

        # Last resort: a clean sentence that NAMES affected systems — but never a
        # disclosure/cataloging sentence (e.g. "added ... to the KEV catalog"),
        # which describes an agency action, not the affected product.
        catalog_markers = (
            'known exploited vulnerabilities', 'kev catalog', 'to its known exploited',
            'citing evidence', 'added a maximum-severity', 'added a maximum severity',
        )
        sentences = self.extract_meaningful_sentences(clean_content, max_sentences=12)
        system_keywords = ['affect', 'runs on', 'deployment', 'installation', 'all versions', 'prior to', 'used by']
        for sentence in sentences:
            low = sentence.lower()
            if any(m in low for m in catalog_markers):
                continue
            if any(keyword in low for keyword in system_keywords):
                return sentence

        return "Refer to the source advisory for the specific affected products and versions."

    def _product_from_title(self, title: str) -> Optional[str]:
        """Best-effort product name from a headline, e.g.
        'CISA Warns of Actively Exploited Joomla JCE Flaw ...' -> 'Joomla JCE'."""
        if not title:
            return None
        head = self._strip_article_numbering(title)
        # The product usually precedes the vulnerability noun.
        m = re.search(r'(.*?)\s+(?:flaws?|vulnerabilit|bugs?|rce|zero-?days?|exploit|0-?days?|defects?)',
                      head, re.IGNORECASE)
        if m:
            head = m.group(1)
        # Strip leading source/agency/verb noise, repeatedly.
        noise = (r'(?:cisa|fbi|nsa|cert-in|microsoft|google|apple|adobe|new|critical|'
                 r'high-severity|max(?:imum)?-?severity|active(?:ly)?|exploited|warns?|warning|'
                 r'of|the|a|an|patch(?:es|ed)?|update[sd]?|hackers?|researchers?|attackers?|'
                 r'reportedly|now|multiple|several)')
        prev = None
        while prev != head:
            prev = head
            head = re.sub(rf'^{noise}\b[\s:,\-]*', '', head, flags=re.IGNORECASE).strip()
        pm = re.search(r"[A-Z][\w.\-]*(?:\s+[A-Z0-9][\w.\-]*){0,3}", head)
        prod = pm.group(0).strip(' ,.:;-') if pm else ''
        return prod if 3 <= len(prod) <= 60 else None

    @staticmethod
    def _extract_affected_product(content: str) -> Optional[str]:
        """Pull the product the vulnerability is 'in'/'affects' as a proper-noun
        phrase, case-sensitively so we capture real product names."""
        # Trigger phrases located case-insensitively; capture stays case-sensitive.
        triggers = [
            r'vulnerabilit(?:y|ies)\s+in\s+',
            r'flaw\s+in\s+',
            r'bug\s+in\s+',
            r'weakness\s+in\s+',
            r'defect\s+in\s+',
            r'(?:resides?|exists?|present|discovered|found)\s+in\s+(?:the\s+)?',
            r'(?:affects?|affecting|impacts?|impacting|targets?|targeting)\s+',
        ]
        lead_noise = re.compile(r'^(?:the\s+|a\s+|an\s+|web\s+ui\s+of\s+)+', re.IGNORECASE)
        # A proper-noun product phrase: capitalised tokens, allowing connectors.
        prop = re.compile(r'[A-Z][\w.\'/&-]*(?:\s+(?:[A-Z0-9][\w.\'/&-]*|for|of))*')

        candidates = []
        for trig in triggers:
            for m in re.finditer(trig, content, re.IGNORECASE):
                rest = lead_noise.sub('', content[m.end():])
                pm = prop.match(rest)
                if not pm:
                    continue
                prod = pm.group(0).strip(' ,.;:')
                # Drop trailing filler ("formerly ...", "version ...", "and earlier", "to its ...").
                prod = re.sub(
                    r'\s+(?:formerly|version|releases?|and\s+earlier|that|which|could|to\s+its).*$',
                    '', prod, flags=re.IGNORECASE
                ).strip()
                # Accept multi-word names, all-caps acronyms (e.g. "JCE"), or long single words.
                if 3 <= len(prod) <= 70 and ((' ' in prod) or (prod.isupper() and len(prod) >= 3) or len(prod) >= 5):
                    candidates.append(prod)
        if candidates:
            # Prefer the most specific name: multi-word first, then longer.
            candidates.sort(key=lambda p: (' ' in p, len(p)), reverse=True)
            return candidates[0]
        return None

    @staticmethod
    def _extract_affected_versions(content: str) -> List[str]:
        """Affected version ceilings stated as 'Release X and earlier'.

        Deliberately only matches dotted versions, so '0' from '0-Day' is never
        captured as a version."""
        rels = re.findall(r'(?:Release|version)\s+(\d+(?:\.\d+){1,4})\s+and\s+earlier', content, re.IGNORECASE)
        return list(dict.fromkeys(rels))

    @staticmethod
    def _extract_fixed_versions(content: str) -> List[str]:
        """Patched versions stated as 'Fixed in X' — the actual upgrade targets."""
        fixes = re.findall(r'[Ff]ixed in\s+v?(\d+(?:\.\d+){1,4})', content)
        return list(dict.fromkeys(fixes))
    
    # ========================================================================
    # THREAT ASSESSMENT
    # ========================================================================
    
    def is_actual_threat(self, title: str, content: str) -> bool:
        """Determine if article is about an actual threat/attack/vulnerability or just news/advisory"""
        text = f"{title} {content}".lower()
        
        # Indicators of actual threat
        threat_indicators = [
            'cve-', 'exploit', 'vulnerability', 'zero-day', 'ransomware',
            'data breach', 'hacked', 'compromised', 'malware', 'backdoor',
            'actively exploited', 'attack campaign', 'threat actor'
        ]
        
        # Indicators of news/advisory/guidance (not actual threats)
        advisory_indicators = [
            'guidance', 'advisory', 'report finds', 'survey', 'study shows',
            'experts recommend', 'best practices', 'how to', 'tips for',
            'organizations should', 'businesses must', 'compliance', 'readiness'
        ]
        
        # Check if it's advisory/news
        has_advisory = any(indicator in text for indicator in advisory_indicators)
        has_threat = any(indicator in text for indicator in threat_indicators)
        
        # If has advisory indicators and no strong threat indicators, it's not a threat
        if has_advisory and not has_threat:
            return False
        
        # If has strong threat indicators, it's a threat
        if has_threat:
            return True
        
        # Default: treat as news/advisory unless proven otherwise
        return False
    
    def determine_threat_type(self, title: str, content: str, keywords: List[str]) -> str:
        """Determine threat type from content"""
        text = f"{title} {content}".lower()
        
        # Check for specific types
        if 'ransomware' in text:
            return "Ransomware Attack"
        elif 'cve-' in text or ('vulnerability' in text and 'exploit' in text):
            if 'zero-day' in text or 'zero day' in text:
                return "Zero-Day Vulnerability"
            else:
                return "Vulnerability"
        elif 'data breach' in text or 'data leak' in text:
            return "Data Breach"
        elif 'phishing' in text:
            return "Phishing Attack"
        elif 'malware' in text:
            return "Malware Threat"
        else:
            return "Security Update"
    
    def extract_cvss_from_content(self, content: str) -> Optional[str]:
        """Extract actual CVSS score from article content if it exists"""
        import re
        
        # Patterns to match CVSS scores
        cvss_patterns = [
            r'CVSS\s*(?:score|rating)?[:\s]*(?:v?3\.?\d?)?\s*[:\s]*(\d+\.?\d*)',
            r'CVSS\s*(?:v?3\.?\d?)?\s*score\s*of\s*(\d+\.?\d*)',
            r'(?:has|with)\s+(?:a\s+)?CVSS\s*(?:score|rating)?\s*(?:of\s+)?(\d+\.?\d*)',
        ]
        
        for pattern in cvss_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                cvss_score = float(match.group(1))
                # Map CVSS score to severity
                if cvss_score >= 9.0:
                    return f"Critical (CVSS {cvss_score})"
                elif cvss_score >= 7.0:
                    return f"High (CVSS {cvss_score})"
                elif cvss_score >= 4.0:
                    return f"Medium (CVSS {cvss_score})"
                else:
                    return f"Low (CVSS {cvss_score})"
        
        return None
    
    def assess_severity(self, relevance_score: float, content: str) -> str:
        """FIXED: Extract actual CVSS from article, or use descriptive severity without fake CVSS"""
        
        # STEP 1: Try to extract actual CVSS score from article
        actual_cvss = self.extract_cvss_from_content(content)
        if actual_cvss:
            return actual_cvss
        
        # STEP 2: If no CVSS found, use descriptive severity (NO FAKE CVSS)
        content_lower = content.lower()
        
        # Look for severity keywords in article
        if any(word in content_lower for word in ['critical vulnerability', 'critical security', 'critical flaw', 'emergency', 'severe vulnerability']):
            return "Critical Severity"
        elif any(word in content_lower for word in ['high severity', 'high-severity', 'serious vulnerability', 'significant risk']):
            return "High Severity"
        elif any(word in content_lower for word in ['medium severity', 'medium-severity', 'moderate risk', 'moderate vulnerability']):
            return "Medium Severity"
        elif any(word in content_lower for word in ['low severity', 'low-severity', 'minor vulnerability', 'low risk']):
            return "Low Severity"
        elif any(word in content_lower for word in ['critical', 'severe']) and any(word in content_lower for word in ['vulnerability', 'exploit', 'flaw']):
            return "Critical Severity"
        elif any(word in content_lower for word in ['high', 'serious']) and any(word in content_lower for word in ['vulnerability', 'exploit', 'flaw']):
            return "High Severity"
        else:
            # STEP 3: If no severity info found at all
            return "Severity not specified in source"
    
    def determine_impact_assessments(self, content: str, threat_type: str, is_threat: bool,
                                     severity_rating: str = "") -> Dict[str, str]:
        """Determine impact assessments, anchored to SEVERITY and exploitability
        rather than the mere presence of words like 'customers' or 'trust'.

        This prevents over-stating impact — e.g. rating a medium-severity,
        authentication-required bug as 'High reputational risk' just because the
        advisory mentions 'customers'.
        """
        if not is_threat:
            na = "Not Applicable — Advisory/guidance content, no active threat"
            return {'financial': na, 'data_exposure': na, 'reputational': na}

        content_lower = content.lower()
        sev = (severity_rating or '').lower()
        is_critical = 'critical' in sev
        is_high = 'high' in sev
        elevated = is_critical or is_high  # high or critical

        actively_exploited = any(t in content_lower for t in [
            'actively exploited', 'active exploitation', 'exploited in the wild',
            'exists in the wild', 'being exploited', 'under exploitation', 'zero-day',
        ])
        # "unauthenticated" contains the substring "authenticated"; check it first
        # so an unauthenticated flaw is never mis-classified as auth-gated.
        unauthenticated = any(t in content_lower for t in [
            'unauthenticated', 'without authentication', 'no authentication',
            'pre-auth', 'pre-authentication', 'requires no credentials',
            'no credentials', 'unauthorized access',
        ])
        authenticated = (not unauthenticated) and any(t in content_lower for t in [
            'authenticated', 'valid credentials', 'requires credentials',
            'already having valid', 'logged-in', 'logged in', 'admin privileges',
            'authentication is required', 'with write access',
        ])
        data_breach = any(t in content_lower for t in [
            'data breach', 'data leak', 'exfiltration', 'exfiltrate',
            'personal information', 'customer data', 'stolen data',
            'records exposed', 'database exposed', 'data theft', 'leaked data',
        ])
        # Full-compromise capability. A successful code execution / web shell /
        # backdoor generally implies access to everything on the host, so it must
        # NOT be reported as "Low" data exposure.
        code_execution = any(t in content_lower for t in [
            'remote code execution', 'arbitrary code execution', 'code execution',
            'rce', 'web shell', 'webshell', 'web-shell', 'reverse shell',
            'backdoor', 'full control', 'complete control', 'take over',
            'fully compromise', 'system compromise', 'root access', 'arbitrary command',
            'arbitrary commands', 'privilege escalation',
        ])
        severe_capability = actively_exploited or code_execution

        # Financial
        if any(t in content_lower for t in ['ransomware', 'extortion', 'financial loss', 'wire fraud', 'fraudulent transaction']):
            financial = "High — potential significant financial losses, operational disruption, and recovery costs."
        elif is_critical and severe_capability:
            financial = "Medium to High — incident response, remediation, and potential downtime costs from a critical, exploitable flaw."
        elif elevated and any(t in content_lower for t in ['business', 'operations', 'enterprise', 'downtime', 'disruption']):
            financial = "Medium — potential business disruption and moderate recovery costs."
        else:
            financial = "Low to Medium — limited direct financial impact, monitoring and response costs."

        # Data exposure
        if data_breach:
            data = "High — enables unauthorized data access that can lead to privacy violations and regulatory issues."
        elif code_execution and (is_critical or is_high):
            data = "High — code execution / backdoor access can expose or alter all data held on the affected systems."
        elif elevated and any(t in content_lower for t in ['data', 'information disclosure', 'read arbitrary', 'sensitive']):
            data = "Medium — potential for limited data exposure and privacy concerns."
        else:
            data = "Low — minimal risk of direct data exposure, primarily system security concerns."

        # Reputational — High for genuine data loss, or critical actively-exploited /
        # code-execution flaws that are NOT gated behind authentication.
        if data_breach:
            reputation = "High — potential breach of customer/partner data affecting trust and brand."
        elif is_critical and severe_capability and not authenticated:
            reputation = "High — actively exploitable critical flaw with public exposure; brand/trust impact if compromised."
        elif is_high or (is_critical and authenticated):
            reputation = "Medium — potential impact on service reliability and customer confidence."
        else:
            reputation = "Low to Medium — limited direct reputational impact, primarily operational concerns."

        return {
            'financial': financial,
            'data_exposure': data,
            'reputational': reputation,
        }

    # ========================================================================
    # CONSISTENCY GATE — flag (do NOT silently drop) accuracy problems so the
    # human validator can catch them before the report reaches the SOC team.
    # ========================================================================

    # Well-known product/vendor names used for cross-contamination checks.
    _KNOWN_PRODUCTS = [
        'chrome', 'firefox', 'safari', 'edge', 'peoplesoft', 'oracle', 'cisco',
        'windows', 'android', 'ios', 'macos', 'linux', 'fortinet', 'fortios',
        'ivanti', 'vmware', 'unifi', 'ubiquiti', 'wordpress', 'sharepoint',
        'exchange', 'citrix', 'sap', 'gitlab', 'github', 'atlassian', 'confluence',
        'jira', 'sonicwall', 'palo alto', 'juniper', 'apache', 'openssl',
        'kubernetes', 'docker', 'jenkins', 'zimbra', 'moveit', 'curl',
    ]

    @staticmethod
    def _looks_like_fragment(text: str) -> bool:
        """Detect torn-out fragments such as 'Chrome 0' or trailing ' 0'."""
        if not text:
            return True
        t = text.strip()
        if len(t) < 12:
            return True
        # "Word 0" / "Word 12" with nothing else — a truncated version string.
        if re.fullmatch(r'[A-Za-z][\w.\-]*\s+\d+', t):
            return True
        if re.search(r'\b\d-?\s*$', t):  # ends in a lone digit (e.g. "... 0")
            return True
        return False

    # ── Output sanitation: kill torn-off bylines and duplicated sentences ──
    # A trailing author byline such as "Phil E. Muncaster" / "Phil E." that the
    # sentence splitter glued onto the end of real content (a name followed by at
    # least one single-letter initial — a strong byline signal).
    _BYLINE_TAIL = re.compile(
        r'\s*["”’\']?\s*[A-Z][a-z]+(?:\s+[A-Z]\.)+(?:\s+[A-Z][a-z]+){0,2}\.?\s*$'
    )
    # Structured/placeholder field values that must never be sentence-filtered.
    _STRUCTURED_PREFIXES = (
        'Not Applicable', 'Refer to', 'Review vendor', 'Review security',
        'Apply available', 'Severity not', 'Under investigation',
        'Security patches', 'Updates available', 'Affected releases',
    )

    @staticmethod
    def _norm_sentence(s: str) -> str:
        return re.sub(r'[^a-z0-9]', '', (s or '').lower())

    @staticmethod
    def _split_sentences_clean(text: str) -> List[str]:
        # Break after terminal punctuation, allowing a closing quote in between.
        return [p.strip() for p in re.split(r'(?<=[.!?])["”’\']?\s+', text) if p.strip()]

    def _sanitize_prose(self, text: str, dedup: set = None, fallback: str = None) -> str:
        """Clean a prose field: strip torn-off author bylines, drop incomplete
        fragments, and de-duplicate sentences within the field and (if `dedup`
        is supplied) against sentences already used in other sections. Never
        destroys content — returns `fallback`/original if everything is removed."""
        if not text:
            return fallback if fallback is not None else text
        t = re.sub(r'\s+', ' ', str(text)).strip()
        if t.startswith(self._STRUCTURED_PREFIXES):
            return t
        kept = []
        for s in self._split_sentences_clean(t):
            stripped = self._BYLINE_TAIL.sub('', s).strip()
            if stripped and stripped != s and not re.search(r'[.!?]["”’\']?$', stripped):
                stripped += '.'
            s = stripped or s
            if len(s) < 25:
                continue
            if len(re.findall(r"[A-Za-z]{3,}", s)) < 4:          # too few real words
                continue
            if not re.search(r'[.!?]["”’\']?$', s):     # not a complete sentence
                continue
            norm = self._norm_sentence(s)
            if not norm:
                continue
            if dedup is not None and norm in dedup:               # used in another section
                continue
            if any(norm == self._norm_sentence(k) for k in kept): # repeated in this field
                continue
            kept.append(s)
            if dedup is not None:
                dedup.add(norm)
        result = ' '.join(kept).strip()
        if not result:
            return fallback if fallback is not None else text
        return result

    def _register_sentences(self, text: str, seen: set) -> None:
        if not text or text.startswith(self._STRUCTURED_PREFIXES):
            return
        for s in self._split_sentences_clean(re.sub(r'\s+', ' ', str(text))):
            n = self._norm_sentence(s)
            if n:
                seen.add(n)

    def _sanitize_exploited(self, text: str, seen: set) -> str:
        """Affected-systems field: usually a product phrase. Strip a leaked byline
        and, if it is actually a full sentence already used elsewhere, replace it."""
        generic = "Refer to the source advisory for the specific affected products and versions."
        if not text:
            return generic
        t = re.sub(r'\s+', ' ', str(text)).strip()
        if t.startswith(self._STRUCTURED_PREFIXES):
            return t
        if self._norm_sentence(t) in seen:
            return generic
        t = self._BYLINE_TAIL.sub('', t).strip()
        return t or generic

    def _product_mismatch(self, subject_text: str, field_text: str) -> Optional[str]:
        """If `field_text` names a known product absent from the report subject
        (and shares none with it), flag possible cross-contamination."""
        subj = (subject_text or '').lower()
        fld = (field_text or '').lower()
        subject_products = {p for p in self._KNOWN_PRODUCTS if p in subj}
        if not subject_products:
            return None
        field_products = {p for p in self._KNOWN_PRODUCTS if p in fld}
        foreign = field_products - subject_products
        if foreign and not (field_products & subject_products):
            return (f"references {sorted(foreign)} but the report subject is "
                    f"{sorted(subject_products)}")
        return None

    def _validate_consistency(self, report: 'ThreatReport', article: Dict,
                              focus_content: str, is_roundup: bool) -> List[str]:
        """Build a list of human-facing accuracy warnings for this report."""
        warnings: List[str] = []

        if is_roundup:
            warnings.append(
                "Source is a multi-threat roundup/digest — this report was scoped to the "
                "lead item only. Other threats in the source are NOT covered here. "
                "Verify the CVE, product, and details before sending."
            )

        # CVE consistency: the primary CVE should appear in the prose.
        if report.cve_id:
            prose = f"{report.threat_summary} {report.description} {report.mitigation_measures}".upper()
            if report.cve_id.upper() not in prose:
                warnings.append(
                    f"Primary CVE {report.cve_id} is not mentioned in the summary/description — "
                    f"possible mismatch. Verify this is the correct identifier."
                )
            cves = self.extract_cve_ids(focus_content)
            if len(cves) > 1:
                others = [c for c in cves if c != report.cve_id][:5]
                warnings.append(
                    f"Multiple CVEs in source ({', '.join([report.cve_id] + others)}); "
                    f"report focuses on {report.cve_id}. Confirm this is the intended one."
                )

        # Fragment checks on key fields.
        if self._looks_like_fragment(report.exploited_systems):
            warnings.append(f"'Exploited Systems' looks incomplete: \"{report.exploited_systems}\".")
        if self._looks_like_fragment(report.attack_outcome):
            warnings.append("'Attack Outcome' looks incomplete or truncated.")

        # Filler leaked into mitigation.
        if self._is_filler_sentence(report.mitigation_measures):
            warnings.append("Mitigation text may contain newsletter/boilerplate rather than actionable steps.")

        # Cross-contamination between the title and the attack outcome.
        mismatch = self._product_mismatch(report.title, report.attack_outcome)
        if mismatch:
            warnings.append(f"'Attack Outcome' {mismatch} — possible cross-contamination from another story.")

        return warnings

    # ========================================================================
    # MAIN FORMAT FUNCTION
    # ========================================================================
    
    def format_soc_report(self, article: Dict) -> Optional[ThreatReport]:
        """
        Format article into structured SOC report using AUTHENTIC content
        Returns None if content quality is too low
        """
        
        # Extract basic information
        title = article.get('title', 'Unknown Threat')
        content = article.get('content', article.get('summary', ''))
        keywords = article.get('keywords', [])
        source_name = article.get('source', 'Unknown Source')
        source_url = article.get('url', '')
        relevance_score = article.get('relevance_score', 0)
        
        # Detect multi-threat digests/recaps. They must NOT be rendered as a
        # single coherent threat without first isolating ONE item, otherwise
        # facts from different stories bleed together (wrong CVE, wrong product).
        is_roundup = self.detect_roundup(title, content)

        # Isolate ONE threat's text BEFORE any field extraction. Two triggers:
        #   • a detected roundup/digest, OR
        #   • any article listing >=2 distinct CVEs (e.g. a "CISA adds N flaws to
        #     KEV" bulletin) — the exact shape whose fields otherwise bleed
        #     across CVEs (wrong product, mixed attack outcome).
        # We scope to the PRIMARY CVE (chosen on the FULL text) so every field
        # extractor below binds to the same single CVE by construction.
        primary_cve = self.select_primary_cve(content)
        needs_isolation = is_roundup or len(self.extract_cve_ids(content)) >= 2
        focus_content = self.scope_to_lead_item(content, primary_cve) if needs_isolation else content

        # FIXED: Determine if this is an actual threat or just news/advisory
        is_threat = self.is_actual_threat(title, focus_content)

        # Determine threat type
        threat_type = self.determine_threat_type(title, focus_content, keywords)

        # Create clear summary and assess quality
        threat_summary, quality_score = self.create_clear_summary(title, focus_content, threat_type)

        # Skip if quality is too low (less than 1.5 - only reject obvious garbage)
        # Lower threshold allows borderline content to reach sender validation
        if quality_score < 1.5:
            db.log_system_event('WARNING', f'Article quality too low ({quality_score:.1f}): {title}', 'REPORT_FORMATTER')
            return None

        # Create detailed description
        description = self.create_detailed_description(title, focus_content, threat_type)

        # Extract CVE — pick the PRIMARY one deterministically (only for threats).
        # (Was list(set(...))[0], which selected an arbitrary CVE.)
        cve_id = self.select_primary_cve(focus_content) if is_threat else None

        # Extract attack details from actual content (only for actual threats)
        if is_threat:
            attack_details = self.extract_attack_details_from_content(focus_content)
        else:
            attack_details = {
                'outcome': 'Not Applicable — This is advisory/guidance content, not an active threat',
                'tactics': 'Not Applicable — No attack tactics involved'
            }

        # Extract mitigation from actual content
        mitigation_measures = self.extract_mitigation_from_content(focus_content)

        # Extract affected systems (only for actual threats)
        if is_threat:
            exploited_systems = self.extract_exploited_systems(focus_content, title)
        else:
            exploited_systems = "Not Applicable — Advisory/guidance content"

        # Assess severity (only for actual threats)
        if is_threat:
            severity_rating = self.assess_severity(relevance_score, focus_content)
        else:
            severity_rating = "Not Applicable — Advisory/guidance content, not a vulnerability"

        # Determine patch availability (only for actual threats)
        content_lower = focus_content.lower()
        if not is_threat:
            patch_availability = "Not Applicable — Advisory/guidance content, no patches required"
        elif cve_id:
            if any(term in content_lower for term in ['patch', 'update', 'fixed', 'resolved']):
                patch_availability = "Security patches available (requires prompt deployment)"
            else:
                patch_availability = "Under investigation - monitor vendor advisory for updates"
        else:
            if 'patch' in content_lower or 'update' in content_lower:
                patch_availability = "Updates available - refer to vendor security advisory"
            else:
                patch_availability = "Review security configurations and implement recommended protections"

        # Determine impact assessments (severity-aware, so impact is not inflated
        # by stray keywords like "customers")
        impacts = self.determine_impact_assessments(focus_content, threat_type, is_threat, severity_rating)

        # Create structured report
        report = ThreatReport(
            title=title,
            threat_type=threat_type,
            date_identified=datetime.now().strftime('%B %d, %Y'),
            threat_summary=threat_summary,
            attack_outcome=attack_details['outcome'],
            tactics_used=attack_details['tactics'],
            data_loss_exposure=impacts['data_exposure'],
            financial_impact=impacts['financial'],
            reputational_risk=impacts['reputational'],
            cve_id=cve_id,
            description=description,
            exploited_systems=exploited_systems,
            severity_rating=severity_rating,
            patch_availability=patch_availability,
            mitigation_measures=mitigation_measures,
            source_url=source_url,
            source_name=source_name,
            content_quality_score=quality_score,
            is_roundup=is_roundup,
        )

        # ── Output sanitation pass (runs on every report) ──────────────────
        # Clean torn-off author bylines (e.g. "Phil E. Muncaster") and incomplete
        # fragments, and stop the same sentence from appearing in several sections.
        report.threat_summary = self._sanitize_prose(report.threat_summary)
        report.description = self._sanitize_prose(report.description)
        report.attack_outcome = self._sanitize_prose(report.attack_outcome)

        seen_sentences = set()
        for fld in (report.threat_summary, report.description, report.attack_outcome):
            self._register_sentences(fld, seen_sentences)

        report.exploited_systems = self._sanitize_exploited(report.exploited_systems, seen_sentences)
        report.mitigation_measures = self._sanitize_prose(
            report.mitigation_measures,
            dedup=seen_sentences,
            fallback="Apply available security patches/updates and follow the vendor security advisory for specific remediation steps.",
        )

        # Consistency gate — attach human-facing accuracy warnings (never silently
        # drops the report; the sender validator decides).
        report.validation_warnings = self._validate_consistency(report, article, focus_content, is_roundup)

        return report
    
    def generate_soc_report_html(self, report: ThreatReport) -> str:
        """Generate professional HTML SOC report (keeping existing format)"""
        
        # Generate unique report ID with ENFORCED 1-10 numbering
        if ENFORCE_NUMBERING_1_TO_10:
            today = datetime.now().strftime('%Y%m%d')
            report_num = ((self.daily_counter - 1) % 10) + 1
            report_id = f"TI-{today}-{report_num:02d}"
            self.daily_counter = (self.daily_counter % 10) + 1
        else:
            report_id = f"TI-{datetime.now().strftime('%Y%m%d')}-{self.report_id_counter:03d}"
            self.report_id_counter += 1
        
        # [Keep the same HTML template as original - lines 651-1036 from soc_report_formatter.py]
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
                    background: #002E6E;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    margin: -50px -50px 30px -50px;
                    font-weight: 700;
                    font-size: 14pt;
                    border-bottom: 4px solid #002E6E;
                }}
                
                .document-title {{
                    text-align: center;
                    color: #002E6E;
                    font-size: 18pt;
                    font-weight: 700;
                    margin: 30px 0;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    border-bottom: 3px solid #002E6E;
                    padding-bottom: 15px;
                }}
                
                .intro-section {{
                    background: #f8f9fa;
                    border-left: 6px solid #002E6E;
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
                    color: #002E6E;
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
                    background: #002E6E;
                    color: white;
                    padding: 8px 15px;
                    border-radius: 5px;
                    display: inline-block;
                    font-weight: 600;
                    margin: 10px 0;
                    font-size: 9pt;
                }}
                
                .clickable-button {{
                    background: #e3f2fd;
                    color: #0056b3;
                    padding: 8px 15px;
                    text-decoration: none;
                    border-radius: 5px;
                    display: inline-block;
                    font-weight: 600;
                    margin: 5px 10px 5px 0;
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
                    Notable Global Cyber Threat – "{self._strip_article_numbering(report.title)}"
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
                            <td class="info-value">: {report.cve_id or 'None'}</td>
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
        """Generate plain text version of SOC report (keeping existing format)"""
        
        if ENFORCE_NUMBERING_1_TO_10:
            today = datetime.now().strftime('%Y%m%d')
            report_num = ((self.daily_counter - 1) % 10) + 1
            report_id = f"TI-{today}-{report_num:02d}"
            self.daily_counter = (self.daily_counter % 10) + 1
        else:
            report_id = f"TI-{datetime.now().strftime('%Y%m%d')}-{self.report_id_counter:03d}"
        
        text_report = f"""
🔴 NOTABLE GLOBAL CYBER THREAT – "{self._strip_article_numbering(report.title)}"

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

CVE-ID             : {report.cve_id or 'None'}
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
        """Generate Excel file attachment - same as original"""
        # [Keep the same implementation as soc_report_formatter.py lines 1102-1310]
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
            from openpyxl.utils import get_column_letter
            
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Threat Analysis"
            
            headers = [
                'Area', 'Issues', 'Issue Summary', 'Attack Methodology',
                'Potential Impact', 'Realized Impact', 'Recommendation',
                'Source', 'CVE', 'Date'
            ]
            
            for col_num, header in enumerate(headers, 1):
                cell = ws.cell(row=1, column=col_num)
                cell.value = header
                cell.fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
                cell.font = Font(bold=True, color="FFFFFF", size=11)
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
                cell.border = Border(
                    left=Side(style='thin'),
                    right=Side(style='thin'),
                    top=Side(style='thin'),
                    bottom=Side(style='thin')
                )
            
            # Extract area from title
            area = self._extract_area_from_title(report.title)
            issues = self._format_issues(report.cve_id, report.severity_rating, report.threat_summary)
            potential_impact = self._format_potential_impact(
                report.financial_impact, report.data_loss_exposure, report.reputational_risk
            )
            realized_impact = self._extract_realized_impact(report.threat_summary, report.attack_outcome)
            
            data_row = [
                area, issues, report.threat_summary, report.tactics_used,
                potential_impact, realized_impact, report.mitigation_measures,
                report.source_url, report.cve_id if report.cve_id else "N/A",
                datetime.now().strftime('%B %d, %Y')
            ]
            
            for col_num, value in enumerate(data_row, 1):
                cell = ws.cell(row=2, column=col_num)
                cell.value = value
                cell.font = Font(size=10)
                cell.alignment = Alignment(horizontal='left', vertical='top', wrap_text=True)
                cell.border = Border(
                    left=Side(style='thin'),
                    right=Side(style='thin'),
                    top=Side(style='thin'),
                    bottom=Side(style='thin')
                )
                
                if col_num == 8 and report.source_url:
                    cell.hyperlink = report.source_url
                    cell.font = Font(size=10, color="0563C1", underline="single")
            
            column_widths = [25, 35, 50, 50, 40, 40, 45, 40, 18, 15]
            for i, width in enumerate(column_widths, 1):
                ws.column_dimensions[get_column_letter(i)].width = width
            
            ws.row_dimensions[1].height = 30
            ws.row_dimensions[2].height = 100
            
            safe_title = re.sub(r'[^\w\s-]', '', report.title)
            safe_title = re.sub(r'[-\s]+', '_', safe_title)[:50]
            filename = f"{safe_title}_Threat_Analysis.xlsx"
            
            wb.save(filename)
            return filename
            
        except Exception as e:
            db.log_system_event('ERROR', f'Error generating Excel file: {e}', 'EXCEL_GENERATOR')
            return None
    
    def _extract_area_from_title(self, title: str) -> str:
        """Extract area/product from title"""
        patterns = [
            r'^([A-Za-z0-9\s/]+?)\s+(?:Vulnerability|CVE|Security)',
            r'in\s+([A-Za-z0-9\s/]+)',
            r'^([\w\s]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, title, re.IGNORECASE)
            if match:
                area = match.group(1).strip()
                if len(area) > 5:
                    return area + " Vulnerability"
        
        return title[:50] + " Vulnerability"
    
    def _format_issues(self, cve_id: str, severity: str, summary: str) -> str:
        """Format issues column"""
        issues = []
        
        if 'Critical' in severity:
            issues.append("Critical vulnerability")
        elif 'High' in severity:
            issues.append("High severity vulnerability")
        
        if cve_id:
            issues.append(f"({cve_id})")
        
        if any(keyword in summary.lower() for keyword in ['actively exploit', 'active exploitation', 'being exploited']):
            issues.append("actively exploited")
        
        return " ".join(issues) if issues else "Security vulnerability"
    
    def _format_potential_impact(self, financial: str, data: str, reputational: str) -> str:
        """Format potential impact"""
        impacts = []
        
        if 'High' in financial:
            impacts.append("significant financial losses")
        if 'High' in data:
            impacts.append("data theft/exposure")
        if 'High' in reputational:
            impacts.append("reputational damage")
        
        impacts.extend([
            "business process disruption",
            "operational downtime",
            "regulatory penalties"
        ])
        
        return ", ".join(impacts[:6]) + "."
    
    def _extract_realized_impact(self, summary: str, outcome: str) -> str:
        """Extract realized impact"""
        text = f"{summary} {outcome}".lower()
        
        exploitation_keywords = [
            'actively exploited', 'active exploitation', 'being exploited',
            'exploited in the wild', 'attacks observed', 'attacks detected'
        ]
        
        for keyword in exploitation_keywords:
            if keyword in text:
                sentences = (summary + " " + outcome).split('.')
                for sent in sentences:
                    if any(kw in sent.lower() for kw in exploitation_keywords):
                        return sent.strip() + "."
                
                return "Active exploitation observed in the wild; attackers able to compromise systems and gain unauthorized access."
        
        return "No active exploitation reported"


# Create global enhanced formatter instance
enhanced_soc_formatter = EnhancedSOCReportFormatter()

