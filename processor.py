import os
import re
import time
import random
import json
import requests
from dotenv import load_dotenv
import google.generativeai as genai
import logging
import unicodedata
import praw
from datetime import datetime, timedelta
import hashlib

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

class CVETracker:
    """Tracks posted CVEs and topics to prevent duplicates."""
    
    def __init__(self, tracking_file="cve_tracking.json"):
        self.tracking_file = tracking_file
        self.data = self.load_tracking_data()
    
    def load_tracking_data(self):
        """Load existing tracking data."""
        try:
            if os.path.exists(self.tracking_file):
                with open(self.tracking_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Error loading tracking data: {e}")
        
        return {
            "posted_cves": [],
            "posted_topics": [],
            "content_hashes": [],
            "last_updated": datetime.now().isoformat()
        }
    
    def save_tracking_data(self):
        """Save tracking data to file."""
        try:
            self.data["last_updated"] = datetime.now().isoformat()
            with open(self.tracking_file, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving tracking data: {e}")
    
    def is_cve_posted(self, cve_id):
        """Check if CVE has been posted before."""
        return cve_id in self.data.get("posted_cves", [])
    
    def is_topic_posted(self, topic):
        """Check if topic has been posted recently (within 30 days)."""
        posted_topics = self.data.get("posted_topics", [])
        topic_hash = hashlib.md5(topic.lower().encode()).hexdigest()
        
        # Remove old topics (older than 30 days)
        cutoff_date = datetime.now() - timedelta(days=30)
        self.data["posted_topics"] = [
            item for item in posted_topics 
            if datetime.fromisoformat(item.get("date", "2020-01-01")) > cutoff_date
        ]
        
        # Check if topic exists
        return any(item.get("hash") == topic_hash for item in self.data["posted_topics"])
    
    def is_content_duplicate(self, content):
        """Check if similar content has been posted."""
        content_hash = hashlib.md5(content.lower().encode()).hexdigest()
        return content_hash in self.data.get("content_hashes", [])
    
    def mark_cve_posted(self, cve_id):
        """Mark CVE as posted."""
        if "posted_cves" not in self.data:
            self.data["posted_cves"] = []
        if cve_id not in self.data["posted_cves"]:
            self.data["posted_cves"].append(cve_id)
            self.save_tracking_data()
    
    def mark_topic_posted(self, topic):
        """Mark topic as posted."""
        if "posted_topics" not in self.data:
            self.data["posted_topics"] = []
        
        topic_hash = hashlib.md5(topic.lower().encode()).hexdigest()
        topic_entry = {
            "topic": topic,
            "hash": topic_hash,
            "date": datetime.now().isoformat()
        }
        self.data["posted_topics"].append(topic_entry)
        self.save_tracking_data()
    
    def mark_content_posted(self, content):
        """Mark content as posted."""
        if "content_hashes" not in self.data:
            self.data["content_hashes"] = []
        
        content_hash = hashlib.md5(content.lower().encode()).hexdigest()
        
        # Keep only last 100 content hashes to prevent file bloat
        if len(self.data["content_hashes"]) >= 100:
            self.data["content_hashes"] = self.data["content_hashes"][-50:]
        
        self.data["content_hashes"].append(content_hash)
        self.save_tracking_data()

class CyberSecurityProcessor:
    def __init__(self):
        self.cve_tracker = CVETracker()
        self.reddit = self.setup_reddit()
        self.linkedin_api = LinkedInAPI()

    def setup_reddit(self):
        """Setup Reddit API client."""
        try:
            reddit = praw.Reddit(
                client_id=os.getenv("REDDIT_CLIENT_ID", ""),
                client_secret=os.getenv("REDDIT_CLIENT_SECRET", ""),
                user_agent=os.getenv("REDDIT_USER_AGENT", "linkedin_cve_bot/1.0"),
                # For read-only access, we don't need username/password
            )
            logging.info("Reddit API configured successfully")
            return reddit
        except Exception as e:
            logging.warning(f"Reddit API setup failed: {e}. Will use anonymous access.")
            return None

    def random_delay(self, min_delay=1, max_delay=3):
        """Introduce a random delay to mimic human behavior."""
        time.sleep(random.uniform(min_delay, max_delay))

    def fetch_reddit_cves(self, limit=10):
        """Fetch CVE information from Reddit r/CVEWatch."""
        reddit_cves = []
        
        if not self.reddit:
            logging.warning("Reddit API not available, skipping Reddit CVEs")
            return reddit_cves
        
        try:
            logging.info("Fetching CVEs from Reddit r/CVEWatch...")
            subreddit = self.reddit.subreddit("CVEWatch")
            
            for submission in subreddit.new(limit=limit):
                # Extract CVE IDs from both title and content
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                full_text = f"{submission.title} {submission.selftext}"
                cve_matches = re.findall(cve_pattern, full_text, re.IGNORECASE)
                
                if cve_matches:
                    # Process multiple CVEs from a single post
                    for cve_match in cve_matches[:5]:  # Limit to 5 CVEs per post
                        cve_id = cve_match.upper()
                        
                        # Skip if already posted
                        if self.cve_tracker.is_cve_posted(cve_id):
                            continue
                        
                        # Extract CVSS score for this specific CVE
                        severity = "Unknown"
                        # Look for CVSS patterns near this CVE
                        cve_section = self._extract_cve_section(full_text, cve_id)
                        score_patterns = [
                            r'📈\s*CVSS[:\s]*(\d+\.?\d*)',
                            r'CVSS[:\s]*(\d+\.?\d*)',
                            r'Score[:\s]*(\d+\.?\d*)'
                        ]
                        
                        for pattern in score_patterns:
                            score_matches = re.findall(pattern, cve_section, re.IGNORECASE)
                            if score_matches:
                                severity = score_matches[0]
                                break
                        
                        # Extract description for this CVE
                        description = self._extract_cve_description(full_text, cve_id)
                        
                        reddit_cves.append({
                            'id': cve_id,
                            'title': submission.title,
                            'description': description,
                            'cvss_score': severity,
                            'url': submission.url,
                            'reddit_score': submission.score,
                            'source': 'reddit',
                            'post_date': datetime.fromtimestamp(submission.created_utc).strftime('%Y-%m-%d')
                        })
            
            logging.info(f"Found {len(reddit_cves)} new CVEs from Reddit")
            return reddit_cves
            
        except Exception as e:
            logging.error(f"Failed to fetch Reddit CVEs: {e}")
            return reddit_cves
    
    def _extract_cve_section(self, text, cve_id):
        """Extract the section of text related to a specific CVE."""
        lines = text.split('\n')
        cve_section = ""
        found_cve = False
        
        for i, line in enumerate(lines):
            if cve_id in line:
                found_cve = True
                # Get this line and next 10 lines for context
                section_lines = lines[i:i+10]
                cve_section = '\n'.join(section_lines)
                break
        
        return cve_section if found_cve else text[:500]
    
    def _extract_cve_description(self, text, cve_id):
        """Extract description for a specific CVE from Reddit post."""
        lines = text.split('\n')
        description = ""
        
        for i, line in enumerate(lines):
            if cve_id in line:
                # Look for description in next few lines
                for j in range(i, min(i+5, len(lines))):
                    if any(keyword in lines[j].lower() for keyword in ['📝', 'description', 'vulnerability', 'allows', 'enables']):
                        # Clean up the description
                        desc = lines[j]
                        desc = re.sub(r'📝\s*', '', desc)  # Remove emoji
                        desc = re.sub(r'^\d+\.\s*', '', desc)  # Remove numbering
                        description = desc.strip()
                        break
                break
        
        if not description and cve_id in text:
            # Fallback: get text around CVE mention
            cve_index = text.find(cve_id)
            start = max(0, cve_index - 100)
            end = min(len(text), cve_index + 200)
            description = text[start:end].strip()
        
        return description[:300] + '...' if len(description) > 300 else description

    def fetch_latest_cves(self, limit=5):
        """Fetch latest CVE entries from NIST API."""
        try:
            logging.info("Fetching CVEs from NIST...")
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'resultsPerPage': limit,
                'startIndex': 0
            }
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id', 'Unknown')
                
                # Skip if already posted
                if self.cve_tracker.is_cve_posted(cve_id):
                    continue
                
                description = ''
                
                # Extract description
                descriptions = cve_data.get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Get CVSS score if available
                cvss_score = 'Unknown'
                metrics = cve_data.get('metrics', {})
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 'Unknown')
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 'Unknown')
                
                cves.append({
                    'id': cve_id,
                    'description': description[:200] + '...' if len(description) > 200 else description,
                    'cvss_score': cvss_score,
                    'source': 'nist'
                })
                
            logging.info(f"Found {len(cves)} new CVEs from NIST")
            return cves
        except Exception as e:
            logging.error(f"Failed to fetch NIST CVEs: {e}")
            return []

    def get_combined_cve_data(self, reddit_limit=5, nist_limit=3):
        """Combine CVE data from Reddit and NIST, ensuring no duplicates."""
        reddit_cves = self.fetch_reddit_cves(reddit_limit)
        nist_cves = self.fetch_latest_cves(nist_limit)
        
        # Combine and deduplicate by CVE ID
        all_cves = {}
        
        # Add Reddit CVEs first (they might have more context)
        for cve in reddit_cves:
            all_cves[cve['id']] = cve
        
        # Add NIST CVEs (won't overwrite Reddit ones due to dict behavior)
        for cve in nist_cves:
            if cve['id'] not in all_cves:
                all_cves[cve['id']] = cve
        
        # Convert back to list and limit total
        combined_cves = list(all_cves.values())[:8]  # Max 8 CVEs total
        
        logging.info(f"Combined CVE data: {len(combined_cves)} unique CVEs")
        return combined_cves

    def clean_ai_content(self, text):
        """Clean AI-generated content while preserving emojis and good formatting."""
        if not text:
            return ""
        
        # Remove hidden characters and normalize Unicode (but preserve emojis)
        text = unicodedata.normalize('NFKD', text)
        
        # Remove zero-width characters and other invisible characters
        invisible_chars = [
            '\u200b',  # Zero width space
            '\u200c',  # Zero width non-joiner
            '\u200d',  # Zero width joiner
            '\u2060',  # Word joiner
            '\ufeff',  # Byte order mark
            '\u00ad',  # Soft hyphen
        ]
        for char in invisible_chars:
            text = text.replace(char, '')
        
        # Remove only basic markdown formatting but keep structural elements
        patterns = [
            r"(\*{3,})(.*?)\1",  # Remove triple+ asterisks
            r"`{3,}[^`]*`{3,}",  # Remove code blocks
            r"`(.*?)`",  # Inline code
            r"(#{1,6})\s*",  # Remove markdown headers
        ]

        # Apply basic markdown removal
        for pattern in patterns:
            if pattern == r"`(.*?)`":  # Inline code - keep content
                text = re.sub(pattern, r"\1", text)
            else:
                text = re.sub(pattern, "", text)

        # Clean up excessive whitespace but preserve intentional line breaks
        text = re.sub(r'\n{4,}', '\n\n\n', text)  # Max 3 consecutive newlines
        text = re.sub(r'[ \t]+', ' ', text)  # Remove multiple spaces/tabs
        text = re.sub(r'^\s+|\s+$', '', text, flags=re.MULTILINE)  # Trim lines
        text = text.strip()
        
        return text

    def add_reference_links(self, content, cves_used=None, topic=""):
        """Add reference links to the content."""
        references = []
        
        # Add CVE references
        if cves_used:
            for cve_id in cves_used:
                references.append(f"🔗 {cve_id}: https://nvd.nist.gov/vuln/detail/{cve_id}")
        
        # Add relevant cybersecurity resources based on topic
        topic_lower = topic.lower()
        if "ransomware" in topic_lower:
            references.append("🔗 CISA Ransomware Guide: https://cisa.gov/stopransomware")
        elif "zero-day" in topic_lower or "exploit" in topic_lower:
            references.append("🔗 MITRE ATT&CK: https://attack.mitre.org")
        elif "cloud" in topic_lower or "aws" in topic_lower or "azure" in topic_lower:
            references.append("🔗 Cloud Security Alliance: https://cloudsecurityalliance.org")
        elif "incident" in topic_lower or "response" in topic_lower:
            references.append("🔗 NIST IR Framework: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final")
        else:
            references.append("🔗 NIST Cybersecurity Framework: https://nist.gov/cyberframework")
        
        # Add references if we have any
        if references and len(content) < 1100:  # Only add if we have space
            content += "\n\n📚 References:\n" + "\n".join(references[:2])  # Max 2 references
        
        return content

    def generate_cybersecurity_content(self, topic, include_cve=True):
        """Generates cybersecurity-focused post content using Gemini AI."""
        logging.info(f"Generating cybersecurity content for topic: {topic}")
        
        try:
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            client = genai.GenerativeModel("gemini-2.5-pro")

            # Fetch combined CVE data if requested
            cve_context = ""
            used_cves = []
            if include_cve:
                latest_cves = self.get_combined_cve_data(reddit_limit=5, nist_limit=3)
                if latest_cves:
                    cve_context = "\n\nCRITICAL VULNERABILITIES TO REFERENCE:\n"
                    for cve in latest_cves[:3]:  # Use max 3 CVEs per post
                        source = "Community Analysis" if cve['source'] == 'reddit' else "Official NIST"
                        post_date = cve.get('post_date', 'Recent')
                        severity = "🔥 CRITICAL" if float(cve['cvss_score']) >= 9.0 else "⚠️ HIGH" if float(cve['cvss_score']) >= 7.0 else "📊 MEDIUM"
                        cve_context += f"{severity} {cve['id']} (CVSS: {cve['cvss_score']}) - {source} ({post_date})\n  Impact: {cve['description']}\n\n"
                        used_cves.append(cve['id'])

            current_date = datetime.now().strftime('%B %d, %Y')
            
            prompt = f"""You are a cybersecurity expert writing for a company LinkedIn page. Create an engaging, visually appealing daily security briefing post.

TOPIC: {topic}
DATE: {current_date}

CONTENT REQUIREMENTS:
- 800-1000 characters (leaving room for references)
- Professional but conversational tone
- Include relevant emojis (2-4 total, strategically placed)
- Use proper line breaks for readability
- Include specific actionable advice
- Start with a compelling hook
- Add relevant hashtags at the end

FORMATTING REQUIREMENTS:
- Use emojis to highlight key points (🔥 for urgent, ⚠️ for warnings, 💡 for tips, 🎯 for actions)
- Use line breaks to separate sections naturally
- NO markdown formatting (**, *, [], etc.)
- Write in flowing, natural sentences with proper spacing

{cve_context if cve_context else ""}

STRUCTURE:
🔥 Opening hook with current threat landscape
[Blank line]
Main insight about the topic with specific data/examples
[Blank line] 
💡 Practical business impact and what it means
[Blank line]
🎯 1-2 specific action items for security teams
[Blank line]
Closing thought that encourages engagement
[Blank line]
#hashtags #cybersecurity #infosec

TONE EXAMPLES:
"This week's threat intelligence reveals..." 
"Security teams are reporting a 40% increase in..."
"Based on our latest incident data..."
"URGENT: New campaign targeting..."

EMOJI USAGE:
- 🔥 for hot/urgent threats
- ⚠️ for warnings and alerts  
- 💡 for insights and tips
- 🎯 for action items
- 📊 for statistics
- 🛡️ for defense/protection
- 🔍 for investigation/analysis

Remember: Write like a human expert sharing critical insights with peers. Include specific numbers, timeframes, and real-world examples. Keep it urgent but professional."""

            response = client.generate_content(prompt)

            if response.text:
                # Clean the AI-generated content
                cleaned_content = self.clean_ai_content(response.text)
                
                # Add reference links if space allows
                cleaned_content = self.add_reference_links(cleaned_content, used_cves, topic)
                
                # Check for content duplication
                if self.cve_tracker.is_content_duplicate(cleaned_content):
                    logging.warning("Generated content appears to be duplicate, regenerating...")
                    # Try once more with different approach
                    return self.generate_cybersecurity_content(topic, include_cve=False)
                
                # Mark CVEs as used
                for cve_id in used_cves:
                    self.cve_tracker.mark_cve_posted(cve_id)
                
                return cleaned_content
            else:
                return f"🔒 Daily Security Brief: {topic} - Latest threat intelligence and actionable insights for security teams. #cybersecurity #infosec #dailybrief"
                
        except Exception as e:
            logging.error("Failed to generate cybersecurity content.", exc_info=True)
            return f"🔒 Daily Security Brief: {topic} - Critical security updates and threat analysis. #cybersecurity #infosec #dailybrief"

    def post_to_linkedin(self, post_text):
        """Posts content to LinkedIn using API."""
        logging.info("Posting to LinkedIn via API.")
        
        try:
            # Use LinkedIn API to post
            success = self.linkedin_api.create_post(post_text)
            if success:
                logging.info("Post successful via LinkedIn API.")
                return True
            else:
                logging.error("Failed to post via LinkedIn API.")
                return False
                
        except Exception as e:
            logging.error("Failed to post to LinkedIn API.", exc_info=True)
            return False

    def process_cybersecurity_topics(self):
        """Processes cybersecurity topics and posts to company page."""
        try:
            with open("Topics.txt", "r") as file:
                topics = file.readlines()

            if not topics:
                logging.info("No topics to process.")
                return

            # Get an unused topic
            topic = None
            for potential_topic in topics:
                potential_topic = potential_topic.strip()
                if potential_topic and not self.cve_tracker.is_topic_posted(potential_topic):
                    topic = potential_topic
                    break
            
            if not topic:
                logging.info("No unused topics available.")
                return

            # Generate cybersecurity-focused content
            post_text = self.generate_cybersecurity_content(topic, include_cve=True)
            
            # Final duplicate check
            if self.cve_tracker.is_content_duplicate(post_text):
                logging.warning("Generated content is duplicate, skipping post.")
                return
            
            # Post using LinkedIn API
            success = self.post_to_linkedin(post_text)
            
            if success:
                # Mark topic and content as posted
                self.cve_tracker.mark_topic_posted(topic)
                self.cve_tracker.mark_content_posted(post_text)
                
                with open("Topics_done.txt", "a") as done_file:
                    done_file.write(f"{topic} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                logging.info(f"Topic posted and saved to Topics_done.txt: {topic}")

                # Remove the posted topic from Topics.txt
                remaining_topics = [t for t in topics if t.strip() != topic]
                with open("Topics.txt", "w") as file:
                    file.writelines(remaining_topics)
                logging.info("Topic removed from Topics.txt.")
            else:
                logging.info(f"Failed to post topic: {topic}")
            
            self.random_delay(5, 10)

        except Exception as e:
            logging.error("An error occurred while processing topics.", exc_info=True)



class LinkedInAPI:
    """Handles LinkedIn API operations for posting."""
    
    def __init__(self):
        self.access_token = os.getenv("LINKEDIN_ACCESS_TOKEN")
        self.org_urn = os.getenv("LINKEDIN_ORG_URN")
        
        if not self.access_token:
            logging.warning("LinkedIn access token not found. API posting will fail.")
        if not self.org_urn:
            logging.warning("LinkedIn organization URN not found. Will post to personal profile.")
    
    def create_post(self, content):
        """Create a post on LinkedIn using the API."""
        try:
            if self.org_urn:
                # Use Posts API for organization posting (newer API)
                return self._create_organization_post(content)
            else:
                # Use UGC Posts API for personal posting
                return self._create_personal_post(content)
                
        except Exception as e:
            logging.error(f"Failed to create LinkedIn post: {e}")
            return False
    
    def _create_organization_post(self, content):
        """Create organization post using Posts API."""
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'LinkedIn-Version': '202410',  # Updated version
                'X-Restli-Protocol-Version': '2.0.0',
                'Content-Type': 'application/json'
            }
            
            data = {
                'author': self.org_urn,
                'commentary': content,
                'visibility': 'PUBLIC',
                'distribution': {
                    'feedDistribution': 'MAIN_FEED',
                    'targetEntities': [],
                    'thirdPartyDistributionChannels': []
                },
                'lifecycleState': 'PUBLISHED',
                'isReshareDisabledByAuthor': False
            }
            
            # Use the Posts API endpoint for organizations
            response = requests.post(
                'https://api.linkedin.com/rest/posts',
                headers=headers,
                json=data
            )
            
            if response.status_code in [200, 201]:
                post_id = response.headers.get('x-restli-id')
                logging.info(f"Organization post created successfully. Post ID: {post_id}")
                return True
            else:
                logging.error(f"Organization posting failed: {response.status_code} - {response.text}")
                # Try alternative UGC API for organization
                return self._create_organization_ugc_post(content)
                
        except Exception as e:
            logging.error(f"Organization post creation failed: {e}")
            return False
    
    def _create_organization_ugc_post(self, content):
        """Fallback: Create organization post using UGC Posts API."""
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'LinkedIn-Version': '202410',
                'X-Restli-Protocol-Version': '2.0.0',
                'Content-Type': 'application/json'
            }
            
            data = {
                'author': self.org_urn,
                'lifecycleState': 'PUBLISHED',
                'specificContent': {
                    'com.linkedin.ugc.ShareContent': {
                        'shareCommentary': {
                            'text': content
                        },
                        'shareMediaCategory': 'NONE'
                    }
                },
                'visibility': {
                    'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC'
                }
            }
            
            response = requests.post(
                'https://api.linkedin.com/v2/ugcPosts',
                headers=headers,
                json=data
            )
            
            if response.status_code in [200, 201]:
                post_id = response.headers.get('X-RestLi-Id')
                logging.info(f"Organization UGC post created successfully. Post ID: {post_id}")
                return True
            else:
                logging.error(f"Organization UGC posting failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logging.error(f"Organization UGC post creation failed: {e}")
            return False
    
    def _create_personal_post(self, content):
        """Create personal post using UGC Posts API."""
        try:
            # Get person URN first
            person_urn = self._get_person_urn()
            if not person_urn:
                logging.error("Could not get person URN for personal posting")
                return False
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'LinkedIn-Version': '202410',
                'X-Restli-Protocol-Version': '2.0.0',
                'Content-Type': 'application/json'
            }
            
            data = {
                'author': person_urn,
                'lifecycleState': 'PUBLISHED',
                'specificContent': {
                    'com.linkedin.ugc.ShareContent': {
                        'shareCommentary': {
                            'text': content
                        },
                        'shareMediaCategory': 'NONE'
                    }
                },
                'visibility': {
                    'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC'
                }
            }
            
            response = requests.post(
                'https://api.linkedin.com/v2/ugcPosts',
                headers=headers,
                json=data
            )
            
            if response.status_code in [200, 201]:
                post_id = response.headers.get('X-RestLi-Id')
                logging.info(f"Personal post created successfully. Post ID: {post_id}")
                return True
            else:
                logging.error(f"Personal posting failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logging.error(f"Personal post creation failed: {e}")
            return False
    
    def _get_person_urn(self):
        """Get the person URN for personal posting."""
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'LinkedIn-Version': '202410'
            }
            
            response = requests.get('https://api.linkedin.com/v2/people/~', headers=headers)
            
            if response.status_code == 200:
                person_data = response.json()
                person_id = person_data.get('id', '')
                if person_id:
                    return f'urn:li:person:{person_id}'
                else:
                    logging.error("No person ID found in profile response")
                    return ''
            else:
                logging.error(f"Failed to get person profile: {response.status_code} - {response.text}")
                return ''
                
        except Exception as e:
            logging.error(f"Error getting person URN: {e}")
            return ''

if __name__ == "__main__":
    processor = CyberSecurityProcessor()
    try:
        processor.process_cybersecurity_topics()
        time.sleep(5)
    finally:
        logging.info("Content processing completed.")
