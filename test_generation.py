#!/usr/bin/env python3
"""
Test script for LinkedIn Cybersecurity Bot content generation
This script demonstrates the exact content that will be posted to LinkedIn via API
"""

import os
import json
import requests
import unicodedata
import re
from dotenv import load_dotenv
import google.generativeai as genai
import praw
from datetime import datetime, timedelta
import hashlib

load_dotenv()

class CVETracker:
    """Simple CVE tracker for testing."""
    
    def __init__(self):
        self.posted_cves = []
    
    def is_cve_posted(self, cve_id):
        return cve_id in self.posted_cves
    
    def mark_cve_posted(self, cve_id):
        if cve_id not in self.posted_cves:
            self.posted_cves.append(cve_id)

def setup_reddit():
    """Setup Reddit API client for testing."""
    try:
        reddit = praw.Reddit(
            client_id=os.getenv("REDDIT_CLIENT_ID", ""),
            client_secret=os.getenv("REDDIT_CLIENT_SECRET", ""),
            user_agent=os.getenv("REDDIT_USER_AGENT", "linkedin_cve_bot/1.0"),
        )
        print("✅ Reddit API configured successfully")
        return reddit
    except Exception as e:
        print(f"❌ Reddit API setup failed: {e}")
        return None

def extract_cve_section(text, cve_id):
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

def extract_cve_description(text, cve_id):
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

def fetch_reddit_cves(reddit, tracker, limit=5):
    """Fetch CVE information from Reddit r/CVEWatch with improved parsing."""
    reddit_cves = []
    
    if not reddit:
        print("⚠️ Reddit API not available, skipping Reddit CVEs")
        return reddit_cves
    
    try:
        print("🔍 Fetching CVEs from Reddit r/CVEWatch...")
        subreddit = reddit.subreddit("CVEWatch")
        
        for submission in subreddit.new(limit=limit):
            print(f"📄 Analyzing post: {submission.title[:60]}...")
            
            # Extract CVE IDs from both title and content
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            full_text = f"{submission.title} {submission.selftext}"
            cve_matches = re.findall(cve_pattern, full_text, re.IGNORECASE)
            
            if cve_matches:
                print(f"   🎯 Found {len(cve_matches)} CVEs in this post")
                
                # Process multiple CVEs from a single post
                for cve_match in cve_matches[:5]:  # Limit to 5 CVEs per post
                    cve_id = cve_match.upper()
                    
                    # Skip if already posted
                    if tracker.is_cve_posted(cve_id):
                        print(f"   ⏭️ Skipping {cve_id} (already posted)")
                        continue
                    
                    # Extract CVSS score for this specific CVE
                    severity = "Unknown"
                    cve_section = extract_cve_section(full_text, cve_id)
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
                    description = extract_cve_description(full_text, cve_id)
                    
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
                    
                    print(f"   ✅ Added {cve_id} (CVSS: {severity})")
        
        print(f"✅ Found {len(reddit_cves)} new CVEs from Reddit")
        return reddit_cves
        
    except Exception as e:
        print(f"❌ Failed to fetch Reddit CVEs: {e}")
        return reddit_cves

def fetch_latest_cves(tracker, limit=3):
    """Fetch latest CVE entries from NIST API."""
    try:
        print("🔍 Fetching CVEs from NIST...")
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
            if tracker.is_cve_posted(cve_id):
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
                'source': 'nist',
                'post_date': 'Recent'
            })
            
        print(f"✅ Found {len(cves)} new CVEs from NIST")
        return cves
    except Exception as e:
        print(f"❌ Failed to fetch NIST CVEs: {e}")
        return []

def get_combined_cve_data(reddit, tracker, reddit_limit=5, nist_limit=3):
    """Combine CVE data from Reddit and NIST, ensuring no duplicates."""
    reddit_cves = fetch_reddit_cves(reddit, tracker, reddit_limit)
    nist_cves = fetch_latest_cves(tracker, nist_limit)
    
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
    
    print(f"📊 Combined CVE data: {len(combined_cves)} unique CVEs")
    return combined_cves

def clean_ai_content(text):
    """Comprehensive cleaning of AI-generated content."""
    if not text:
        return ""
    
    print("🧹 Cleaning AI-generated content...")
    
    # Remove hidden characters and normalize Unicode
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
    
    # Remove markdown formatting but keep hashtags
    patterns = [
        r"(\*{1,2})(.*?)\1",  # Bold and italics
        r"\[(.*?)\]\((.*?)\)",  # Links -> keep text, remove URL
        r"`(.*?)`",  # Inline code
        r"(\n\s*)- (.*)",  # Unordered lists (with `-`)
        r"(\n\s*)\* (.*)",  # Unordered lists (with `*`)
        r"(\n\s*)[0-9]+\. (.*)",  # Ordered lists
        r"(>+)(.*)",  # Blockquotes
        r"(---|\*\*\*)",  # Horizontal rules
        r"!\[(.*?)\]\((.*?)\)",  # Images
    ]

    # Replace patterns while preserving content
    for pattern in patterns:
        if pattern == r"\[(.*?)\]\((.*?)\)":  # Special handling for links
            text = re.sub(pattern, r"\1", text)
        elif pattern in [r"(\n\s*)- (.*)", r"(\n\s*)\* (.*)", r"(\n\s*)[0-9]+\. (.*)"]:
            text = re.sub(pattern, r"\1\2", text)
        elif pattern == r"(\*{1,2})(.*?)\1":  # Bold and italics
            text = re.sub(pattern, r"\2", text)
        elif pattern == r"`(.*?)`":  # Inline code
            text = re.sub(pattern, r"\1", text)
        elif pattern == r"(>+)(.*)":  # Blockquotes
            text = re.sub(pattern, r"\2", text)
        elif pattern == r"!\[(.*?)\]\((.*?)\)":  # Images
            text = re.sub(pattern, r"\1", text)
        else:
            # For patterns with only one group or no specific handling
            text = re.sub(pattern, "", text)

    # Clean up excessive whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)  # Max 2 consecutive newlines
    text = re.sub(r' {2,}', ' ', text)  # Remove multiple spaces
    text = text.strip()
    
    return text

def generate_cybersecurity_content(topic, cves=None):
    """Generate cybersecurity content using Gemini AI with enhanced prompting."""
    print(f"🤖 Generating content for topic: {topic}")
    
    try:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            print("❌ GEMINI_API_KEY not found in environment variables")
            return f"🔒 Daily Security Brief: {topic} #cybersecurity #infosec #dailybrief"
        
        genai.configure(api_key=api_key)
        client = genai.GenerativeModel("gemini-1.5-flash")

        # Build CVE context
        cve_context = ""
        if cves:
            cve_context = "\n\nLatest Critical Vulnerabilities:\n"
            for cve in cves[:3]:  # Max 3 CVEs
                source = "Community Analysis" if cve['source'] == 'reddit' else "Official NIST"
                post_date = cve.get('post_date', 'Recent')
                cve_context += f"• {cve['id']} (CVSS: {cve['cvss_score']}) - {source} ({post_date})\n  Impact: {cve['description']}\n"

        current_date = datetime.now().strftime('%B %d, %Y')
        
        prompt = f"""You are a cybersecurity expert writing for a company LinkedIn page. Create an engaging daily security briefing post.

TOPIC: {topic}
DATE: {current_date}

REQUIREMENTS:
- Write like a human cybersecurity professional, not an AI
- 900-1200 characters (LinkedIn optimal length)
- Professional but conversational tone
- Include specific actionable advice
- Start with a compelling hook or current event reference
- Use natural transitions, not bullet points
- Add relevant hashtags at the end
- Avoid buzzwords and corporate speak
- Make it feel urgent but not alarmist

{cve_context if cve_context else ""}

STRUCTURE:
1. Opening hook (current threat landscape/news)
2. Main insight about the topic
3. Practical business impact
4. 1-2 specific action items
5. Closing thought that encourages engagement
6. Relevant hashtags

Write as if you're sharing insider knowledge with fellow security professionals. Use "we" and "our" to create community. Include specific numbers, timeframes, or examples when possible.

Example tone: "This week's threat intelligence shows..." or "Security teams are reporting..." or "Based on recent incident data..."

DO NOT use markdown, bullet points, or corporate jargon. Write in flowing, natural sentences."""

        response = client.generate_content(prompt)

        if response.text:
            # Clean the AI-generated content
            cleaned_content = clean_ai_content(response.text)
            return cleaned_content
        else:
            return f"🔒 Daily Security Brief: {topic} - Latest threat intelligence and actionable insights. #cybersecurity #infosec #dailybrief"
            
    except Exception as e:
        print(f"❌ Failed to generate content: {e}")
        return f"🔒 Daily Security Brief: {topic} - Critical security updates and threat analysis. #cybersecurity #infosec #dailybrief"

def main():
    """Main demonstration function with comprehensive output."""
    print("🚀 LinkedIn Cybersecurity Bot - FINAL CONTENT PREVIEW")
    print("=" * 80)
    
    # Check API configuration
    access_token = os.getenv("LINKEDIN_ACCESS_TOKEN", "")
    org_urn = os.getenv("LINKEDIN_ORG_URN", "")
    
    print("🔧 API Configuration Check:")
    print(f"   LinkedIn Access Token: {'✅ Configured' if access_token else '❌ Missing'}")
    print(f"   Organization URN: {'✅ Configured (Company page)' if org_urn else '⚠️ Missing (Personal profile)'}")
    print(f"   Reddit API: {'✅ Configured' if setup_reddit() else '⚠️ Not configured'}")
    print()
    
    # Initialize tracker and Reddit
    tracker = CVETracker()
    reddit = setup_reddit()
    
    # Test multiple topics
    test_topics = [
        "Critical zero-day exploits discovered this week",
        "Enterprise ransomware attacks surge across financial sector",
        "Advanced persistent threats targeting cloud infrastructure"
    ]
    
    for i, test_topic in enumerate(test_topics, 1):
        print(f"\n📝 CONTENT PREVIEW #{i}")
        print(f"Topic: {test_topic}")
        print("-" * 60)
        
        # Fetch combined CVE data
        combined_cves = get_combined_cve_data(reddit, tracker, reddit_limit=5, nist_limit=3)
        
        if combined_cves:
            print("📋 CVE Sources Used:")
            for cve in combined_cves[:3]:
                source_emoji = "📱" if cve['source'] == 'reddit' else "🏛️"
                print(f"   {source_emoji} {cve['id']} (CVSS: {cve['cvss_score']}) - {cve.get('post_date', 'Recent')}")
            print()
        
        # Generate content
        content = generate_cybersecurity_content(test_topic, combined_cves)
        
        # Display final result
        print("📄 FINAL LINKEDIN POST (via API):")
        print("=" * 50)
        print(content)
        print("=" * 50)
        print(f"📊 Character count: {len(content)}")
        print(f"✅ LinkedIn optimal range: {'YES' if 800 <= len(content) <= 1300 else 'NO'}")
        print(f"🎯 Will post to: {'Company page' if org_urn else 'Personal profile'}")
        
        # Mark CVEs as used for next iteration
        for cve in combined_cves[:3]:
            tracker.mark_cve_posted(cve['id'])
        
        if i < len(test_topics):
            print(f"\n{'='*40} NEXT CONTENT {'='*40}")

    print(f"\n🎯 SUMMARY")
    print(f"Generated {len(test_topics)} unique LinkedIn posts")
    print(f"Used {len(tracker.posted_cves)} CVEs from community and official sources")
    print(f"All content optimized for LinkedIn API posting")
    print(f"Ready for daily automation via LinkedIn API!")
    
    if not access_token:
        print(f"\n⚠️ SETUP REQUIRED:")
        print(f"   1. Get LinkedIn API access token from Developer Portal")
        print(f"   2. Add LINKEDIN_ACCESS_TOKEN to your .env file")
        print(f"   3. Optionally add LINKEDIN_ORG_URN for company page posting")

if __name__ == "__main__":
    main() 