# LinkedIn Cybersecurity Bot

An advanced Python bot that automates LinkedIn company page posting with a focus on cybersecurity content, latest CVE updates, and AI-generated security insights.

## Features

- 🔐 **Cybersecurity Focus**: Generates professional posts about cybersecurity topics, threat intelligence, and security best practices
- 🚨 **Dual CVE Sources**: Combines data from both NIST API and Reddit r/CVEWatch for comprehensive coverage
- 📱 **Reddit Integration**: Automatically fetches trending CVE discussions from r/CVEWatch community
- 🏢 **Company Page Support**: Posts to LinkedIn company pages (with fallback to personal feed)
- 🤖 **AI Content Generation**: Uses Google Gemini AI to create engaging, human-like content
- 🧹 **Content Cleaning**: Advanced cleaning to remove hidden characters and unwanted formatting from AI output
- 🚫 **Smart Deduplication**: Never posts the same CVE or similar content twice
- 📅 **Daily Security Briefings**: Automated posting at optimal business hours with daily digest format
- 📝 **Topic Management**: Processes topics from file and tracks completed posts
- 🔒 **Secure Login**: Cookie-based authentication with verification code support

## Daily Content Format

Your bot generates professional security briefings like:

> **Security Brief - January 15, 2025**
> 
> This week's threat intelligence shows a 40% spike in enterprise ransomware targeting financial institutions. Security teams are reporting sophisticated attacks bypassing traditional email gateways, with CVE-2025-1234 (CVSS: 9.8) enabling remote code execution in widely-used VPN solutions. 
> 
> The business impact is immediate - we're seeing average downtime of 72 hours and recovery costs exceeding $2M per incident. Security leaders should immediately audit VPN configurations and implement network segmentation as a critical control.
> 
> What defensive measures is your organization prioritizing this quarter? 
> 
> #cybersecurity #ransomware #threatintelligence #infosec #dailybrief

## Setup

### 1. Clone the Repository
```bash
git clone https://github.com/ovld-team/LinkedInDailyDigest.git
cd LinkedInDailyDigest
pip install -r requirements.txt
```

### 2. Environment Variables
Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

Required variables:
- `LINKEDIN_ACCESS_TOKEN`: Your LinkedIn API access token
- `GEMINI_API_KEY`: Your Google Gemini API key

Optional variables:
- `LINKEDIN_ORG_URN`: Organization URN for company page posting (e.g., `urn:li:organization:12345678`)
- `REDDIT_CLIENT_ID`: Reddit API client ID (for r/CVEWatch integration)
- `REDDIT_CLIENT_SECRET`: Reddit API client secret
- `REDDIT_USER_AGENT`: Bot user agent string

### 3. Get API Keys

#### LinkedIn API (Required)
1. Go to [LinkedIn Developer Portal](https://developer.linkedin.com/)
2. Create a new app with "Share on LinkedIn" permissions
3. Generate access token
4. Get organization URN for company posting
5. See detailed guide: `linkedin_api_setup.md`

#### Gemini API Key (Required)
1. Go to [Google AI Studio](https://aistudio.google.com/)
2. Create a new API key
3. Add it to your `.env` file

#### Reddit API Key (Recommended)
1. Go to [Reddit App Preferences](https://www.reddit.com/prefs/apps)
2. Click "Create App" → Choose "script" type
3. Fill in: 
   - **Name**: LinkedIn CVE Bot
   - **Redirect URI**: http://localhost:8080
4. Copy Client ID and Secret to your `.env` file

## Usage

### Single Post
```bash
# Post once to personal feed or company page
python processor.py
```

### Daily Automated Posting
```bash
# Run daily scheduler (posts 3x per day at optimal times)
python scheduler.py

# Test single scheduled post
python scheduler.py test
```

### Company Page Posting
Set your organization URN in the `.env` file:
```env
LINKEDIN_ORG_URN=urn:li:organization:your_org_id
```
Leave empty to post to personal profile.

### Content Testing & Preview
```bash
# Test CVE fetching and see exactly what will be posted
python test_generation.py
```

## How It Works

1. **API Authentication**: Uses LinkedIn API with OAuth access tokens
2. **CVE Collection**: Fetches vulnerabilities from both NIST API and Reddit r/CVEWatch
3. **Content Parsing**: Extracts CVE details, CVSS scores, and descriptions from Reddit posts
4. **Deduplication**: Checks against tracking database to avoid duplicate content
5. **Topic Selection**: Chooses unused cybersecurity topics from `Topics.txt`
6. **Content Generation**: Uses Gemini AI to create professional daily briefings
7. **Content Cleaning**: Removes hidden characters, markdown, and unwanted formatting
8. **API Posting**: Posts to company page or personal profile via LinkedIn API
9. **Tracking**: Records posted CVEs, topics, and content hashes to prevent duplicates

## Cybersecurity Topics

The bot comes pre-loaded with 200+ current cybersecurity topics including:
- Critical zero-day exploits discovered this week
- Enterprise ransomware attacks surge across financial sector
- Advanced persistent threats targeting cloud infrastructure
- Multi-factor authentication bypass techniques emerge
- Supply chain security breaches impact major vendors
- And much more current, actionable content...

## Content Features

### Dual-Source CVE Integration
- **NIST API**: Official government vulnerability database
- **Reddit r/CVEWatch**: Community-driven CVE discussions and analysis
- **Smart Parsing**: Extracts CVE IDs, CVSS scores, and descriptions from Reddit posts
- **Smart Merging**: Combines both sources, prioritizing Reddit context when available
- **CVSS Scoring**: Includes severity ratings for risk assessment

### Advanced Deduplication
- **CVE Tracking**: Never posts the same vulnerability twice
- **Topic Rotation**: Ensures variety in cybersecurity topics (30-day cooldown)
- **Content Hashing**: Prevents similar content from being posted
- **Intelligent Fallbacks**: Generates fresh content when duplicates detected

### AI Content Cleaning
- Removes hidden Unicode characters
- Strips markdown formatting
- Preserves hashtags and links
- Normalizes whitespace
- Eliminates zero-width characters

### Professional Tone
- Daily security briefing format
- Human-like cybersecurity expert voice
- Business impact analysis
- Actionable security advice
- Community engagement prompts
- Relevant hashtags (#cybersecurity #infosec #dailybrief)

## File Structure

- `processor.py` - Main cybersecurity content processor with LinkedIn API and Reddit integration
- `scheduler.py` - Automated daily posting scheduler
- `test_generation.py` - Testing script for content generation and preview
- `linkedin_api_setup.md` - LinkedIn API setup guide
- `utils.py` - Additional utilities (legacy)
- `Topics.txt` - Queue of cybersecurity topics to post
- `Topics_done.txt` - Completed topics log with timestamps
- `cve_tracking.json` - CVE and content deduplication database
- `requirements.txt` - Python dependencies (simplified, no Selenium)
- `.env.example` - Environment variables template
- `setup_guide.md` - Comprehensive setup instructions

## Security Considerations

- Store credentials securely in `.env` file
- Use strong, unique passwords
- Enable 2FA on LinkedIn account
- Review generated content before posting
- Monitor for unusual account activity

## Scheduling & Automation

### Daily Posting Schedule
- **9:00 AM**: Morning threat briefing
- **1:00 PM**: Midday community insights
- **5:00 PM**: End-of-day security summary

### Rate Limiting
- Maximum 3 posts per day
- Random delays (1-5 minutes) between actions
- Automatic daily counter reset

### Running as Service
```bash
# Linux/macOS - run in background
nohup python scheduler.py > scheduler.log 2>&1 &

# Windows - run as service (requires additional setup)
# Or use Task Scheduler for automation
```

## Troubleshooting

### LinkedIn API Issues
- **Access token expired**: Generate new token every 60 days
- **Insufficient permissions**: Ensure app has "Share on LinkedIn" product
- **Organization not found**: Verify URN format and admin rights
- **Rate limit exceeded**: LinkedIn allows ~100 posts per day

### API Issues
- **Gemini**: Verify API key is valid and has quota
- **Reddit**: Check client ID/secret, ensure app is "script" type
- **NIST**: API is public, check internet connection

### Content Generation
- Check `cve_tracking.json` for deduplication database
- Verify topics in `Topics.txt` aren't all used
- Review `scheduler.log` for detailed error messages
- Use `test_generation.py` to preview content and check API setup

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is for educational and legitimate business use only. Users are responsible for complying with LinkedIn's Terms of Service and applicable laws.

## Disclaimer

- Use responsibly and in accordance with LinkedIn's Terms of Service and API Terms
- LinkedIn API has built-in rate limiting (no browser automation required)
- CVE data is sourced from NIST's public API and Reddit community
- AI-generated content should be reviewed before posting
- Daily briefings are designed for cybersecurity thought leadership
- API approach is more reliable and compliant than browser automation

 
