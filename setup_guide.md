# LinkedIn CVE Bot - Quick Setup Guide

## 📋 Prerequisites Checklist

- [ ] Python 3.7+ installed
- [ ] LinkedIn Developer account
- [ ] LinkedIn API access token
- [ ] Google Gemini API key
- [ ] Reddit API credentials (optional but recommended)

## 🚀 Quick Start (5 Minutes)

### 1. Clone and Install
```bash
git clone https://github.com/ovld-team/LinkedInDailyDigest.git
cd LinkedInDailyDigest
pip install -r requirements.txt
```

### 2. Setup Environment
```bash
cp .env.example .env
# Edit .env with your credentials
```

### 3. Test the Setup
```bash
# Test CVE fetching and content generation
python test_generation.py

# Test single LinkedIn post
python scheduler.py test
```

### 4. Start Daily Automation
```bash
# Run continuous daily posting
python daily_scheduler.py
```

## 🔑 API Keys Setup

### Google Gemini API (Required)
1. Visit [Google AI Studio](https://aistudio.google.com/)
2. Click "Get API Key" → "Create API Key"
3. Copy the key to your `.env` file:
   ```env
   GEMINI_API_KEY=your_key_here
   ```

### Reddit API (Optional - for r/CVEWatch integration)
1. Go to [Reddit Apps](https://www.reddit.com/prefs/apps)
2. Click "Create App"
3. Fill out:
   - **Name**: LinkedIn CVE Bot
   - **Type**: Script
   - **Description**: Fetches CVE data for LinkedIn posts
   - **Redirect URI**: http://localhost:8080
4. Copy credentials to `.env`:
   ```env
   REDDIT_CLIENT_ID=your_client_id
   REDDIT_CLIENT_SECRET=your_client_secret
   REDDIT_USER_AGENT=linkedin_cve_bot/1.0
   ```

## 🏢 Company Page Setup

1. Get your company page URL:
   ```
   https://www.linkedin.com/company/your-company-name/
   ```

2. Add to `.env`:
   ```env
   LINKEDIN_COMPANY_PAGE_URL=https://www.linkedin.com/company/your-company-name/
   ```

3. Ensure you have posting permissions on the company page

## 📅 Scheduling Options

### Option 1: Manual Posting
```bash
python processor.py  # Post once
```

### Option 2: Daily Automation
```bash
python scheduler.py  # Posts 1x daily at 9:00 AM
```

### Option 3: Custom Schedule
Edit `scheduler.py` and modify:
```python
self.posting_times = [
    "09:00",  # Morning
    "13:00",  # Lunch
    "17:00",  # End of day
]
self.max_daily_posts = 3
```

## 🔧 Configuration Options

### Environment Variables
```env
# Required
LINKEDIN_ACCESS_TOKEN=your_linkedin_access_token
GEMINI_API_KEY=your_gemini_key

# Optional
LINKEDIN_ORG_URN=urn:li:organization:your_org_id
REDDIT_CLIENT_ID=your_reddit_client_id
REDDIT_CLIENT_SECRET=your_reddit_client_secret
REDDIT_USER_AGENT=linkedin_cve_bot/1.0
```

### Content Customization
- **Topics**: Edit `Topics.txt` to add your preferred cybersecurity topics
- **Posting Time**: Modify morning posting time in `scheduler.py` (default: 9:00 AM)
- **CVE Sources**: Configure Reddit vs NIST preferences in `processor.py`

## 🧪 Testing Your Setup

### 1. Test CVE Fetching
```bash
python test_generation.py
```
Expected output:
- ✅ CVE data from NIST
- ✅ CVE data from Reddit (if configured)
- ✅ Content generation
- ✅ Content cleaning demonstration

### 2. Test LinkedIn API Posting
```bash
python scheduler.py test
```
Expected output:
- ✅ LinkedIn API authentication successful
- ✅ Company page or personal posting (based on URN)
- ✅ Post creation via API
- ✅ CVE tracking updated

## 🔍 Monitoring and Logs

### Log Files
- `scheduler.log` - Daily automation logs
- `cve_tracking.json` - Deduplication database

### Checking Status
```bash
# View recent logs
tail -f scheduler.log

# Check tracking database
cat cve_tracking.json | python -m json.tool
```

## 🚨 Common Issues & Solutions

### "LinkedIn API Authentication Failed"
- ✅ Check access token in `.env`
- ✅ Ensure token hasn't expired (60-day limit)
- ✅ Verify app has "Share on LinkedIn" permissions
- ✅ See detailed setup guide: `linkedin_api_setup.md`

### "No CVEs Found"
- ✅ Check internet connection
- ✅ Verify Reddit API credentials
- ✅ Check `cve_tracking.json` - might be all CVEs already posted

### "Organization Not Found"
- ✅ Verify organization URN format: `urn:li:organization:ID`
- ✅ Ensure you have admin/content creator permissions
- ✅ Test posting to personal profile first (leave URN empty)

### "Content Generation Failed"
- ✅ Verify Gemini API key and quota
- ✅ Check `Topics.txt` has unused topics
- ✅ Clear `cve_tracking.json` to reset deduplication

## 🎯 Success Indicators

Your bot is working correctly when you see:

1. **Daily Posts**: 3 posts per day at scheduled times
2. **Unique Content**: No duplicate CVEs or topics
3. **Professional Quality**: Clean, well-formatted posts
4. **CVE Integration**: Recent vulnerabilities included in posts
5. **Company Branding**: Posts appear on your company page

## 📞 Support

If you encounter issues:

1. Check the logs in `scheduler.log`
2. Run the test scripts to isolate the problem
3. Verify all API keys are valid and have quota
4. Ensure LinkedIn account has proper permissions

## 🔄 Maintenance

### Weekly
- Review posted content quality
- Check `Topics_done.txt` for variety
- Monitor API usage quotas

### Monthly
- Add new topics to `Topics.txt`
- Review and update CVE tracking
- Update dependencies: `pip install -r requirements.txt --upgrade`

---

🎉 **You're all set!** Your LinkedIn CVE bot will now automatically post engaging cybersecurity content with the latest vulnerability information from both NIST and Reddit sources. 