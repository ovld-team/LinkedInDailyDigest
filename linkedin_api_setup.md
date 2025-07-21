# LinkedIn API Setup Guide

This guide will help you set up LinkedIn API access for the cybersecurity bot.

## 🔑 Getting LinkedIn API Access

### Step 1: Create LinkedIn Developer Account
1. Go to [LinkedIn Developer Portal](https://developer.linkedin.com/)
2. Sign in with your LinkedIn account
3. Click "Create App"

### Step 2: Create Your App
Fill out the application form:

- **App name**: `Cybersecurity Content Bot`
- **LinkedIn Page**: Select your company page (if posting to company page)
- **App description**: `Automated cybersecurity content posting with CVE intelligence`
- **App logo**: Upload your company logo
- **Legal agreement**: Accept terms

### Step 3: Configure App Permissions
In your app dashboard, go to the **Products** tab and request:

- **Community Management API** - Required for organization/company page posting

> ⚠️ **Important for Company Posting**: 
> - You need **Community Management API** access for organization posting
> - Your LinkedIn account must be an **ADMINISTRATOR** or **DIRECT_SPONSORED_CONTENT_POSTER** on the company page
> - The access token must include `w_organization_social` permission scope

### Step 4: Get Your Credentials

#### Access Token
1. Go to the **Auth** tab in your app
2. Under **OAuth 2.0 settings**, note your:
   - **Client ID**
   - **Client Secret**
3. Add redirect URL: `http://localhost:8080/callback`

#### Generate Access Token
You'll need to implement OAuth flow or use LinkedIn's test token:

**For testing** (expires in 60 days):
1. Go to **Auth** tab → **OAuth 2.0 tools**
2. Click "Generate token"
3. Copy the access token

**For production** (recommended):
Implement OAuth 2.0 flow in your application.

#### Get Organization URN (for company posting)

**Method 1: From LinkedIn Company Page URL**
1. Go to your company's LinkedIn page
2. Look at the URL: `https://www.linkedin.com/company/your-company-name/`
3. View page source (Ctrl+U) and search for `"organizationId"`
4. You'll find: `"organizationId":"12345678"`
5. Your URN is: `urn:li:organization:12345678`

**Method 2: Using LinkedIn API (requires admin permissions)**
```bash
# First, check what organizations you can access
curl -X GET 'https://api.linkedin.com/v2/organizations?q=administeredOrganization' \
-H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

**Method 3: Using People API (alternative)**
```bash
# Get your profile first, then check for organization roles
curl -X GET 'https://api.linkedin.com/v2/people/~:(id,firstName,lastName)' \
-H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

**Method 4: Manual lookup from Company Page**
1. Go to your LinkedIn company page
2. Click "Edit page" (if you're an admin)
3. The organization ID will be in the URL or page data

### Step 5: Add to Environment Variables

Add these to your `.env` file:

```env
# LinkedIn API Credentials
LINKEDIN_ACCESS_TOKEN=your_access_token_here
LINKEDIN_ORG_URN=urn:li:organization:12345678

# Other required credentials
GEMINI_API_KEY=your_gemini_key
REDDIT_CLIENT_ID=your_reddit_client_id
REDDIT_CLIENT_SECRET=your_reddit_client_secret
REDDIT_USER_AGENT=linkedin_cve_bot/1.0
```

## 🧪 Testing Your Setup

Run the test script to verify everything works:

```bash
python test_generation.py
```

You should see:
- ✅ LinkedIn Access Token: Configured
- ✅ Organization URN: Configured (Company page)
- ✅ Reddit API: Configured

## 📝 Sample API Call

Here's what the bot does internally:

```python
import requests

headers = {
    'Authorization': f'Bearer {access_token}',
    'LinkedIn-Version': '202506',
    'X-Restli-Protocol-Version': '2.0.0',
    'Content-Type': 'application/json'
}

data = {
    'author': 'urn:li:organization:12345678',
    'commentary': 'Your cybersecurity post content...',
    'visibility': 'PUBLIC',
    'distribution': {
        'feedDistribution': 'MAIN_FEED'
    },
    'lifecycleState': 'PUBLISHED'
}

response = requests.post(
    'https://api.linkedin.com/rest/posts',
    headers=headers,
    json=data
)
```

## 🚨 Troubleshooting

### "Access token expired"
- Tokens expire every 60 days
- Implement refresh token flow for production
- Generate new token from Developer Portal

### "Insufficient permissions" or "ACCESS_DENIED"
- **For personal posting**: Ensure your app has "Share on LinkedIn" product
- **For organization posting**: Ensure your app has "Community Management API" product
- Verify you are an ADMINISTRATOR on the company page
- Check organization URN format: `urn:li:organization:12345678`
- **For organization URN issues**: Use Method 1 (page source) instead of API
- Your access token must include `w_organization_social` scope for company posting

### "Organization permissions must be used when using organization as author"
- This means you need **Community Management API** access
- Your LinkedIn account must be an **ADMINISTRATOR** or **DIRECT_SPONSORED_CONTENT_POSTER** on the company page
- Apply for Community Management API through LinkedIn Developer Portal
- The access token must be generated with organization permissions

### "Rate limit exceeded"
- LinkedIn allows ~100 posts per day
- Bot includes automatic delays
- Spread posts throughout the day

### "Organization not found"
- Verify organization URN format: `urn:li:organization:ID`
- Ensure you have admin rights to the company page
- Test with personal profile first (leave ORG_URN empty)

## 🔐 Security Best Practices

1. **Never commit tokens** - Keep `.env` in `.gitignore`
2. **Rotate tokens regularly** - Generate new ones monthly
3. **Monitor usage** - Check Developer Portal for API calls
4. **Use HTTPS** - Always use secure connections
5. **Limit scope** - Only request necessary permissions

## 📚 Official Documentation

- [LinkedIn API Documentation](https://docs.microsoft.com/en-us/linkedin/)
- [Share on LinkedIn API](https://docs.microsoft.com/en-us/linkedin/marketing/integrations/community-management/shares/share-api)
- [OAuth 2.0 Authentication](https://docs.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow)

---

🎉 **You're ready!** Your bot can now post professional cybersecurity content directly via LinkedIn's API. 