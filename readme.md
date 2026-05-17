# Google Login for WordPress

Adds a **"Continue with Google"** button to your WordPress login page using secure OAuth 2.0.



## Requirements

- WordPress 5.8+
- PHP 7.4+
- An HTTPS-enabled site (required by Google for production)



## Step 1 — Install the Plugin

1. Copy the `google-login-wp` folder into `wp-content/plugins/`
2. Go to **WordPress Admin → Plugins → Installed Plugins**
3. Find **Google Login for WordPress** and click **Activate**



## Step 2 — Create Google OAuth Credentials

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Click **Select a project → New Project**, give it a name, click **Create**
3. Go to **APIs & Services → OAuth consent screen**
   - Choose **External** → click **Create**
   - Fill in: App name, support email, developer email → **Save and Continue**
   - On the Scopes step, add: `openid`, `email`, `profile` → **Save and Continue**
   - Finish the remaining steps
4. Go to **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**
   - Application type: **Web application**
   - Under **Authorized redirect URIs**, click **Add URI** and paste your redirect URI (see Step 3)
   - Click **Create**
5. Copy your **Client ID** and **Client Secret** — you'll need them in Step 4



## Step 3 — Find Your Redirect URI

1. In WordPress, go to **Settings → Google Login**
2. Copy the **Redirect URI** shown on that page — it looks like:
   ```
   https://yoursite.com/wp-login.php?glwp_action=google_callback
   ```
3. Paste it into Google Cloud Console (Step 2 → Step 4 above)

> ⚠️ The URI must match **exactly** — no trailing slash differences, no HTTP vs HTTPS mismatch.



## Step 4 — Configure the Plugin

1. Go to **Settings → Google Login** in your WordPress admin
2. Paste your **Client ID** and **Client Secret**
3. Choose whether to allow **Auto-register new users** (creates a WordPress account automatically for first-time Google users)
4. Click **Save Settings**
5. The status table at the bottom of the page should show ✅ for all items



## Step 5 — Test It

1. Open your login page (`/wp-login.php`) in a private/incognito browser window
2. You should see a **"Continue with Google"** button below the login form
3. Click it → approve on Google → you should land on your dashboard


## File Structure

```
google-login-wp/
├── google-login-wp.php      ← Main plugin file
├── includes/
│   ├── functions.php        ← Shared helpers & settings
│   ├── oauth.php            ← Builds Google redirect URL
│   ├── callback.php         ← Handles Google's response & token exchange
│   ├── user.php             ← Creates or logs in WordPress users
│   └── admin.php            ← Settings page
└── assets/css/
    └── google-button.css    ← Button styling
```


## License

GPL-2.0+ — free to use, modify, and distribute.