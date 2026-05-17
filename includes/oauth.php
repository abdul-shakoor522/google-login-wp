<?php

/**
 * OAuth URL Builder
 *
 * This file has ONE job: build the URL that sends the user to Google,
 * and initiate that redirect.
 *
 * Think of this file as the "travel agent" — it figures out the destination
 * URL with all the right parameters, and books the trip (redirects the user).
 *
 * @package Google_Login_WP
 */

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Builds the Google OAuth 2.0 Authorization URL.
 *
 * This is the URL we send the user to when they click "Continue with Google".
 * Google reads the parameters to know: who is asking (client_id), what
 * information they want (scope), and where to send the user back (redirect_uri).
 *
 * @return string|WP_Error The full Google authorization URL, or WP_Error on failure.
 */
function glwp_build_auth_url()
{
    // -------------------------------------------------------------------
    // 1. Get credentials from settings
    // -------------------------------------------------------------------
    $client_id = glwp_get_client_id();

    if (empty($client_id)) {
        // WP_Error is WordPress's standard way to return errors from functions.
        // First argument: error code (machine-readable)
        // Second argument: error message (human-readable)
        return new WP_Error('no_client_id', __('Google Client ID is not configured.', 'google-login-wp'));
    }

    // -------------------------------------------------------------------
    // 2. Generate a secure state parameter (anti-CSRF)
    // -------------------------------------------------------------------
    // This function (in functions.php) creates a random string AND stores
    // it in a transient so we can verify it when Google sends it back.
    $state = glwp_generate_oauth_state();

    // -------------------------------------------------------------------
    // 3. Define the OAuth scopes (what user data we're requesting)
    // -------------------------------------------------------------------
    // Scopes are permissions. We're asking Google for:
    // - 'openid'  : confirms the user's identity (required for OAuth 2.0)
    // - 'email'   : the user's email address
    // - 'profile' : name, profile picture, locale
    //
    // PRINCIPLE OF LEAST PRIVILEGE: only request what you need.
    // Requesting unnecessary scopes (like 'https://mail.google.com') would
    // alarm users and likely cause them to cancel the flow.
    $scopes = array(
        'openid',
        'email',
        'profile',
    );

    // Google expects scopes as a space-separated string.
    $scope_string = implode(' ', $scopes);

    // -------------------------------------------------------------------
    // 4. Build the query parameters array
    // -------------------------------------------------------------------
    $params = array(
        'client_id'             => $client_id,
        // WHERE should Google send the user after they approve?
        // Must exactly match what you entered in Google Cloud Console.
        'redirect_uri'          => GLWP_REDIRECT_URI,

        // 'code' means "give us an authorization code" — the standard OAuth flow.
        // The alternative 'token' is the implicit flow, which is LESS SECURE
        // because the token is exposed in the browser. We always use 'code'.
        'response_type'         => 'code',

        'scope'                 => $scope_string,

        // Our anti-CSRF token — Google will return this in the callback.
        'state'                 => $state,

        // 'select_account' forces the Google account picker to appear,
        // even if the user is already logged into one Google account.
        // WHY? On shared computers, you want to let the user choose which
        // Google account to use, not auto-select the last one.
        'prompt'                => 'select_account',

        // 'offline' access_type would give us a refresh token (for long-term access).
        // We don't need that — we only need the user's identity right now.
        'access_type'           => 'online',
    );

    // -------------------------------------------------------------------
    // 5. Assemble the final URL
    // -------------------------------------------------------------------
    // add_query_arg() takes an array of parameters and appends them to a base URL.
    // It handles URL encoding automatically (spaces become %20, etc.).
    // This is much safer than manually concatenating strings with '?' and '&'.
    $auth_url = add_query_arg($params, GLWP_GOOGLE_AUTH_URL);

    glwp_log('Built Google auth URL', array('url' => $auth_url));

    return $auth_url;
}

/**
 * Redirects the user to Google's OAuth authorization page.
 *
 * This function is called by the 'init' hook dispatcher in the main plugin file
 * when it detects ?glwp_action=google_login in the URL.
 *
 * After this function runs, the user's browser is sent to Google.
 * PHP execution stops (because of exit).
 */
function glwp_redirect_to_google()
{
    // Check plugin is configured before trying to redirect.
    $client_id = glwp_get_client_id();
    if (empty($client_id)) {
        glwp_log('Redirect to Google attempted but Client ID is not configured.');
        glwp_redirect_with_error('not_configured');
        return;
    }

    // Build the URL.
    $auth_url = glwp_build_auth_url();

    // Check for errors.
    if (is_wp_error($auth_url)) {
        glwp_log('Failed to build auth URL', $auth_url->get_error_message());
        glwp_redirect_with_error('not_configured');
        return;
    }

    // ----------------------------------------------------------------
    // SECURITY: wp_redirect() vs wp_safe_redirect()
    // ----------------------------------------------------------------
    // wp_safe_redirect() only allows redirects to:
    // - The same domain as your WordPress site
    // - Explicitly whitelisted domains
    //
    // PROBLEM: Google's domain (accounts.google.com) is NOT your domain.
    // So we must use wp_redirect() here.
    //
    // But isn't wp_redirect() unsafe? It CAN be if you pass user-supplied
    // URLs to it. Our URL is built entirely from:
    // - Our own constants (GLWP_GOOGLE_AUTH_URL, GLWP_REDIRECT_URI)
    // - Our plugin settings (client_id, which we read from the database)
    // - Our own generated state string
    //
    // NO user-supplied data goes into this URL, so it's safe.
    // ----------------------------------------------------------------

    // Status code 302 = temporary redirect (browser doesn't cache it).
    // Status code 301 = permanent redirect (browser DOES cache it — avoid for OAuth).
    wp_redirect($auth_url, 302); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
    exit; // CRITICAL: always exit after a redirect.
}
