<?php

/**
 * OAuth Callback Handler
 *
 * This file handles the most critical part of the OAuth flow:
 * when Google redirects the user back to our site with an authorization code.
 *
 * This is the "secure back room" where:
 * 1. We verify the security state parameter (CSRF check)
 * 2. We exchange the one-time code for an access token (server-to-server)
 * 3. We use that token to ask Google who the user is
 * 4. We hand the profile data to user.php to create/login the user
 *
 * IMPORTANT: Every step here has a security check. If anything fails,
 * we redirect with an error rather than proceeding. "Fail safe" is
 * the principle — reject on any doubt, rather than risk a bad login.
 *
 * @package Google_Login_WP
 */

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Main callback handler — orchestrates the entire post-Google-redirect flow.
 *
 * Called by the 'init' hook when ?glwp_action=google_callback is in the URL.
 *
 * This function is the "conductor" — it calls other functions in sequence
 * and stops if any step fails.
 */
function glwp_handle_google_callback()
{
    glwp_log('OAuth callback received', $_GET); // phpcs:ignore WordPress.Security.NonceVerification

    // ===================================================================
    // STEP A: Check if Google sent an error instead of a code
    // ===================================================================
    // When the user clicks "Cancel" on Google's consent screen, Google
    // doesn't send a 'code' — it sends ?error=access_denied instead.
    // We must handle this gracefully.
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    if (isset($_GET['error'])) {
        $google_error = sanitize_text_field($_GET['error']);
        glwp_log('Google returned an error', $google_error);
        // Redirect back to login — user probably just cancelled. No scary error.
        wp_safe_redirect(wp_login_url());
        exit;
    }

    // ===================================================================
    // STEP B: Verify the 'state' parameter (CRITICAL SECURITY CHECK)
    // ===================================================================
    // The state we sent to Google must come back unchanged.
    // If it's missing or doesn't match what we stored → ATTACK or expired session.
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';

    if (empty($state) || ! glwp_validate_oauth_state($state)) {
        glwp_log('State validation failed', array('received_state' => $state));
        glwp_redirect_with_error('state_mismatch');
        return;
    }

    glwp_log('State validation passed.');

    // ===================================================================
    // STEP C: Extract the Authorization Code
    // ===================================================================
    // The 'code' is a one-time-use token from Google. It's ONLY valid for
    // a few minutes and can only be used ONCE to get an access token.
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $code = isset($_GET['code']) ? sanitize_text_field($_GET['code']) : '';

    if (empty($code)) {
        glwp_log('No authorization code in callback URL.');
        glwp_redirect_with_error('no_code');
        return;
    }

    // ===================================================================
    // STEP D: Exchange the Code for an Access Token
    // ===================================================================
    // This is a server-to-server request (PHP → Google API).
    // The user's browser is NOT involved. This is why it's secure —
    // the token never appears in the browser's address bar or history.
    $token_data = glwp_exchange_code_for_token($code);

    if (is_wp_error($token_data)) {
        glwp_log('Token exchange failed', $token_data->get_error_message());
        glwp_redirect_with_error('token_failed');
        return;
    }

    $access_token = $token_data['access_token'];
    glwp_log('Token exchange successful.');

    // ===================================================================
    // STEP E: Use Access Token to Get User's Google Profile
    // ===================================================================
    $google_user = glwp_get_google_userinfo($access_token);

    if (is_wp_error($google_user)) {
        glwp_log('Failed to get user info', $google_user->get_error_message());
        glwp_redirect_with_error('userinfo_failed');
        return;
    }

    glwp_log('Google user info retrieved', array('email' => $google_user['email']));

    // ===================================================================
    // STEP F: Create or Log In the WordPress User
    // ===================================================================
    // Hand off to user.php — that file handles the WordPress side.
    $result = glwp_process_google_user($google_user);

    if (is_wp_error($result)) {
        glwp_log('User processing failed', $result->get_error_message());
        glwp_redirect_with_error($result->get_error_code());
        return;
    }

    // $result is a WP_User object if everything went well.
    $user = $result;

    // ===================================================================
    // STEP G: Set the WordPress Authentication Cookie (LOG THE USER IN)
    // ===================================================================
    // This is the WordPress equivalent of "logging in".
    // wp_set_auth_cookie() creates a secure cookie in the user's browser.
    // On every subsequent request, WordPress reads this cookie and knows
    // who the user is — they stay logged in.
    //
    // Second parameter: $remember
    // true  = persistent cookie (stays after browser closes)
    // false = session cookie (deleted when browser closes)
    //
    // We use 'false' here to match WordPress's default login behavior.
    // You could make this a setting later.
    wp_set_auth_cookie($user->ID, false);

    // Fire the 'wp_login' action — this is important because:
    // 1. Other plugins may listen for this hook (e.g., login logging plugins)
    // 2. WordPress itself uses it to update last login time
    // 3. It's the "correct" way to announce a login happened
    do_action('wp_login', $user->user_login, $user);

    glwp_log('User logged in successfully', array('user_id' => $user->ID, 'login' => $user->user_login));

    // ===================================================================
    // STEP H: Redirect to the appropriate page
    // ===================================================================
    // apply_filters( 'login_redirect', $default, $requested, $user ) allows
    // our (and other plugins') login_redirect filter hooks to decide where
    // to send the user. This is the correct WordPress way.
    $redirect_to = apply_filters('login_redirect', admin_url(), '', $user);

    wp_safe_redirect($redirect_to);
    exit;
}

/**
 * Exchanges a one-time authorization code for a Google access token.
 *
 * This is a server-to-server HTTP POST request to Google's token endpoint.
 * It happens entirely in PHP — the user's browser sees nothing of this.
 *
 * @param string $code The authorization code from the callback URL.
 * @return array|WP_Error Array with 'access_token' key on success, WP_Error on failure.
 */
function glwp_exchange_code_for_token($code)
{
    $client_id     = glwp_get_client_id();
    $client_secret = glwp_get_client_secret();

    // Validate we have what we need.
    if (empty($client_id) || empty($client_secret)) {
        return new WP_Error('missing_credentials', __('Google OAuth credentials are not configured.', 'google-login-wp'));
    }

    // -------------------------------------------------------------------
    // Build the POST request body
    // -------------------------------------------------------------------
    // This is what we send to Google to "buy" an access token with our code.
    // Think of the code like a cheque — we send it to Google's "bank"
    // (token endpoint), and in return we get cash (access token).
    $body = array(
        'code'          => $code,          // The one-time code from the URL
        'client_id'     => $client_id,     // Who we are
        'client_secret' => $client_secret, // Our secret password (proves we are who we say)
        'redirect_uri'  => GLWP_REDIRECT_URI, // Must match exactly what's in Google Console
        'grant_type'    => 'authorization_code', // Tells Google we're doing the standard OAuth flow
    );

    // -------------------------------------------------------------------
    // Make the HTTP request using WordPress's built-in HTTP API
    // -------------------------------------------------------------------
    // WHY wp_remote_post() instead of curl or file_get_contents()?
    // 1. WordPress abstraction — works on all hosting environments
    // 2. Respects WordPress SSL/TLS settings
    // 3. Integrates with WordPress caching and logging
    // 4. Automatically handles redirects, timeouts, etc.
    $response = wp_remote_post(
        GLWP_GOOGLE_TOKEN_URL,
        array(
            'body'    => $body,
            'timeout' => 15, // Seconds to wait for Google to respond. 15s is generous.
            // Without a timeout, a slow/unresponsive Google could hang your PHP process.
            'headers' => array(
                'Accept' => 'application/json',
            ),
        )
    );

    // -------------------------------------------------------------------
    // Check for WordPress-level errors (network failure, timeout, etc.)
    // -------------------------------------------------------------------
    // wp_remote_post returns a WP_Error if the REQUEST failed (e.g., no internet).
    // It does NOT return a WP_Error if Google returned HTTP 400 — we check that separately.
    if (is_wp_error($response)) {
        glwp_log('wp_remote_post error during token exchange', $response->get_error_message());
        return new WP_Error('http_error', $response->get_error_message());
    }

    // -------------------------------------------------------------------
    // Check HTTP response code
    // -------------------------------------------------------------------
    $http_code = wp_remote_retrieve_response_code($response);
    if (200 !== $http_code) {
        $body_text = wp_remote_retrieve_body($response);
        glwp_log('Google token endpoint returned non-200', array('http_code' => $http_code, 'body' => $body_text));
        return new WP_Error('token_http_error', sprintf('Google returned HTTP %d', $http_code));
    }

    // -------------------------------------------------------------------
    // Parse the JSON response
    // -------------------------------------------------------------------
    $body_text = wp_remote_retrieve_body($response);
    $token_data = json_decode($body_text, true); // true = associative array (not object)

    if (json_last_error() !== JSON_ERROR_NONE) {
        glwp_log('Failed to parse token response JSON', $body_text);
        return new WP_Error('json_parse_error', __('Invalid response from Google token endpoint.', 'google-login-wp'));
    }

    // -------------------------------------------------------------------
    // Validate the token data structure
    // -------------------------------------------------------------------
    if (empty($token_data['access_token'])) {
        glwp_log('No access_token in Google response', $token_data);
        return new WP_Error('no_access_token', __('Google did not return an access token.', 'google-login-wp'));
    }

    return $token_data;
}

/**
 * Retrieves the authenticated user's profile information from Google.
 *
 * After getting an access token, we use it like an ID badge to ask Google's
 * userinfo endpoint: "Who is the person who gave us this token?"
 *
 * @param string $access_token The access token from glwp_exchange_code_for_token().
 * @return array|WP_Error Array of user data on success, WP_Error on failure.
 *
 * Successful return array shape:
 * {
 *   'sub'            => '108...', // Google's unique user ID (never changes)
 *   'name'           => 'John Doe',
 *   'given_name'     => 'John',
 *   'family_name'    => 'Doe',
 *   'email'          => 'john@gmail.com',
 *   'email_verified' => true,
 *   'picture'        => 'https://lh3.googleusercontent.com/...',
 *   'locale'         => 'en',
 * }
 */
function glwp_get_google_userinfo($access_token)
{
    // -------------------------------------------------------------------
    // Make authenticated GET request to Google's userinfo endpoint
    // -------------------------------------------------------------------
    // We pass the access token in the Authorization header.
    // WHY header instead of URL parameter?
    // Headers don't appear in server logs or browser history. URL params do.
    // This is the industry standard way to authenticate API requests.
    $response = wp_remote_get(
        GLWP_GOOGLE_USERINFO_URL,
        array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token,
                // 'Bearer' is the OAuth token type — tells Google what kind of token we're sending.
            ),
            'timeout' => 15,
        )
    );

    // Check for WordPress-level HTTP error.
    if (is_wp_error($response)) {
        glwp_log('wp_remote_get error during userinfo fetch', $response->get_error_message());
        return new WP_Error('http_error', $response->get_error_message());
    }

    $http_code = wp_remote_retrieve_response_code($response);
    if (200 !== $http_code) {
        glwp_log('Google userinfo endpoint returned non-200', $http_code);
        return new WP_Error('userinfo_http_error', sprintf('Google returned HTTP %d', $http_code));
    }

    // Parse the JSON response.
    $body_text = wp_remote_retrieve_body($response);
    $user_data = json_decode($body_text, true);

    if (json_last_error() !== JSON_ERROR_NONE || empty($user_data)) {
        glwp_log('Failed to parse userinfo JSON', $body_text);
        return new WP_Error('json_parse_error', __('Invalid user data from Google.', 'google-login-wp'));
    }

    // -------------------------------------------------------------------
    // Validate critical fields
    // -------------------------------------------------------------------

    // 'sub' is the Google user's unique ID. It NEVER changes, even if they
    // change their name or email. This is what we use to identify a user
    // across multiple logins. If it's missing, something is very wrong.
    if (empty($user_data['sub'])) {
        glwp_log('Google user has no sub (unique ID)', $user_data);
        return new WP_Error('no_sub', __('Google did not return a user identifier.', 'google-login-wp'));
    }

    // Email is required for WordPress account creation.
    if (empty($user_data['email'])) {
        glwp_log('Google user has no email', $user_data);
        return new WP_Error('no_email', __('No email address provided by Google.', 'google-login-wp'));
    }

    // WHY check email_verified?
    // Google allows users to have accounts with unverified email addresses.
    // An unverified email could be:
    // 1. Owned by someone else (typo)
    // 2. Used to impersonate another user on your site
    // We only accept verified emails for security.
    if (empty($user_data['email_verified']) || true !== $user_data['email_verified']) {
        glwp_log('Google email not verified', $user_data['email']);
        return new WP_Error('email_not_verified', __('Google email address is not verified.', 'google-login-wp'));
    }

    return $user_data;
}
