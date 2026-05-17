<?php

/**
 * WordPress User Management
 *
 * This file handles everything related to WordPress users in the Google login flow:
 * 1. Find an existing user by their Google ID or email
 * 2. Create a new user if they don't exist
 * 3. Update their stored Google profile data
 *
 * Think of this file as the "registrar's office":
 * - Check if the student (user) is already enrolled (registered in WordPress)
 * - If yes, update their record and let them in
 * - If no, and enrollment is open (auto_register = true), enroll them now
 * - If no, and enrollment is closed, turn them away politely
 *
 * @package Google_Login_WP
 */

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Main entry point: processes a Google user and returns a WP_User.
 *
 * Decides whether to find an existing user or create a new one.
 *
 * @param array $google_user Google userinfo data from glwp_get_google_userinfo().
 * @return WP_User|WP_Error WP_User on success, WP_Error on failure.
 */
function glwp_process_google_user($google_user)
{
    // -------------------------------------------------------------------
    // Sanitize ALL incoming Google data before touching our database
    // -------------------------------------------------------------------
    // Even though this data came from Google (a trusted API), we still
    // sanitize it. Why?
    // 1. Defense in depth — what if Google was compromised?
    // 2. A user could have special characters in their name that break things
    // 3. WordPress coding standards require sanitizing all external input
    $google_id    = sanitize_text_field($google_user['sub']);       // Unique Google user ID
    $email        = sanitize_email($google_user['email']);           // Email address
    $display_name = sanitize_text_field($google_user['name'] ?? ''); // Full name (e.g., "John Doe")
    $first_name   = sanitize_text_field($google_user['given_name'] ?? '');
    $last_name    = sanitize_text_field($google_user['family_name'] ?? '');
    $avatar_url   = esc_url_raw($google_user['picture'] ?? '');      // Profile picture URL
    $locale       = sanitize_text_field($google_user['locale'] ?? 'en');

    // Validate email after sanitization.
    if (! is_email($email)) {
        return new WP_Error('invalid_email', __('The email address from Google is not valid.', 'google-login-wp'));
    }

    // -------------------------------------------------------------------
    // LOOKUP STRATEGY: Try multiple ways to find an existing user
    // -------------------------------------------------------------------
    // WHY multiple methods?
    // A user might have:
    // a) Previously logged in with Google (we stored their Google ID in meta)
    // b) Previously registered manually with the same email (no Google ID stored yet)
    // We check both, in order of reliability.

    // Method 1: Find by Google ID (most reliable — IDs never change)
    $wp_user = glwp_find_user_by_google_id($google_id);

    // Method 2: Find by email address (handles existing manual accounts)
    if (! $wp_user) {
        $wp_user = get_user_by('email', $email);
        // get_user_by() returns false if no user found, or a WP_User object.
    }

    if ($wp_user) {
        // -------------------------------------------------------------------
        // EXISTING USER PATH: Update their data and log them in
        // -------------------------------------------------------------------
        glwp_log('Found existing user', array('user_id' => $wp_user->ID));

        // Refresh their Google metadata in case it changed (name, avatar, etc.)
        // We do this silently — no error if it fails.
        glwp_save_google_user_meta($wp_user->ID, $google_id, $avatar_url, $locale);

        return $wp_user;
    }

    // -------------------------------------------------------------------
    // NEW USER PATH: Check if auto-registration is allowed
    // -------------------------------------------------------------------
    if (! glwp_is_auto_register_enabled()) {
        glwp_log('Auto-register is disabled. New user rejected.', array('email' => $email));
        return new WP_Error('registration_off', __('Account registration is disabled.', 'google-login-wp'), 'registration_off');
    }

    // -------------------------------------------------------------------
    // Create new WordPress user
    // -------------------------------------------------------------------
    $new_user_id = glwp_create_user_from_google($google_id, $email, $display_name, $first_name, $last_name, $avatar_url, $locale);

    if (is_wp_error($new_user_id)) {
        return $new_user_id;
    }

    glwp_log('New user created', array('user_id' => $new_user_id, 'email' => $email));

    // Retrieve and return the newly created WP_User object.
    return get_user_by('id', $new_user_id);
}

/**
 * Finds a WordPress user by their Google ID (stored in user meta).
 *
 * WHY store Google ID in user meta?
 * Email addresses can change. A user's Google ID ('sub') NEVER changes.
 * By storing the Google ID, we can match a returning user even if they
 * updated their Gmail address.
 *
 * @param string $google_id The 'sub' value from Google's userinfo response.
 * @return WP_User|false WP_User object if found, false if not found.
 */
function glwp_find_user_by_google_id($google_id)
{
    // WP_User_Query searches the users and usermeta tables.
    $query = new WP_User_Query(
        array(
            // 'meta_query' searches the wp_usermeta table.
            'meta_query' => array( // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
                array(
                    'key'   => 'glwp_google_id', // Our custom meta key
                    'value' => $google_id,        // The Google ID to find
                ),
            ),
            'number' => 1, // We only expect one user — stop searching after first match.
            // Limiting to 1 result = faster database query.
        )
    );

    $users = $query->get_results();

    if (! empty($users)) {
        return $users[0]; // Return the first (and should be only) matching WP_User.
    }

    return false;
}

/**
 * Creates a new WordPress user from Google profile data.
 *
 * @param string $google_id    Google unique user ID.
 * @param string $email        User's email address.
 * @param string $display_name User's full display name.
 * @param string $first_name   User's first name.
 * @param string $last_name    User's last name.
 * @param string $avatar_url   URL to user's Google profile picture.
 * @param string $locale       User's locale (e.g., 'en').
 * @return int|WP_Error New user ID on success, WP_Error on failure.
 */
function glwp_create_user_from_google($google_id, $email, $display_name, $first_name, $last_name, $avatar_url, $locale)
{
    // -------------------------------------------------------------------
    // Generate a username from the email address
    // -------------------------------------------------------------------
    // WordPress requires a username (user_login). We generate one from
    // the email because the user never sees it (they log in via Google).
    //
    // Strategy:
    // 1. Take the part before @ (e.g., "john.doe" from "john.doe@gmail.com")
    // 2. Sanitize it (WordPress usernames allow letters, numbers, ., -, @, _)
    // 3. If that username is already taken, add a number until it's unique
    $username_base = sanitize_user(strstr($email, '@', true), true);
    // strstr( $email, '@', true ) = everything BEFORE the @ sign
    // sanitize_user( ..., true ) = strict mode — removes anything not alphanumeric/.-_

    // Ensure we have at least something to work with.
    if (empty($username_base)) {
        $username_base = 'user';
    }

    $username = $username_base;
    $suffix   = 1;

    // Keep adding numbers until we find a username that doesn't exist.
    // e.g., johndoe → johndoe2 → johndoe3
    while (username_exists($username)) {
        $username = $username_base . $suffix;
        $suffix++;
        // Safety valve: if we somehow can't find a unique name after 100 tries,
        // use a timestamp-based name. This should never happen in practice.
        if ($suffix > 100) {
            $username = $username_base . '_' . time();
            break;
        }
    }

    // -------------------------------------------------------------------
    // Generate a strong random password
    // -------------------------------------------------------------------
    // The user logs in via Google, so they'll never USE this password.
    // But WordPress requires every account to have one, and we should
    // make it strong so no one can brute-force the account directly.
    //
    // wp_generate_password( length, include_special_chars, include_extra_special )
    $random_password = wp_generate_password(32, true, true);

    // -------------------------------------------------------------------
    // Set the display name
    // -------------------------------------------------------------------
    // Use the full name from Google, or fall back to the username.
    $user_display_name = ! empty($display_name) ? $display_name : $username;

    // -------------------------------------------------------------------
    // Create the user with wp_insert_user()
    // -------------------------------------------------------------------
    // wp_insert_user() inserts or updates a user. We use the array form.
    $user_data = array(
        'user_login'   => $username,
        'user_email'   => $email,
        'user_pass'    => $random_password,
        'display_name' => $user_display_name,
        'first_name'   => $first_name,
        'last_name'    => $last_name,
        // Default role: WordPress uses the 'default_role' setting from Settings → General.
        // If you hardcode 'subscriber' here, you override the admin's preference.
        // Let WordPress use its configured default instead.
        'role'         => get_option('default_role', 'subscriber'),
    );

    $user_id = wp_insert_user($user_data);

    if (is_wp_error($user_id)) {
        glwp_log('wp_insert_user failed', $user_id->get_error_message());
        return new WP_Error('user_creation_failed', __('Could not create user account.', 'google-login-wp'));
    }

    // -------------------------------------------------------------------
    // Save Google-specific meta data
    // -------------------------------------------------------------------
    glwp_save_google_user_meta($user_id, $google_id, $avatar_url, $locale);

    // -------------------------------------------------------------------
    // Fire the 'user_register' action
    // -------------------------------------------------------------------
    // WHY? Other plugins (like email confirmation plugins) listen for this
    // hook to send welcome emails, etc. We must fire it manually when
    // creating users programmatically.
    // wp_insert_user fires this automatically, but we confirm it here.
    // Actually wp_insert_user() fires it — so we don't need to. Left as a note.

    return $user_id;
}

/**
 * Saves (or updates) a user's Google-specific meta data.
 *
 * Called both when creating a new user AND when an existing user logs in,
 * to keep their data current.
 *
 * Meta keys are prefixed with 'glwp_' to namespace them to our plugin.
 * This prevents conflicts with other plugins that might use similar keys.
 *
 * @param int    $user_id    WordPress user ID.
 * @param string $google_id  Google unique user ID ('sub').
 * @param string $avatar_url Google profile picture URL.
 * @param string $locale     User's locale string.
 */
function glwp_save_google_user_meta($user_id, $google_id, $avatar_url, $locale)
{
    // update_user_meta() creates the meta if it doesn't exist, updates if it does.
    // It's safer than add_user_meta() for our use case (which would add duplicates).

    // Store Google's unique user ID — our primary lookup key.
    update_user_meta($user_id, 'glwp_google_id', sanitize_text_field($google_id));

    // Store their Google avatar URL — could be used by themes/plugins that display avatars.
    if (! empty($avatar_url)) {
        update_user_meta($user_id, 'glwp_google_avatar', esc_url_raw($avatar_url));
    }

    // Store locale (e.g., 'en', 'fr', 'de').
    if (! empty($locale)) {
        update_user_meta($user_id, 'glwp_google_locale', sanitize_text_field($locale));
    }

    // Store timestamp of last Google login.
    // Useful for analytics, security audits, or "last seen" features.
    update_user_meta($user_id, 'glwp_last_google_login', current_time('mysql'));
    // current_time('mysql') returns: '2024-01-15 14:30:00' in WordPress's timezone.
}
