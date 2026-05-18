<?php

/**
 * Plugin Name:       Google Login for WordPress
 * Plugin URI:        https://shakoor-wpdev.vercel.app
 * Description:       Adds a secure "Continue with Google" button to the WordPress login page using OAuth 2.0.
 * Version:           1.0.0
 * Author:            Shakoor
 * Author URI:        https://shakoor-wpdev.vercel.app
 * License:           GPL-2.0+
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       google-login-wp
 * Domain Path:       /languages
 *
 * @package Google_Login_WP
 */


// =============================================================================
// SECURITY GATE — THE MOST IMPORTANT LINE IN ANY PLUGIN
// =============================================================================
// ABSPATH is a constant WordPress defines when it loads.
// If someone tries to access this file directly in their browser (by typing
// the URL to this file), ABSPATH won't be defined, so we exit immediately.
// This prevents people from seeing your code or triggering functions directly.
// EVERY plugin file should start with this line.
// =============================================================================
if (! defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

// =============================================================================
// PLUGIN CONSTANTS
// =============================================================================
// Think of constants like labeled boxes that never change.
// We define them ONCE here so every other file can use the label
// instead of repeating the full path/value everywhere.
//
// WHY constants instead of variables?
// - Constants are available everywhere (global scope) without `global $var`
// - Constants cannot be accidentally overwritten
// - They're faster for PHP to look up
// =============================================================================

/** The full filesystem path to this plugin's folder, with trailing slash. */
define('GLWP_PLUGIN_DIR', plugin_dir_path(__FILE__));
// Example value: /var/www/html/wp-content/plugins/google-login-wp/

/** The public URL to this plugin's folder, with trailing slash. */
define('GLWP_PLUGIN_URL', plugin_dir_url(__FILE__));
// Example value: https://yoursite.com/wp-content/plugins/google-login-wp/

/** Plugin version. Used for cache-busting CSS/JS files. */
define('GLWP_VERSION', '1.0.0');

/** The URL that Google will redirect the user back to after login. */
// wp_login_url() returns the full URL to wp-login.php on your site.
// We append our custom query parameter so we know it's an OAuth callback.
define('GLWP_REDIRECT_URI', wp_login_url() . '?glwp_action=google_callback');

/** Google's OAuth 2.0 endpoints (these never change, but naming them is good practice). */
define('GLWP_GOOGLE_AUTH_URL', 'https://accounts.google.com/o/oauth2/v2/auth');
define('GLWP_GOOGLE_TOKEN_URL', 'https://oauth2.googleapis.com/token');
define('GLWP_GOOGLE_USERINFO_URL', 'https://www.googleapis.com/oauth2/v3/userinfo');

// =============================================================================
// LOAD PLUGIN FILES
// =============================================================================
// require_once loads a file exactly once — if something else already loaded it,
// PHP won't load it again. This prevents "function already defined" errors.
//
// We load in dependency order:
// 1. functions.php  — helpers everything else uses
// 2. oauth.php      — builds OAuth URLs
// 3. callback.php   — handles Google's response
// 4. user.php       — creates/finds WordPress users
// 5. admin.php      — settings page (only needed in admin area)
// =============================================================================

require_once GLWP_PLUGIN_DIR . 'includes/functions.php';
require_once GLWP_PLUGIN_DIR . 'includes/oauth.php';
require_once GLWP_PLUGIN_DIR . 'includes/callback.php';
require_once GLWP_PLUGIN_DIR . 'includes/user.php';

// Only load admin file when in the WordPress admin dashboard.
// WHY? No reason to load admin code on the public-facing site.
// This is a small but meaningful performance optimization.
if (is_admin()) {
    require_once GLWP_PLUGIN_DIR . 'includes/admin.php';
}

// =============================================================================
// HOOK: Render Google Login Button on the Login Form
// =============================================================================
// 'login_form' is fired by WordPress inside wp-login.php, right after
// the standard username/password fields are rendered.
// Our function will run at that moment and output the Google button HTML.
//
// Priority 10 is default — we don't need to go earlier or later.
// =============================================================================
add_action('login_form', 'glwp_render_login_button');

// =============================================================================
// HOOK: Enqueue CSS for the Login Page
// =============================================================================
// 'login_enqueue_scripts' is the correct hook to add CSS/JS to wp-login.php.
// DO NOT use 'wp_enqueue_scripts' for the login page — that hook does not
// fire on wp-login.php. This is a very common beginner mistake.
// =============================================================================
add_action('login_enqueue_scripts', 'glwp_enqueue_login_assets');

// =============================================================================
// HOOK: Intercept OAuth Actions (Login Start + Callback)
// =============================================================================
// 'init' fires very early in every WordPress page load, after WordPress is
// set up but before any HTML is sent to the browser.
//
// WHY 'init' and not something more specific?
// Because our callback URL IS wp-login.php — WordPress doesn't have a special
// hook for "someone visited wp-login.php with these parameters". The 'init'
// hook fires on every request including wp-login.php, so we check the URL
// ourselves and act only when our parameter is present.
//
// Priority 1 means we run EARLY — before most other things — so we can
// redirect the user before WordPress outputs any login page HTML.
// =============================================================================
add_action('init', 'glwp_handle_oauth_actions', 1);

// =============================================================================
// HOOK: Login Redirect
// =============================================================================
// After a successful login, WordPress calls this filter to decide where to
// send the user. We hook in to ensure our Google-logged-in users go to the
// right place (dashboard by default, or wherever was intended).
// =============================================================================
add_filter('login_redirect', 'glwp_handle_login_redirect', 10, 3);

// =============================================================================
// ACTIVATION / DEACTIVATION HOOKS
// =============================================================================
// These run ONCE when the plugin is activated or deactivated from wp-admin.
// We use them to set default options and clean up after ourselves.
// =============================================================================
register_activation_hook(__FILE__, 'glwp_activate');
register_deactivation_hook(__FILE__, 'glwp_deactivate');

/**
 * Runs once when plugin is activated.
 *
 * Sets default option values so the plugin doesn't error if settings
 * haven't been configured yet.
 */
function glwp_activate()
{
    // add_option only adds if the option doesn't already exist.
    // This means re-activating the plugin won't wipe existing settings.
    $defaults = array(
        'client_id'     => '',
        'client_secret' => '',
        'auto_register' => '1', // '1' = enabled by default
    );
    add_option('glwp_settings', $defaults);
}

/**
 * Runs once when plugin is deactivated (NOT uninstalled).
 *
 * We do NOT delete options here — the user might just be temporarily
 * deactivating the plugin. Options are deleted on uninstall instead.
 * (That would be handled in an uninstall.php file.)
 */
function glwp_deactivate()
{
    // Nothing to do on deactivate.
    // Intentionally left empty — see docblock above.
}

// =============================================================================
// CALLBACK FUNCTIONS
// =============================================================================
// These functions are called by the hooks above.
// They're defined here (in the main file) because they're short "dispatcher"
// functions — they just decide what to do and call functions from other files.
// =============================================================================

/**
 * Renders the "Continue with Google" button on the login form.
 *
 * Hooked to: login_form
 */
function glwp_render_login_button()
{
    // First, check that the plugin has been configured with credentials.
    // No point showing a button that won't work.
    $settings = glwp_get_settings();
    if (empty($settings['client_id'])) {
        // Don't show the button if there's no Client ID configured.
        return;
    }

    // Build the URL that starts the OAuth flow.
    // This function is defined in includes/oauth.php
    $google_auth_url = glwp_build_auth_url();
    if (is_wp_error($google_auth_url)) {
        // Something went wrong building the URL — fail silently on frontend.
        return;
    }

    // esc_url() sanitizes and escapes a URL for safe output in HTML.
    // NEVER output a URL directly — always escape it first.
    // If $google_auth_url contained javascript:alert('xss') this would neutralize it.
    $escaped_url = esc_url($google_auth_url);

    // Output the button HTML.
    // Note: we're outputting HTML here so we use proper escaping.
    // The URL is already escaped above.
?>
    <div class="glwp-login-separator">
        <span><?php esc_html_e('or', 'google-login-wp'); ?></span>
    </div>

    <div class="glwp-google-btn-wrap">
        <a href="<?php echo $escaped_url; ?>" class="glwp-google-btn" id="glwp-google-login-btn">
            <span class="glwp-google-icon" aria-hidden="true">
                <?php
                // Inline SVG for Google's "G" logo.
                // WHY inline? No extra HTTP request. No broken image if CDN is down.
                // aria-hidden="true" hides it from screen readers (the text label is enough).
                echo glwp_get_google_icon_svg(); // Safe — function returns hardcoded SVG, no user input.
                ?>
            </span>
            <span class="glwp-google-btn-text">
                <?php esc_html_e('Continue with Google', 'google-login-wp'); ?>
            </span>
        </a>
    </div>
<?php
}

/**
 * Enqueues the plugin's CSS file on the login page.
 *
 * Hooked to: login_enqueue_scripts
 */
function glwp_enqueue_login_assets()
{
    wp_enqueue_style(
        'glwp-google-button',                              // Handle (unique ID for this stylesheet)
        GLWP_PLUGIN_URL . 'assets/css/google-button.css', // URL to the file
        array(),                                           // Dependencies (none)
        GLWP_VERSION                                       // Version — appended as ?ver=1.0.0 for cache busting
    );
}

/**
 * Intercepts OAuth-related URL parameters early in the WordPress boot process.
 *
 * Hooked to: init (priority 1)
 *
 * This is our "traffic controller" — it checks the URL and routes to the
 * correct handler function.
 */
function glwp_handle_oauth_actions()
{
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    // Note: We check the 'glwp_action' parameter from $_GET.
    // Nonce verification doesn't apply here because this is an OAuth flow —
    // the 'state' parameter serves the same anti-CSRF purpose as a nonce.

    if (! isset($_GET['glwp_action'])) {
        // Not our URL — do nothing and let WordPress continue normally.
        return;
    }

    $action = sanitize_key($_GET['glwp_action']);
    // sanitize_key() lowercases and removes anything that's not a letter,
    // number, underscore, or hyphen. So 'google_callback' stays 'google_callback',
    // but '<script>alert(1)</script>' becomes empty string. Safe.

    if ('google_login' === $action) {
        // User clicked the button — redirect them to Google.
        // Defined in includes/oauth.php
        glwp_redirect_to_google();
    } elseif ('google_callback' === $action) {
        // Google redirected the user back to us with a code.
        // Defined in includes/callback.php
        glwp_handle_google_callback();
    }
}

/**
 * Handles where the user is redirected after a successful login.
 *
 * Hooked to: login_redirect (filter)
 *
 * WordPress passes three arguments:
 * @param string  $redirect_to The URL to redirect to (what WordPress chose).
 * @param string  $requested   The redirect URL that was requested (from the form).
 * @param WP_User $user        The logged-in user object.
 * @return string The URL to redirect to.
 */
function glwp_handle_login_redirect($redirect_to, $requested, $user)
{
    // If the user object has an error, return the default redirect.
    // This prevents fatal errors if login failed.
    if (is_wp_error($user)) {
        return $redirect_to;
    }

    // If a specific redirect was requested (e.g., user was trying to access
    // a page before being asked to log in), honour that.
    if (! empty($requested) && $requested !== wp_login_url()) {
        return $requested;
    }

    // Default: administrators go to the dashboard, others go to home.
    if ($user instanceof WP_User && $user->has_cap('manage_options')) {
        return admin_url();
    }

    return home_url();
}
