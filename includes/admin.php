<?php

/**
 * Admin Settings Page
 *
 * This file adds a settings page under Settings → Google Login in wp-admin.
 * It lets the site administrator enter their Google OAuth credentials
 * (Client ID and Client Secret) and toggle auto-registration.
 *
 * WHY a settings page instead of wp-config.php?
 * - Non-technical admins can configure the plugin without editing code files
 * - Settings survive plugin updates (stored in the database, not in the plugin)
 * - We can add validation and save feedback easily
 *
 * @package Google_Login_WP
 */

if (! defined('ABSPATH')) {
    exit;
}

// =============================================================================
// HOOKS
// =============================================================================

// Add our settings page to the WordPress admin menu.
add_action('admin_menu', 'glwp_add_admin_menu');

// Register our settings with WordPress's Settings API.
// The Settings API handles saving form data securely (with nonces, sanitization).
add_action('admin_init', 'glwp_register_settings');

// =============================================================================
// MENU & PAGE REGISTRATION
// =============================================================================

/**
 * Adds a submenu page under "Settings" in wp-admin.
 *
 * Hooked to: admin_menu
 */
function glwp_add_admin_menu()
{
    add_options_page(
        __('Google Login Settings', 'google-login-wp'), // Page title (shown in browser tab)
        __('Google Login', 'google-login-wp'),          // Menu label (shown in the sidebar)
        'manage_options',                                  // Capability required to see this page
        // 'manage_options' = administrators only. Editors and subscribers cannot see it.
        'glwp-settings',                                   // Menu slug (unique ID for this page)
        'glwp_render_settings_page'                        // Function that outputs the page HTML
    );
}

// =============================================================================
// SETTINGS REGISTRATION (WordPress Settings API)
// =============================================================================

/**
 * Registers the settings, sections, and fields with the WordPress Settings API.
 *
 * HOW THE SETTINGS API WORKS:
 * 1. register_setting()    → Tell WordPress: "I have a setting called X, sanitize it with Y"
 * 2. add_settings_section() → Add a visual group/section to the settings page
 * 3. add_settings_field()  → Add an individual form field inside a section
 *
 * WHY use the Settings API instead of a plain HTML form?
 * - WordPress automatically adds a nonce to the form (CSRF protection)
 * - WordPress handles the save request (you don't write POST handling code)
 * - The sanitize callback runs automatically on save
 * - You get settings_errors() notices for free (success/error messages)
 *
 * Hooked to: admin_init
 */
function glwp_register_settings()
{
    // Register the option name — tells WordPress this option exists and
    // how to sanitize it when saved.
    register_setting(
        'glwp_settings_group', // Option group name (used in settings_fields() in the form)
        'glwp_settings',       // Option name (matches get_option('glwp_settings'))
        array(
            'sanitize_callback' => 'glwp_sanitize_settings', // Run this before saving
        )
    );

    // -------------------------------------------------------------------
    // Section: Google OAuth Credentials
    // -------------------------------------------------------------------
    add_settings_section(
        'glwp_credentials_section',          // Section ID
        __('Google OAuth Credentials', 'google-login-wp'), // Section title
        'glwp_render_credentials_section',   // Callback to render description text
        'glwp-settings'                      // Page slug this section appears on
    );

    // Field: Client ID
    add_settings_field(
        'glwp_client_id',                   // Field ID
        __('Client ID', 'google-login-wp'), // Label
        'glwp_render_client_id_field',      // Callback to render the input
        'glwp-settings',                    // Page slug
        'glwp_credentials_section'          // Which section this field goes in
    );

    // Field: Client Secret
    add_settings_field(
        'glwp_client_secret',
        __('Client Secret', 'google-login-wp'),
        'glwp_render_client_secret_field',
        'glwp-settings',
        'glwp_credentials_section'
    );

    // -------------------------------------------------------------------
    // Section: Registration Settings
    // -------------------------------------------------------------------
    add_settings_section(
        'glwp_registration_section',
        __('Registration Settings', 'google-login-wp'),
        'glwp_render_registration_section',
        'glwp-settings'
    );

    // Field: Auto-register new users
    add_settings_field(
        'glwp_auto_register',
        __('Auto-register New Users', 'google-login-wp'),
        'glwp_render_auto_register_field',
        'glwp-settings',
        'glwp_registration_section'
    );
}

/**
 * Sanitizes settings before they are saved to the database.
 *
 * This callback is called automatically by the Settings API when the form is submitted.
 *
 * WHY sanitize here even though we sanitized input elsewhere?
 * Defense in depth. Settings are saved to the database and read on every page load.
 * We want to ensure what's in the database is always clean.
 *
 * @param array $input Raw form input from $_POST.
 * @return array Sanitized settings array.
 */
function glwp_sanitize_settings($input)
{
    $sanitized = array();

    // Client ID: should be alphanumeric with dots and hyphens.
    // sanitize_text_field() removes HTML tags, extra whitespace, invalid UTF-8.
    $sanitized['client_id'] = isset($input['client_id'])
        ? sanitize_text_field(trim($input['client_id']))
        : '';

    // Client Secret: same treatment.
    $sanitized['client_secret'] = isset($input['client_secret'])
        ? sanitize_text_field(trim($input['client_secret']))
        : '';

    // Auto-register: checkbox returns '1' when checked, nothing when unchecked.
    $sanitized['auto_register'] = isset($input['auto_register']) ? '1' : '0';

    return $sanitized;
}

// =============================================================================
// FIELD RENDER CALLBACKS
// =============================================================================

/**
 * Renders a description for the Google OAuth Credentials section.
 */
function glwp_render_credentials_section()
{
?>
    <p>
        <?php
        printf(
            /* translators: %s: Google Cloud Console URL */
            esc_html__('Enter your Google OAuth 2.0 credentials. Get them from the %s.', 'google-login-wp'),
            '<a href="https://console.cloud.google.com/apis/credentials" target="_blank" rel="noopener noreferrer">'
                . esc_html__('Google Cloud Console', 'google-login-wp')
                . '</a>'
        );
        ?>
    </p>
    <p>
        <?php esc_html_e('Required Redirect URI (add this in Google Cloud Console):', 'google-login-wp'); ?>
        <br />
        <code><?php echo esc_html(GLWP_REDIRECT_URI); ?></code>
    </p>
<?php
}

/**
 * Renders the Client ID input field.
 */
function glwp_render_client_id_field()
{
    $settings  = glwp_get_settings();
    $client_id = $settings['client_id'];
?>
    <input
        type="text"
        name="glwp_settings[client_id]"
        id="glwp_client_id"
        value="<?php echo esc_attr($client_id); ?>"
        class="regular-text"
        placeholder="123456789-abc.apps.googleusercontent.com"
        autocomplete="off" />
    <p class="description">
        <?php esc_html_e('Found in Google Cloud Console → APIs & Services → Credentials.', 'google-login-wp'); ?>
    </p>
<?php
    // esc_attr() — escapes a string for use inside an HTML attribute.
    // Prevents: value="<script>alert(1)</script>" from being dangerous.
    // Without it, a malicious value in the database could inject scripts into your admin page.
}

/**
 * Renders the Client Secret input field.
 */
function glwp_render_client_secret_field()
{
    $settings      = glwp_get_settings();
    $client_secret = $settings['client_secret'];
?>
    <input
        type="password"
        name="glwp_settings[client_secret]"
        id="glwp_client_secret"
        value="<?php echo esc_attr($client_secret); ?>"
        class="regular-text"
        autocomplete="new-password" />
    <p class="description">
        <?php esc_html_e('Keep this secret. Never share it publicly or commit it to version control.', 'google-login-wp'); ?>
    </p>
<?php
    // WHY type="password"? So the secret isn't visible on screen over someone's shoulder.
    // WHY autocomplete="new-password"? Prevents browser from offering to save it as a login password.
}

/**
 * Renders the registration description section.
 */
function glwp_render_registration_section()
{
    echo '<p>' . esc_html__('Control what happens when a user logs in with Google but has no existing WordPress account.', 'google-login-wp') . '</p>';
}

/**
 * Renders the auto-register toggle.
 */
function glwp_render_auto_register_field()
{
    $settings        = glwp_get_settings();
    $auto_register   = $settings['auto_register'];
?>
    <label for="glwp_auto_register">
        <input
            type="checkbox"
            name="glwp_settings[auto_register]"
            id="glwp_auto_register"
            value="1"
            <?php checked('1', $auto_register); ?>
            <?php
            // checked( $checked_value, $current_value ) outputs ' checked="checked"'
            // if the values match. WordPress helper — avoids if/else for checked attribute.
            ?> />
        <?php esc_html_e('Automatically create a new WordPress account for first-time Google login users.', 'google-login-wp'); ?>
    </label>
    <p class="description">
        <?php esc_html_e('When disabled, only existing WordPress users can log in with Google.', 'google-login-wp'); ?>
    </p>
<?php
}

// =============================================================================
// SETTINGS PAGE HTML
// =============================================================================

/**
 * Renders the full settings page HTML.
 *
 * This function outputs the complete admin page including the form.
 * It uses WordPress's Settings API to output all registered fields.
 */
function glwp_render_settings_page()
{
    // Check permissions one more time — defense in depth.
    // Even though add_options_page() restricts access, we verify explicitly.
    if (! current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have permission to access this page.', 'google-login-wp'));
    }
?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

        <?php
        // Display any settings errors/success messages saved via add_settings_error().
        // The Settings API calls this after a successful save to show "Settings Saved."
        settings_errors('glwp_settings');
        ?>

        <form method="post" action="options.php">
            <?php
            // settings_fields() outputs:
            // 1. A hidden nonce field (CSRF protection — verifies the form came from your admin)
            // 2. A hidden _wp_http_referer field
            // 3. A hidden action field
            // This is REQUIRED for the Settings API to process your form.
            settings_fields('glwp_settings_group');

            // do_settings_sections() outputs all sections and fields you registered
            // for this page with add_settings_section() and add_settings_field().
            do_settings_sections('glwp-settings');

            // submit_button() outputs the styled "Save Changes" button.
            submit_button(__('Save Settings', 'google-login-wp'));
            ?>
        </form>

        <hr />

        <h2><?php esc_html_e('Connection Status', 'google-login-wp'); ?></h2>
        <?php glwp_render_connection_status(); ?>
    </div>
<?php
}

/**
 * Renders a visual connection status check on the settings page.
 * Helps admins quickly see if the plugin is configured correctly.
 */
function glwp_render_connection_status()
{
    $settings      = glwp_get_settings();
    $has_client_id = ! empty($settings['client_id']);
    $has_secret    = ! empty($settings['client_secret']);

    echo '<table class="widefat" style="max-width:500px;">';
    echo '<tbody>';

    // Check: Client ID configured
    glwp_render_status_row(
        __('Client ID configured', 'google-login-wp'),
        $has_client_id
    );

    // Check: Client Secret configured
    glwp_render_status_row(
        __('Client Secret configured', 'google-login-wp'),
        $has_secret
    );

    // Check: HTTPS (required for production)
    glwp_render_status_row(
        __('HTTPS enabled (required for production)', 'google-login-wp'),
        is_ssl()
    );

    // Show the redirect URI the admin needs to add to Google Console.
    echo '<tr>';
    echo '<td>' . esc_html__('Redirect URI to add in Google Console:', 'google-login-wp') . '</td>';
    echo '<td><code>' . esc_html(GLWP_REDIRECT_URI) . '</code></td>';
    echo '</tr>';

    echo '</tbody>';
    echo '</table>';
}

/**
 * Renders a single status row in the connection status table.
 *
 * @param string $label  Description of what we're checking.
 * @param bool   $status Whether the check passed.
 */
function glwp_render_status_row($label, $status)
{
    $icon  = $status ? '✅' : '❌';
    $class = $status ? 'status-ok' : 'status-error';
    echo '<tr class="' . esc_attr($class) . '">';
    echo '<td>' . esc_html($label) . '</td>';
    echo '<td>' . esc_html($icon) . '</td>';
    echo '</tr>';
}
