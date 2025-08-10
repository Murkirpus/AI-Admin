<?php
/**
 * AI Security Analyzer - Система анализа системных логов безопасности с ИИ
 * Автоматическое выявление угроз в UFW, kernel и system логах
 * Версия: 3.0 - Security Focus Edition
 * Поддержка: MariaDB/MySQL, множественные AI модели
 */

// Отключаем отображение ошибок в production
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('memory_limit', '512M');
ini_set('max_execution_time', 120);

// Запуск сессии для сохранения выбранной модели
session_start();

// Конфигурация базы данных MariaDB
$db_config = [
    'host' => 'localhost',
    'dbname' => 'ai_security',
    'username' => 'ai_security',
    'password' => 'ai_security', // Укажите ваш пароль
    'charset' => 'utf8mb4'
];

// Основная конфигурация системы безопасности
$config = [
    'openrouter_api_key' => 'sk-or-v1-',
    'log_paths' => [
        '/var/log/ufw.log',      // UFW Firewall логи
        '/var/log/kern.log',     // Kernel логи
        '/var/log/syslog',       // Системные логи
        '/var/log/auth.log',     // Аутентификация (если доступен)
        //'/var/log/fail2ban.log', // Fail2ban (если установлен)
    ],
    'analysis_interval' => 600, // 10 минут
    'threat_threshold' => [
        'failed_ssh_attempts' => 5,      // Неудачных SSH попыток
        'port_scan_threshold' => 10,     // Сканирований портов
        'blocked_attempts_hour' => 20,   // UFW блокировок в час
        'kernel_errors_threshold' => 15, // Критических ошибок ядра
        'unique_attack_ips' => 3,        // Уникальных атакующих IP
        'ddos_requests_threshold' => 100 // Подозрение на DDoS
    ],
    'default_ai_model' => 'qwen/qwen-2.5-72b-instruct:free',
    'block_duration' => 7200, // 2 часа
    'max_log_lines' => 5000    // Максимум строк лога для анализа
];

// Функция получения доступных AI моделей (та же что и раньше)
function getOpenRouterModels() {
    return [
        // 🆓 БЕСПЛАТНЫЕ МОДЕЛИ
        'qwen/qwen-2.5-72b-instruct:free' => [
            'name' => '🆓 Qwen 2.5 72B Instruct',
            'description' => 'Мощная бесплатная модель от Alibaba для анализа безопасности',
            'price' => 'БЕСПЛАТНО',
            'cost_1000' => '$0.00',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'free'
        ],
        
        'meta-llama/llama-3.3-70b-instruct:free' => [
            'name' => '🆓 Llama 3.3 70B Instruct',
            'description' => 'Отличная бесплатная модель от Meta для кибербезопасности',
            'price' => 'БЕСПЛАТНО',
            'cost_1000' => '$0.00',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'free'
        ],
        
        'deepseek/deepseek-r1:free' => [
            'name' => '🆓 DeepSeek R1',
            'description' => 'Новейшая бесплатная модель с продвинутыми рассуждениями',
            'price' => 'БЕСПЛАТНО',
            'cost_1000' => '$0.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'free'
        ],

        // 💰 БЮДЖЕТНЫЕ МОДЕЛИ
        'deepseek/deepseek-chat' => [
            'name' => '💰 DeepSeek Chat',
            'description' => 'Отличное качество анализа по низкой цене',
            'price' => '$0.14 / $0.28 за 1М токенов',
            'cost_1000' => '$0.42',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'budget'
        ],
        
        'google/gemini-2.5-flash' => [
            'name' => '💰 Gemini 2.5 Flash',
            'description' => 'СУПЕР ПОПУЛЯРНАЯ! Топ модель для анализа безопасности',
            'price' => '$0.075 / $0.30 за 1М токенов',
            'cost_1000' => '$0.375',
            'speed' => '⚡⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'budget'
        ],

        // 🥇 ПРЕМИУМ МОДЕЛИ
        'google/gemini-2.5-pro' => [
            'name' => '🥇 Gemini 2.5 Pro',
            'description' => 'Топовая модель Google для глубокого анализа угроз',
            'price' => '$1.25 / $5.00 за 1М токенов',
            'cost_1000' => '$6.25',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'premium'
        ],
        
        'openai/gpt-4o-mini' => [
            'name' => '🥇 GPT-4o Mini',
            'description' => 'Быстрая и качественная модель для security анализа',
            'price' => '$0.15 / $0.60 за 1М токенов',
            'cost_1000' => '$0.75',
            'speed' => '⚡⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'premium'
        ],
        
        'anthropic/claude-3.5-sonnet' => [
            'name' => '🥇 Claude 3.5 Sonnet',
            'description' => 'Топовая модель от Anthropic для анализа кибератак',
            'price' => '$3.00 / $15.00 за 1М токенов',
            'cost_1000' => '$18.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'premium'
        ],

        // 🚀 НОВЕЙШИЕ И СПЕЦИАЛИЗИРОВАННЫЕ МОДЕЛИ
        'deepseek/deepseek-r1' => [
            'name' => '🚀 DeepSeek R1',
            'description' => 'Революционная модель с рассуждениями для анализа угроз',
            'price' => '$0.55 / $2.19 за 1М токенов',
            'cost_1000' => '$2.74',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'newest'
        ],
        
        'x-ai/grok-3' => [
            'name' => '🚀 Grok 3.0',
            'description' => 'Мощная модель xAI для кибербезопасности',
            'price' => '$2.50 / $12.50 за 1М токенов',
            'cost_1000' => '$15.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'newest'
        ],
        
        'anthropic/claude-sonnet-4' => [
            'name' => '🚀 Claude Sonnet 4',
            'description' => 'Новейшая Claude 4 для продвинутого анализа безопасности',
            'price' => '$5.00 / $25.00 за 1М токенов',
            'cost_1000' => '$30.00',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'newest'
        ]
    ];
}

// Получение текущей выбранной модели
function getCurrentAIModel($config) {
    if (isset($_POST['ai_model'])) {
        $_SESSION['selected_ai_model'] = $_POST['ai_model'];
        return $_POST['ai_model'];
    }
    
    if (isset($_SESSION['selected_ai_model'])) {
        return $_SESSION['selected_ai_model'];
    }
    
    return $config['default_ai_model'];
}

// Подключение к базе данных MariaDB
try {
    $dsn = "mysql:host={$db_config['host']};dbname={$db_config['dbname']};charset={$db_config['charset']}";
    $pdo = new PDO($dsn, $db_config['username'], $db_config['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
    ]);
    
    // Создаем таблицы для анализа безопасности
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS security_analysis (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            analysis_data LONGTEXT,
            ai_decision LONGTEXT,
            threat_level TINYINT,
            security_events_count INT DEFAULT 0,
            blocked_ips_count INT DEFAULT 0,
            actions_taken TEXT,
            status ENUM('pending', 'processed', 'failed') DEFAULT 'pending',
            processing_time_ms INT,
            ai_model VARCHAR(255),
            INDEX idx_timestamp (timestamp),
            INDEX idx_threat_level (threat_level),
            INDEX idx_ai_model (ai_model)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS security_threats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45),
            threat_type VARCHAR(255) DEFAULT 'unknown',
            threat_score TINYINT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            event_count INT DEFAULT 1,
            details JSON,
            source_logs TEXT,
            status ENUM('active', 'monitoring', 'resolved', 'false_positive') DEFAULT 'active',
            INDEX idx_ip_address (ip_address),
            INDEX idx_threat_type (threat_type),
            INDEX idx_threat_score (threat_score),
            INDEX idx_last_seen (last_seen)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    
    // Обновляем существующую таблицу если она уже создана с ENUM
    try {
        $pdo->exec("ALTER TABLE security_threats MODIFY COLUMN threat_type VARCHAR(255) DEFAULT 'unknown'");
    } catch (PDOException $e) {
        // Игнорируем ошибку если колонка уже правильного типа
    }
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS blocked_security_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) UNIQUE,
            threat_type VARCHAR(100),
            reason TEXT,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NULL,
            status ENUM('active', 'expired', 'removed') DEFAULT 'active',
            block_method ENUM('iptables', 'ufw', 'fail2ban', 'database') DEFAULT 'database',
            severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
            INDEX idx_ip_status (ip_address, status),
            INDEX idx_blocked_at (blocked_at),
            INDEX idx_severity (severity)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS security_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            event_time TIMESTAMP,
            event_type VARCHAR(100),
            source_ip VARCHAR(45),
            target_port INT NULL,
            protocol VARCHAR(10) NULL,
            action VARCHAR(50),
            message TEXT,
            log_source ENUM('ufw', 'kernel', 'syslog', 'auth', 'fail2ban') NOT NULL,
            severity TINYINT DEFAULT 1,
            processed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_event_time (event_time),
            INDEX idx_source_ip (source_ip),
            INDEX idx_event_type (event_type),
            INDEX idx_log_source (log_source),
            INDEX idx_processed (processed)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    
    // Обновляем существующие таблицы если они уже созданы
    try {
        $pdo->exec("ALTER TABLE security_events MODIFY COLUMN event_type VARCHAR(100)");
        $pdo->exec("ALTER TABLE security_events MODIFY COLUMN protocol VARCHAR(10)");
        $pdo->exec("ALTER TABLE security_events MODIFY COLUMN action VARCHAR(50)");
    } catch (PDOException $e) {
        // Игнорируем ошибки если колонки уже правильного типа
    }
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS ai_security_decisions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            analysis_id INT,
            decision_type ENUM('block', 'monitor', 'alert', 'ignore'),
            confidence_score TINYINT,
            ai_reasoning TEXT,
            security_recommendations JSON,
            executed_actions JSON,
            processing_time_ms INT,
            ai_model VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (analysis_id) REFERENCES security_analysis(id) ON DELETE CASCADE,
            INDEX idx_decision_type (decision_type),
            INDEX idx_created_at (created_at),
            INDEX idx_ai_model (ai_model)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    
} catch (PDOException $e) {
    die("Ошибка подключения к MariaDB: " . $e->getMessage());
}

// Класс анализатора логов безопасности с ИИ
class AISecurityAnalyzer {
    private $config;
    private $pdo;
    
    public function __construct($config, $pdo) {
        $this->config = $config;
        $this->pdo = $pdo;
    }
    
    // Основная функция анализа логов безопасности
    public function analyzeSecurityLogs($selectedModel = null) {
        $startTime = microtime(true);
        $aiModel = $selectedModel ?: getCurrentAIModel($this->config);
        
        try {
            $securityEvents = $this->parseSecurityLogs();
            
            // Проверяем, есть ли доступные логи
            if (empty($securityEvents['log_sources'])) {
                throw new Exception("Нет доступных логов безопасности для анализа. Проверьте права доступа к файлам логов.");
            }
            
            // Проверяем, есть ли события для анализа
            if ($securityEvents['total_events'] == 0 && $securityEvents['total_processed'] == 0) {
                // Если нет событий, создаем минимальный отчет
                $emptyAnalysis = [
                    'threats' => [],
                    'threat_level' => 0,
                    'total_events' => 0,
                    'total_processed' => 0,
                    'analysis_time' => date('Y-m-d H:i:s'),
                    'period_minutes' => $this->config['analysis_interval'] / 60,
                    'log_sources' => $securityEvents['log_sources'],
                    'unique_ips' => 0
                ];
                
                $aiDecision = [
                    'decision' => 'ignore',
                    'confidence' => 95,
                    'reason' => 'В системных логах за последние ' . ($this->config['analysis_interval'] / 60) . ' минут не обнаружено событий безопасности.',
                    'security_recommendations' => ['Продолжить мониторинг системы', 'Логи доступны: ' . implode(', ', $securityEvents['log_sources'])]
                ];
                
                $processingTime = round((microtime(true) - $startTime) * 1000);
                $analysisId = $this->saveSecurityAnalysis($emptyAnalysis, $aiDecision, $aiModel);
                
                $this->pdo->prepare("UPDATE security_analysis SET processing_time_ms = ?, ai_model = ? WHERE id = ?")
                          ->execute([$processingTime, $aiModel, $analysisId]);
                
                return [
                    'analysis_id' => $analysisId,
                    'ai_decision' => $aiDecision,
                    'actions_taken' => ['✅ Анализ завершен - события безопасности не обнаружены'],
                    'blocked_ips_count' => 0,
                    'timestamp' => date('Y-m-d H:i:s'),
                    'threat_count' => 0,
                    'ai_model_used' => $aiModel
                ];
            }
            
            $threatAnalysis = $this->analyzeThreatPatterns($securityEvents);
            $aiDecision = $this->consultSecurityAI($threatAnalysis, $aiModel);
            $executionResult = $this->executeSecurityDecision($threatAnalysis, $aiDecision, $aiModel);
            
            $processingTime = round((microtime(true) - $startTime) * 1000);
            
            // Обновляем время обработки
            $this->pdo->prepare("UPDATE security_analysis SET processing_time_ms = ?, ai_model = ? WHERE id = ?")
                      ->execute([$processingTime, $aiModel, $executionResult['analysis_id']]);
            
            $this->updateSecurityStats($threatAnalysis, $processingTime, $aiModel);
            
            return array_merge($executionResult, ['ai_model_used' => $aiModel]);
            
        } catch (Exception $e) {
            error_log("AI Security Analyzer Error: " . $e->getMessage());
            throw $e;
        }
    }
    
    // Парсинг логов безопасности
    private function parseSecurityLogs() {
        $currentTime = time();
        $startTime = $currentTime - $this->config['analysis_interval'];
        
        $securityEvents = [];
        $ipStats = [];
        $threatPatterns = [];
        $totalProcessed = 0;
        $availableLogs = [];
        
        foreach ($this->config['log_paths'] as $logPath) {
            if (!file_exists($logPath)) {
                error_log("AI Security: Log file not found: $logPath");
                continue;
            }
            
            if (!is_readable($logPath)) {
                error_log("AI Security: Log file not readable: $logPath");
                continue;
            }
            
            try {
                $logType = $this->getLogType($logPath);
                $lines = $this->tailFile($logPath, $this->config['max_log_lines']);
                $availableLogs[] = basename($logPath);
                
                if (empty($lines)) {
                    error_log("AI Security: No lines read from: $logPath");
                    continue;
                }
                
                foreach ($lines as $line) {
                    if (empty(trim($line))) continue;
                    
                    try {
                        $event = $this->parseSecurityLogLine($line, $logType);
                        if (!$event) continue;
                        
                        $totalProcessed++;
                        
                        // Фильтруем по времени
                        if ($event['timestamp'] && $event['timestamp'] < $startTime) {
                            continue;
                        }
                        
                        $securityEvents[] = $event;
                        
                        // Сохраняем событие в БД
                        $this->saveSecurityEvent($event);
                        
                        // Анализируем IP активность
                        if ($event['source_ip']) {
                            $ip = $event['source_ip'];
                            if (!isset($ipStats[$ip])) {
                                $ipStats[$ip] = [
                                    'events' => 0,
                                    'event_types' => [],
                                    'ports_scanned' => [],
                                    'failed_attempts' => 0,
                                    'blocked_attempts' => 0,
                                    'severity_sum' => 0,
                                    'first_seen' => $event['timestamp'],
                                    'last_seen' => $event['timestamp']
                                ];
                            }
                            
                            $ipStats[$ip]['events']++;
                            $ipStats[$ip]['event_types'][] = $event['event_type'];
                            $ipStats[$ip]['severity_sum'] += $event['severity'];
                            $ipStats[$ip]['last_seen'] = max($ipStats[$ip]['last_seen'], $event['timestamp']);
                            
                            if (isset($event['target_port']) && $event['target_port']) {
                                $ipStats[$ip]['ports_scanned'][] = $event['target_port'];
                            }
                            
                            if (strpos($event['action'], 'BLOCK') !== false || 
                                strpos($event['action'], 'DROP') !== false) {
                                $ipStats[$ip]['blocked_attempts']++;
                            }
                            
                            if (strpos($event['event_type'], 'failed') !== false || 
                                strpos($event['message'], 'authentication failure') !== false) {
                                $ipStats[$ip]['failed_attempts']++;
                            }
                        }
                        
                        // Обнаружение паттернов угроз
                        $this->detectSecurityThreats($event, $threatPatterns);
                        
                    } catch (Exception $e) {
                        error_log("AI Security: Error parsing line from $logPath: " . $e->getMessage());
                        continue;
                    }
                }
            } catch (Exception $e) {
                error_log("AI Security: Error processing log file $logPath: " . $e->getMessage());
                continue;
            }
        }
        
        return [
            'total_events' => count($securityEvents),
            'total_processed' => $totalProcessed,
            'ip_statistics' => $ipStats,
            'threat_patterns' => $threatPatterns,
            'analysis_period' => $this->config['analysis_interval'],
            'timestamp' => $currentTime,
            'log_sources' => $availableLogs,
            'unique_ips' => count($ipStats)
        ];
    }
    
    // Определение типа лога по пути
    private function getLogType($logPath) {
        $basename = basename($logPath);
        if (strpos($basename, 'ufw') !== false) return 'ufw';
        if (strpos($basename, 'kern') !== false) return 'kernel';
        if (strpos($basename, 'auth') !== false) return 'auth';
        if (strpos($basename, 'fail2ban') !== false) return 'fail2ban';
        return 'syslog';
    }
    
    // Чтение последних строк файла (та же функция)
    private function tailFile($file, $lines) {
        $handle = fopen($file, 'r');
        if (!$handle) return [];
        
        $linecounter = $lines;
        $pos = -2;
        $beginning = false;
        $text = [];
        
        while ($linecounter > 0) {
            $t = ' ';
            while ($t != "\n") {
                if (fseek($handle, $pos, SEEK_END) == -1) {
                    $beginning = true;
                    break;
                }
                $t = fgetc($handle);
                $pos--;
            }
            $linecounter--;
            if ($beginning) {
                rewind($handle);
            }
            $text[$lines-$linecounter-1] = fgets($handle);
            if ($beginning) break;
        }
        fclose($handle);
        
        return array_reverse(array_filter($text));
    }
    
    // Парсинг строки лога безопасности
    private function parseSecurityLogLine($line, $logType) {
        $line = trim($line);
        if (empty($line)) return false;
        
        $event = [
            'timestamp' => null,
            'event_type' => 'unknown',
            'source_ip' => null,
            'target_port' => null,
            'protocol' => null,
            'action' => 'unknown',
            'message' => $line,
            'log_source' => $logType,
            'severity' => 1
        ];
        
        // Парсинг временной метки (стандартный syslog формат)
        if (preg_match('/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/', $line, $matches)) {
            $dateStr = date('Y') . ' ' . $matches[1];
            $event['timestamp'] = strtotime($dateStr);
        }
        
        switch ($logType) {
            case 'ufw':
                return $this->parseUFWLog($line, $event);
            case 'kernel':
                return $this->parseKernelLog($line, $event);
            case 'auth':
                return $this->parseAuthLog($line, $event);
            case 'fail2ban':
                return $this->parseFail2banLog($line, $event);
            default:
                return $this->parseSyslog($line, $event);
        }
    }
    
    // Парсинг UFW логов
    private function parseUFWLog($line, $event) {
        // UFW формат: kernel: [timestamp] [UFW BLOCK/ALLOW] IN=eth0 OUT= MAC=... SRC=x.x.x.x DST=y.y.y.y LEN=... PROTO=TCP SPT=... DPT=...
        if (preg_match('/\[UFW\s+(BLOCK|ALLOW)\].*?SRC=(\d+\.\d+\.\d+\.\d+).*?DPT=(\d+).*?PROTO=(\w+)/i', $line, $matches)) {
            $event['action'] = $matches[1];
            $event['source_ip'] = $matches[2];
            $event['target_port'] = intval($matches[3]);
            $event['protocol'] = strtolower($matches[4]);
            $event['event_type'] = $matches[1] === 'BLOCK' ? 'firewall_block' : 'firewall_allow';
            $event['severity'] = $matches[1] === 'BLOCK' ? 3 : 1;
            
            // Определяем тип атаки
            $port = $event['target_port'];
            if (in_array($port, [22, 23, 3389])) {
                $event['event_type'] = 'remote_access_attempt';
                $event['severity'] = 4;
            } elseif (in_array($port, [80, 443, 8080, 8443])) {
                $event['event_type'] = 'web_service_probe';
                $event['severity'] = 2;
            } elseif (in_array($port, [21, 25, 53, 110, 143, 993, 995])) {
                $event['event_type'] = 'service_scan';
                $event['severity'] = 3;
            }
            
            return $event;
        }
        
        return false;
    }
    
    // Парсинг kernel логов
    private function parseKernelLog($line, $event) {
        $event['log_source'] = 'kernel';
        
        // Поиск IP адресов в kernel логах
        if (preg_match('/(\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
            $event['source_ip'] = $matches[1];
        }
        
        // Критические события безопасности
        if (preg_match('/(segfault|killed|protection|violation|denied|blocked)/i', $line)) {
            $event['event_type'] = 'kernel_security_event';
            $event['severity'] = 4;
        }
        
        // Out of memory attacks
        if (preg_match('/Out of memory|oom_kill_process/i', $line)) {
            $event['event_type'] = 'resource_exhaustion';
            $event['severity'] = 5;
        }
        
        // Подозрительные процессы
        if (preg_match('/(suspicious|malicious|backdoor|rootkit)/i', $line)) {
            $event['event_type'] = 'malware_detection';
            $event['severity'] = 5;
        }
        
        return $event;
    }
    
    // Парсинг auth логов
    private function parseAuthLog($line, $event) {
        $event['log_source'] = 'auth';
        
        // SSH неудачные попытки
        if (preg_match('/Failed password.*?from (\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
            $event['event_type'] = 'ssh_failed_login';
            $event['source_ip'] = $matches[1];
            $event['target_port'] = 22;
            $event['severity'] = 3;
        }
        
        // SSH успешные входы
        if (preg_match('/Accepted.*?from (\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
            $event['event_type'] = 'ssh_successful_login';
            $event['source_ip'] = $matches[1];
            $event['target_port'] = 22;
            $event['severity'] = 1;
        }
        
        // Недействительные пользователи
        if (preg_match('/Invalid user.*?from (\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
            $event['event_type'] = 'ssh_invalid_user';
            $event['source_ip'] = $matches[1];
            $event['target_port'] = 22;
            $event['severity'] = 4;
        }
        
        // sudo события
        if (preg_match('/sudo.*?COMMAND=(.*)/', $line, $matches)) {
            $event['event_type'] = 'sudo_command';
            $event['severity'] = 2;
            $event['message'] = 'Sudo command: ' . $matches[1];
        }
        
        return $event;
    }
    
    // Парсинг Fail2ban логов
    private function parseFail2banLog($line, $event) {
        $event['log_source'] = 'fail2ban';
        
        // Fail2ban блокировки
        if (preg_match('/Ban (\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
            $event['event_type'] = 'fail2ban_ban';
            $event['source_ip'] = $matches[1];
            $event['action'] = 'BAN';
            $event['severity'] = 4;
        }
        
        // Fail2ban разблокировки
        if (preg_match('/Unban (\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
            $event['event_type'] = 'fail2ban_unban';
            $event['source_ip'] = $matches[1];
            $event['action'] = 'UNBAN';
            $event['severity'] = 1;
        }
        
        return $event;
    }
    
    // Парсинг общих системных логов
    private function parseSyslog($line, $event) {
        // Поиск IP адресов
        if (preg_match('/(\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
            $event['source_ip'] = $matches[1];
        }
        
        // Определение типов событий
        if (preg_match('/(error|critical|emergency|alert)/i', $line)) {
            $event['event_type'] = 'system_error';
            $event['severity'] = 3;
        }
        
        if (preg_match('/(attack|intrusion|breach|compromise)/i', $line)) {
            $event['event_type'] = 'security_incident';
            $event['severity'] = 5;
        }
        
        return $event;
    }
    
    // Сохранение события безопасности в БД
    private function saveSecurityEvent($event) {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO security_events (event_time, event_type, source_ip, target_port, protocol, action, message, log_source, severity) 
                VALUES (FROM_UNIXTIME(?), ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $event['timestamp'] ?: time(),
                substr($event['event_type'], 0, 100), // Ограничиваем длину
                $event['source_ip'],
                $event['target_port'],
                $event['protocol'] ? substr($event['protocol'], 0, 10) : null, // Ограничиваем длину
                $event['action'] ? substr($event['action'], 0, 50) : null, // Ограничиваем длину
                substr($event['message'], 0, 1000), // Ограничиваем длину сообщения
                $event['log_source'],
                $event['severity']
            ]);
        } catch (PDOException $e) {
            error_log("AI Security: Failed to save security event: " . $e->getMessage());
            // Не прерываем выполнение, просто логируем ошибку
        }
    }
    
    // Обнаружение паттернов угроз
    private function detectSecurityThreats($event, &$threatPatterns) {
        if (!$event['source_ip']) return;
        
        $ip = $event['source_ip'];
        
        // SSH брутфорс
        if ($event['event_type'] === 'ssh_failed_login') {
            if (!isset($threatPatterns[$ip]['ssh_bruteforce'])) {
                $threatPatterns[$ip]['ssh_bruteforce'] = 0;
            }
            $threatPatterns[$ip]['ssh_bruteforce']++;
        }
        
        // Сканирование портов
        if ($event['event_type'] === 'firewall_block' && $event['target_port']) {
            if (!isset($threatPatterns[$ip]['port_scan'])) {
                $threatPatterns[$ip]['port_scan'] = [];
            }
            $threatPatterns[$ip]['port_scan'][] = $event['target_port'];
        }
        
        // DDoS подозрения
        if ($event['severity'] >= 3) {
            if (!isset($threatPatterns[$ip]['high_severity_events'])) {
                $threatPatterns[$ip]['high_severity_events'] = 0;
            }
            $threatPatterns[$ip]['high_severity_events']++;
        }
        
        // Malware/intrusion
        if ($event['event_type'] === 'malware_detection' || $event['event_type'] === 'security_incident') {
            $threatPatterns[$ip]['malware_detected'] = true;
        }
    }
    
    // Анализ паттернов угроз
    private function analyzeThreatPatterns($securityEvents) {
        $threats = [];
        $threatLevel = 0;
        
        foreach ($securityEvents['ip_statistics'] as $ip => $stats) {
            $threat = [
                'ip' => $ip,
                'threat_score' => 0,
                'threat_types' => [],
                'reasons' => [],
                'stats' => $stats,
                'risk_factors' => [],
                'severity' => 'low'
            ];
            
            // Анализ SSH брутфорса
            if ($stats['failed_attempts'] >= $this->config['threat_threshold']['failed_ssh_attempts']) {
                $threat['threat_score'] += 60;
                $threat['threat_types'][] = 'ssh_bruteforce';
                $threat['reasons'][] = "SSH брутфорс: {$stats['failed_attempts']} неудачных попыток";
                $threat['risk_factors'][] = 'ssh_bruteforce';
            }
            
            // Анализ сканирования портов
            $uniquePorts = array_unique($stats['ports_scanned']);
            if (count($uniquePorts) >= $this->config['threat_threshold']['port_scan_threshold']) {
                $threat['threat_score'] += 40;
                $threat['threat_types'][] = 'port_scan';
                $threat['reasons'][] = "Сканирование портов: " . count($uniquePorts) . " уникальных портов";
                $threat['risk_factors'][] = 'port_scanning';
            }
            
            // Анализ блокировок UFW
            if ($stats['blocked_attempts'] >= $this->config['threat_threshold']['blocked_attempts_hour']) {
                $threat['threat_score'] += 35;
                $threat['threat_types'][] = 'persistent_attacks';
                $threat['reasons'][] = "Множественные блокировки: {$stats['blocked_attempts']}";
                $threat['risk_factors'][] = 'persistent_attacker';
            }
            
            // Анализ высокой активности
            if ($stats['events'] >= $this->config['threat_threshold']['ddos_requests_threshold']) {
                $threat['threat_score'] += 50;
                $threat['threat_types'][] = 'ddos_suspect';
                $threat['reasons'][] = "Подозрение на DDoS: {$stats['events']} событий";
                $threat['risk_factors'][] = 'ddos_pattern';
            }
            
            // Анализ средней серьезности
            $avgSeverity = $stats['events'] > 0 ? $stats['severity_sum'] / $stats['events'] : 0;
            if ($avgSeverity >= 3.5) {
                $threat['threat_score'] += 30;
                $threat['reasons'][] = "Высокая средняя серьезность: " . round($avgSeverity, 1);
                $threat['risk_factors'][] = 'high_severity_events';
            }
            
            // Анализ разнообразия типов атак
            $uniqueEventTypes = array_unique($stats['event_types']);
            if (count($uniqueEventTypes) >= 3) {
                $threat['threat_score'] += 25;
                $threat['reasons'][] = "Разнообразные атаки: " . count($uniqueEventTypes) . " типов";
                $threat['risk_factors'][] = 'multi_vector_attack';
            }
            
            // Проверка на известные вредоносные паттерны
            if (isset($securityEvents['threat_patterns'][$ip]['malware_detected'])) {
                $threat['threat_score'] += 80;
                $threat['threat_types'][] = 'malware';
                $threat['reasons'][] = "Обнаружена вредоносная активность";
                $threat['risk_factors'][] = 'malware_detection';
            }
            
            // Определение уровня серьезности
            if ($threat['threat_score'] >= 80) {
                $threat['severity'] = 'critical';
            } elseif ($threat['threat_score'] >= 60) {
                $threat['severity'] = 'high';
            } elseif ($threat['threat_score'] >= 40) {
                $threat['severity'] = 'medium';
            }
            
            // Добавляем в список угроз если превышен порог
            if ($threat['threat_score'] > 25) {
                $threats[] = $threat;
                $threatLevel = max($threatLevel, min(5, floor($threat['threat_score'] / 20)));
            }
        }
        
        // Сортируем по убыванию угрозы
        usort($threats, function($a, $b) {
            return $b['threat_score'] - $a['threat_score'];
        });
        
        return [
            'threats' => array_slice($threats, 0, 30), // Ограничиваем до 30 самых опасных
            'threat_level' => $threatLevel,
            'total_events' => $securityEvents['total_events'],
            'total_processed' => $securityEvents['total_processed'],
            'analysis_time' => date('Y-m-d H:i:s'),
            'period_minutes' => $this->config['analysis_interval'] / 60,
            'log_sources' => $securityEvents['log_sources'],
            'unique_ips' => count($securityEvents['ip_statistics'])
        ];
    }
    
    // Консультация с ИИ по безопасности
    private function consultSecurityAI($threatAnalysis, $aiModel) {
        if (empty($threatAnalysis['threats'])) {
            return [
                'decision' => 'ignore',
                'confidence' => 95,
                'reason' => 'В системных логах не обнаружено серьезных угроз безопасности. Активность выглядит нормальной.',
                'security_recommendations' => ['Продолжить мониторинг системы', 'Регулярно обновлять систему безопасности']
            ];
        }
        
        $prompt = $this->buildSecurityAIPrompt($threatAnalysis);
        
        $data = [
            'model' => $aiModel,
            'messages' => [
                [
                    'role' => 'system',
                    'content' => 'Ты эксперт по кибербезопасности и системный администратор. Анализируй данные системы безопасности и принимай решения о блокировке подозрительных IP адресов. Отвечай СТРОГО в JSON формате: {"decision": "block/monitor/alert/ignore", "confidence": число_1_100, "reason": "подробное_объяснение_на_русском", "security_recommendations": ["рекомендация1", "рекомендация2"]}'
                ],
                [
                    'role' => 'user',
                    'content' => $prompt
                ]
            ],
            'temperature' => 0.1,
            'max_tokens' => 1500
        ];
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://openrouter.ai/api/v1/chat/completions',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($data),
            CURLOPT_TIMEOUT => 45,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $this->config['openrouter_api_key'],
                'HTTP-Referer: ' . ($_SERVER['HTTP_HOST'] ?? 'localhost'),
                'X-Title: AI Security System'
            ]
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode == 200) {
            $responseData = json_decode($response, true);
            if (isset($responseData['choices'][0]['message']['content'])) {
                $aiResponse = $responseData['choices'][0]['message']['content'];
                
                // Поиск JSON в ответе
                if (preg_match('/\{.*\}/s', $aiResponse, $matches)) {
                    $decision = json_decode($matches[0], true);
                    if ($decision && isset($decision['decision'])) {
                        return [
                            'decision' => $decision['decision'],
                            'confidence' => $decision['confidence'] ?? 80,
                            'reason' => $decision['reason'] ?? 'Решение ИИ по безопасности',
                            'security_recommendations' => $decision['security_recommendations'] ?? []
                        ];
                    }
                }
                
                // Fallback парсинг
                $decision = 'ignore';
                $confidence = 50;
                
                if (stripos($aiResponse, 'block') !== false || stripos($aiResponse, 'заблок') !== false) {
                    $decision = 'block';
                    $confidence = 85;
                } elseif (stripos($aiResponse, 'monitor') !== false || stripos($aiResponse, 'наблюд') !== false) {
                    $decision = 'monitor';
                    $confidence = 75;
                } elseif (stripos($aiResponse, 'alert') !== false || stripos($aiResponse, 'предуп') !== false) {
                    $decision = 'alert';
                    $confidence = 70;
                }
                
                return [
                    'decision' => $decision,
                    'confidence' => $confidence,
                    'reason' => substr($aiResponse, 0, 500),
                    'security_recommendations' => []
                ];
            }
        }
        
        // ИИ недоступен - принимаем автоматическое решение по безопасности
        $maxThreatScore = 0;
        $criticalThreats = 0;
        
        foreach ($threatAnalysis['threats'] as $threat) {
            $maxThreatScore = max($maxThreatScore, $threat['threat_score']);
            if ($threat['severity'] === 'critical') $criticalThreats++;
        }
        
        if ($maxThreatScore >= 80 || $criticalThreats > 0) {
            return [
                'decision' => 'block',
                'confidence' => 90,
                'reason' => 'Автоматическое решение: обнаружена критическая угроза безопасности (оценка: ' . $maxThreatScore . ', критических: ' . $criticalThreats . ')',
                'security_recommendations' => ['Немедленная блокировка', 'Проверка системы на компрометацию', 'Анализ логов']
            ];
        } elseif ($maxThreatScore >= 60) {
            return [
                'decision' => 'monitor',
                'confidence' => 80,
                'reason' => 'Автоматическое решение: обнаружена серьезная угроза безопасности (оценка: ' . $maxThreatScore . ')',
                'security_recommendations' => ['Усиленный мониторинг', 'Анализ паттернов атак', 'Проверка системы']
            ];
        } elseif ($maxThreatScore >= 40) {
            return [
                'decision' => 'alert',
                'confidence' => 70,
                'reason' => 'Автоматическое решение: обнаружена умеренная угроза безопасности (оценка: ' . $maxThreatScore . ')',
                'security_recommendations' => ['Предупреждение администратора', 'Регулярный мониторинг']
            ];
        }
        
        return [
            'decision' => 'ignore',
            'confidence' => 60,
            'reason' => 'Автоматическое решение: низкий уровень угрозы безопасности',
            'security_recommendations' => ['Обычный мониторинг', 'Регулярное обновление системы']
        ];
    }
    
    // Формирование промпта для ИИ по безопасности
    private function buildSecurityAIPrompt($threatAnalysis) {
        $prompt = "🛡️ ОТЧЕТ ПО БЕЗОПАСНОСТИ СИСТЕМЫ\n\n";
        $prompt .= "📊 ОБЩАЯ ИНФОРМАЦИЯ:\n";
        $prompt .= "• Период анализа: {$threatAnalysis['period_minutes']} минут\n";
        $prompt .= "• Обработано событий безопасности: {$threatAnalysis['total_processed']}\n";
        $prompt .= "• События в анализе: {$threatAnalysis['total_events']}\n";
        $prompt .= "• Уровень угрозы системы: {$threatAnalysis['threat_level']}/5\n";
        $prompt .= "• Уникальных IP адресов: {$threatAnalysis['unique_ips']}\n";
        $prompt .= "• Источники логов: " . implode(', ', $threatAnalysis['log_sources']) . "\n\n";
        
        if (!empty($threatAnalysis['threats'])) {
            $prompt .= "⚠️ ОБНАРУЖЕННЫЕ УГРОЗЫ БЕЗОПАСНОСТИ (топ-7):\n\n";
            
            foreach (array_slice($threatAnalysis['threats'], 0, 7) as $i => $threat) {
                $prompt .= ($i + 1) . ". 🎯 IP-адрес: {$threat['ip']}\n";
                $prompt .= "   • Оценка угрозы: {$threat['threat_score']}/100\n";
                $prompt .= "   • Уровень серьезности: {$threat['severity']}\n";
                $prompt .= "   • Всего событий безопасности: {$threat['stats']['events']}\n";
                $prompt .= "   • Неудачных попыток: {$threat['stats']['failed_attempts']}\n";
                $prompt .= "   • Заблокированных попыток: {$threat['stats']['blocked_attempts']}\n";
                $prompt .= "   • Типы угроз: " . implode(', ', $threat['threat_types']) . "\n";
                $prompt .= "   • Факторы риска: " . implode(', ', $threat['risk_factors']) . "\n";
                $prompt .= "   • Причины подозрений: " . implode('; ', $threat['reasons']) . "\n";
                
                // Примеры атак
                $uniquePorts = array_unique($threat['stats']['ports_scanned']);
                if (!empty($uniquePorts)) {
                    $prompt .= "   • Сканированные порты: " . implode(', ', array_slice($uniquePorts, 0, 10)) . "\n";
                }
                
                $uniqueEventTypes = array_unique($threat['stats']['event_types']);
                if (!empty($uniqueEventTypes)) {
                    $prompt .= "   • Типы атак: " . implode(', ', array_slice($uniqueEventTypes, 0, 5)) . "\n";
                }
                
                $prompt .= "\n";
            }
        }
        
        $prompt .= "🤔 ПРИНИМАЙ РЕШЕНИЕ ПО БЕЗОПАСНОСТИ:\n\n";
        $prompt .= "Варианты действий:\n";
        $prompt .= "• 🚫 'block' - Немедленно заблокировать IP (критические угрозы, активные атаки)\n";
        $prompt .= "• 👁️ 'monitor' - Усиленное наблюдение (подозрительная активность)\n";
        $prompt .= "• 🚨 'alert' - Предупреждение администратора (умеренные угрозы)\n";
        $prompt .= "• ✅ 'ignore' - Игнорировать (нормальная активность)\n\n";
        
        $prompt .= "Учитывай факторы безопасности:\n";
        $prompt .= "• SSH брутфорс атаки (множественные неудачные попытки)\n";
        $prompt .= "• Сканирование портов (разведка системы)\n";
        $prompt .= "• DDoS паттерны (множественные запросы)\n";
        $prompt .= "• Попытки получения root доступа\n";
        $prompt .= "• Вредоносная активность в kernel логах\n";
        $prompt .= "• Подозрительная активность в системных логах\n";
        $prompt .= "• Географическое расположение атакующих\n";
        $prompt .= "• Повторяющиеся паттерны атак\n\n";
        
        $prompt .= "Приоритеты безопасности:\n";
        $prompt .= "1. Защита от брутфорс атак на SSH\n";
        $prompt .= "2. Предотвращение сканирования портов\n";
        $prompt .= "3. Защита от DDoS атак\n";
        $prompt .= "4. Обнаружение вредоносных процессов\n";
        $prompt .= "5. Мониторинг системных ресурсов\n\n";
        
        $prompt .= "Отвечай СТРОГО в JSON формате:\n";
        $prompt .= '{"decision": "block/monitor/alert/ignore", "confidence": число_от_1_до_100, "reason": "подробное_техническое_объяснение", "security_recommendations": ["рекомендация1", "рекомендация2"]}';
        
        return $prompt;
    }
    
    // Выполнение решения по безопасности
    private function executeSecurityDecision($threatAnalysis, $aiDecision, $aiModel) {
        $analysisId = $this->saveSecurityAnalysis($threatAnalysis, $aiDecision, $aiModel);
        $actions = [];
        $blockedIps = 0;
        
        switch ($aiDecision['decision']) {
            case 'block':
                foreach ($threatAnalysis['threats'] as $threat) {
                    if ($threat['threat_score'] >= 60 || $threat['severity'] === 'critical') {
                        $blockResult = $this->blockSecurityIP($threat['ip'], $threat['threat_types'], implode('; ', $threat['reasons']), $threat['severity']);
                        $actions[] = "🚫 Заблокирован IP {$threat['ip']} (угроза: {$threat['threat_score']}, тип: {$threat['severity']})";
                        $blockedIps++;
                        
                        if ($blockResult['method']) {
                            $actions[] = "   Метод блокировки: {$blockResult['method']}";
                        }
                        
                        // Сохраняем угрозу в специальную таблицу
                        $this->saveSecurityThreat($threat);
                    }
                }
                break;
                
            case 'monitor':
                foreach ($threatAnalysis['threats'] as $threat) {
                    if ($threat['threat_score'] >= 40) {
                        $this->addToSecurityWatchlist($threat['ip'], $threat['threat_score'], $threat['threat_types']);
                        $actions[] = "👁️ Добавлен в наблюдение: {$threat['ip']} (угроза: {$threat['threat_score']})";
                    }
                }
                break;
                
            case 'alert':
                foreach ($threatAnalysis['threats'] as $threat) {
                    if ($threat['threat_score'] >= 30) {
                        $this->createSecurityAlert($threat);
                        $actions[] = "🚨 Создано предупреждение: {$threat['ip']} (угроза: {$threat['threat_score']})";
                    }
                }
                break;
                
            case 'ignore':
                $actions[] = "✅ Активность системы признана нормальной";
                break;
        }
        
        // Логируем решение ИИ по безопасности
        $this->logSecurityDecision($analysisId, $aiDecision, $actions, $aiModel);
        
        // Обновляем действия в основной записи
        $this->pdo->prepare("UPDATE security_analysis SET actions_taken = ?, blocked_ips_count = ? WHERE id = ?")
                  ->execute([implode('; ', $actions), $blockedIps, $analysisId]);
        
        return [
            'analysis_id' => $analysisId,
            'ai_decision' => $aiDecision,
            'actions_taken' => $actions,
            'blocked_ips_count' => $blockedIps,
            'timestamp' => date('Y-m-d H:i:s'),
            'threat_count' => count($threatAnalysis['threats'])
        ];
    }
    
    // Сохранение анализа безопасности
    private function saveSecurityAnalysis($threatAnalysis, $aiDecision, $aiModel) {
        $stmt = $this->pdo->prepare("
            INSERT INTO security_analysis (analysis_data, ai_decision, threat_level, security_events_count, status, ai_model) 
            VALUES (?, ?, ?, ?, 'processed', ?)
        ");
        
        $stmt->execute([
            json_encode($threatAnalysis, JSON_UNESCAPED_UNICODE),
            json_encode($aiDecision, JSON_UNESCAPED_UNICODE),
            $threatAnalysis['threat_level'],
            $threatAnalysis['total_events'],
            $aiModel
        ]);
        
        return $this->pdo->lastInsertId();
    }
    
    // Блокировка IP по соображениям безопасности
    private function blockSecurityIP($ip, $threatTypes, $reason, $severity) {
        $expiresAt = date('Y-m-d H:i:s', time() + $this->config['block_duration']);
        
        $stmt = $this->pdo->prepare("
            INSERT INTO blocked_security_ips (ip_address, threat_type, reason, expires_at, block_method, severity) 
            VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE 
            threat_type = VALUES(threat_type),
            reason = VALUES(reason), 
            expires_at = VALUES(expires_at),
            blocked_at = CURRENT_TIMESTAMP,
            status = 'active',
            block_method = VALUES(block_method),
            severity = VALUES(severity)
        ");
        
        $blockMethod = 'database';
        
        // Правильно обрабатываем типы угроз
        $threatType = 'unknown';
        if (!empty($threatTypes) && is_array($threatTypes)) {
            $threatType = implode(',', $threatTypes);
        } elseif (!empty($threatTypes)) {
            $threatType = (string)$threatTypes;
        }
        
        // Ограничиваем длину до 100 символов для соответствия схеме БД
        $threatType = substr($threatType, 0, 100);
        
        // Попытка создать правило UFW
        if (function_exists('exec') && !empty(shell_exec('which ufw'))) {
            $command = "ufw deny from {$ip} 2>/dev/null";
            $output = [];
            $returnVar = 0;
            @exec($command, $output, $returnVar);
            
            if ($returnVar === 0) {
                $blockMethod = 'ufw';
            }
        }
        
        // Альтернативно используем iptables
        if ($blockMethod === 'database' && function_exists('exec') && !empty(shell_exec('which iptables'))) {
            $command = "iptables -C INPUT -s {$ip} -j DROP 2>/dev/null || iptables -A INPUT -s {$ip} -j DROP";
            $output = [];
            $returnVar = 0;
            @exec($command, $output, $returnVar);
            
            if ($returnVar === 0) {
                $blockMethod = 'iptables';
            }
        }
        
        $stmt->execute([$ip, $threatType, $reason, $expiresAt, $blockMethod, $severity]);
        
        return [
            'success' => true,
            'method' => $blockMethod,
            'expires_at' => $expiresAt
        ];
    }
    
    // Сохранение угрозы безопасности
    private function saveSecurityThreat($threat) {
        $stmt = $this->pdo->prepare("
            INSERT INTO security_threats (ip_address, threat_type, threat_score, details, source_logs, status) 
            VALUES (?, ?, ?, ?, ?, 'active')
            ON DUPLICATE KEY UPDATE 
            threat_score = GREATEST(threat_score, VALUES(threat_score)),
            last_seen = CURRENT_TIMESTAMP,
            event_count = event_count + 1,
            details = VALUES(details)
        ");
        
        $threatType = !empty($threat['threat_types']) ? $threat['threat_types'][0] : 'unknown';
        $details = json_encode([
            'threat_types' => $threat['threat_types'],
            'risk_factors' => $threat['risk_factors'],
            'reasons' => $threat['reasons'],
            'stats' => $threat['stats']
        ], JSON_UNESCAPED_UNICODE);
        
        $stmt->execute([
            $threat['ip'],
            $threatType,
            $threat['threat_score'],
            $details,
            'security_analysis',
        ]);
    }
    
    // Добавление в список наблюдения безопасности
    private function addToSecurityWatchlist($ip, $threatScore, $threatTypes) {
        $stmt = $this->pdo->prepare("
            INSERT INTO security_threats (ip_address, threat_type, threat_score, status) 
            VALUES (?, ?, ?, 'monitoring')
            ON DUPLICATE KEY UPDATE 
            threat_score = GREATEST(threat_score, VALUES(threat_score)),
            last_seen = CURRENT_TIMESTAMP,
            event_count = event_count + 1
        ");
        
        // Правильно обрабатываем типы угроз
        $threatType = 'unknown';
        if (!empty($threatTypes) && is_array($threatTypes)) {
            $threatType = $threatTypes[0]; // Берем первый тип угрозы
        } elseif (!empty($threatTypes)) {
            $threatType = (string)$threatTypes;
        }
        
        // Ограничиваем длину до 255 символов
        $threatType = substr($threatType, 0, 255);
        
        $stmt->execute([$ip, $threatType, $threatScore]);
    }
    
    // Создание предупреждения безопасности
    private function createSecurityAlert($threat) {
        // Можно реализовать отправку уведомлений, логирование в отдельную систему и т.д.
        error_log("SECURITY ALERT: IP {$threat['ip']} threat score {$threat['threat_score']} - " . implode(', ', $threat['reasons']));
    }
    
    // Логирование решения ИИ по безопасности
    private function logSecurityDecision($analysisId, $aiDecision, $actions, $aiModel) {
        $stmt = $this->pdo->prepare("
            INSERT INTO ai_security_decisions (analysis_id, decision_type, confidence_score, ai_reasoning, security_recommendations, executed_actions, ai_model) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([
            $analysisId,
            $aiDecision['decision'],
            $aiDecision['confidence'],
            $aiDecision['reason'],
            json_encode($aiDecision['security_recommendations'], JSON_UNESCAPED_UNICODE),
            json_encode($actions, JSON_UNESCAPED_UNICODE),
            $aiModel
        ]);
    }
    
    // Обновление статистики безопасности
    private function updateSecurityStats($threatAnalysis, $processingTime, $aiModel) {
        // Можно реализовать сохранение статистики производительности и эффективности
    }
    
    // Получение статистики безопасности
    public function getSecurityStats() {
        $stats = [];
        
        // Общая статистика анализов за 24 часа
        $stmt = $this->pdo->query("
            SELECT COUNT(*) as total_analysis, 
                   AVG(threat_level) as avg_threat_level,
                   MAX(timestamp) as last_analysis,
                   AVG(processing_time_ms) as avg_processing_time,
                   SUM(security_events_count) as total_security_events,
                   SUM(blocked_ips_count) as total_blocked_ips
            FROM security_analysis 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $stats['analysis'] = $stmt->fetch();
        
        // Статистика по моделям ИИ
        $stmt = $this->pdo->query("
            SELECT ai_model, COUNT(*) as usage_count, 
                   AVG(processing_time_ms) as avg_processing_time,
                   AVG(threat_level) as avg_threat_level
            FROM security_analysis 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) 
                  AND ai_model IS NOT NULL
            GROUP BY ai_model 
            ORDER BY usage_count DESC
        ");
        $stats['model_usage'] = $stmt->fetchAll();
        
        // Статистика блокировок безопасности
        $stmt = $this->pdo->query("
            SELECT COUNT(*) as active_blocks,
                   COUNT(CASE WHEN blocked_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as recent_blocks,
                   COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_blocks,
                   COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_blocks,
                   COUNT(CASE WHEN block_method = 'ufw' THEN 1 END) as ufw_blocks,
                   COUNT(CASE WHEN block_method = 'iptables' THEN 1 END) as iptables_blocks
            FROM blocked_security_ips 
            WHERE status = 'active' AND (expires_at IS NULL OR expires_at > NOW())
        ");
        $stats['blocks'] = $stmt->fetch();
        
        // Решения ИИ по безопасности за 24 часа
        $stmt = $this->pdo->query("
            SELECT decision_type, COUNT(*) as count, AVG(confidence_score) as avg_confidence
            FROM ai_security_decisions 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY decision_type
            ORDER BY count DESC
        ");
        $stats['decisions'] = $stmt->fetchAll();
        
        // Топ угроз безопасности
        $stmt = $this->pdo->query("
            SELECT ip_address, threat_type, threat_score, event_count, last_seen
            FROM security_threats 
            WHERE last_seen >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND status = 'active'
            ORDER BY threat_score DESC, event_count DESC
            LIMIT 15
        ");
        $stats['top_threats'] = $stmt->fetchAll();
        
        // События безопасности по типам
        $stmt = $this->pdo->query("
            SELECT event_type, COUNT(*) as count, AVG(severity) as avg_severity
            FROM security_events 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 10
        ");
        $stats['event_types'] = $stmt->fetchAll();
        
        return $stats;
    }
    
    // Разблокировка IP
    public function unblockSecurityIP($ip) {
        // Обновляем статус в БД
        $stmt = $this->pdo->prepare("UPDATE blocked_security_ips SET status = 'removed' WHERE ip_address = ?");
        $stmt->execute([$ip]);
        
        $actions = [];
        
        // Удаляем из UFW
        if (function_exists('exec') && !empty(shell_exec('which ufw'))) {
            $command = "ufw delete deny from {$ip} 2>/dev/null";
            @exec($command);
            $actions[] = 'Удален из UFW';
        }
        
        // Удаляем из iptables
        if (function_exists('exec') && !empty(shell_exec('which iptables'))) {
            $command = "iptables -D INPUT -s {$ip} -j DROP 2>/dev/null";
            @exec($command);
            $actions[] = 'Удален из iptables';
        }
        
        $actions[] = 'Удален из базы данных';
        
        return [
            'success' => true,
            'actions' => $actions
        ];
    }
}

// Инициализация анализатора безопасности
$analyzer = new AISecurityAnalyzer($config, $pdo);

// Обработка AJAX запросов
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    
    try {
        switch ($_POST['action']) {
            case 'run_security_analysis':
                $selectedModel = $_POST['ai_model'] ?? getCurrentAIModel($config);
                $result = $analyzer->analyzeSecurityLogs($selectedModel);
                echo json_encode(['success' => true, 'data' => $result], JSON_UNESCAPED_UNICODE);
                break;
                
            case 'get_security_stats':
                $stats = $analyzer->getSecurityStats();
                echo json_encode(['success' => true, 'data' => $stats], JSON_UNESCAPED_UNICODE);
                break;
                
            case 'change_model':
                $newModel = $_POST['model'] ?? $config['default_ai_model'];
                $_SESSION['selected_ai_model'] = $newModel;
                echo json_encode(['success' => true, 'message' => "Модель изменена на: {$newModel}"], JSON_UNESCAPED_UNICODE);
                break;
                
            case 'unblock_security_ip':
                $ip = $_POST['ip'] ?? '';
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $result = $analyzer->unblockSecurityIP($ip);
                    echo json_encode(['success' => true, 'message' => "IP {$ip} разблокирован", 'data' => $result], JSON_UNESCAPED_UNICODE);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Некорректный IP адрес'], JSON_UNESCAPED_UNICODE);
                }
                break;
                
            case 'get_security_details':
                $analysisId = intval($_POST['analysis_id'] ?? 0);
                if ($analysisId > 0) {
                    $stmt = $pdo->prepare("SELECT * FROM security_analysis WHERE id = ?");
                    $stmt->execute([$analysisId]);
                    $analysis = $stmt->fetch();
                    
                    if ($analysis) {
                        $analysis['analysis_data'] = json_decode($analysis['analysis_data'], true);
                        $analysis['ai_decision'] = json_decode($analysis['ai_decision'], true);
                        echo json_encode(['success' => true, 'data' => $analysis], JSON_UNESCAPED_UNICODE);
                    } else {
                        echo json_encode(['success' => false, 'error' => 'Анализ не найден'], JSON_UNESCAPED_UNICODE);
                    }
                } else {
                    echo json_encode(['success' => false, 'error' => 'Некорректный ID анализа'], JSON_UNESCAPED_UNICODE);
                }
                break;
                
            default:
                echo json_encode(['success' => false, 'error' => 'Неизвестное действие'], JSON_UNESCAPED_UNICODE);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// Получение данных для отображения
$currentAiModel = getCurrentAIModel($config);

$stmt = $pdo->query("
    SELECT sa.*, 
           (SELECT COUNT(*) FROM blocked_security_ips bsi WHERE bsi.blocked_at BETWEEN sa.timestamp AND DATE_ADD(sa.timestamp, INTERVAL 5 MINUTE)) as blocked_ips_count
    FROM security_analysis sa
    WHERE sa.timestamp >= DATE_SUB(NOW(), INTERVAL 48 HOUR)
    ORDER BY sa.timestamp DESC 
    LIMIT 20
");
$recent_analyses = $stmt->fetchAll();

$stmt = $pdo->query("
    SELECT bsi.*, 
           CASE 
               WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 'expired'
               ELSE 'active'
           END as current_status
    FROM blocked_security_ips bsi
    WHERE bsi.status = 'active'
    ORDER BY bsi.severity DESC, bsi.blocked_at DESC
    LIMIT 50
");
$blocked_ips = $stmt->fetchAll();

$stats = $analyzer->getSecurityStats();
$models = getOpenRouterModels();

// Проверка доступности логов
$logStatus = [];
foreach ($config['log_paths'] as $logPath) {
    $logStatus[basename($logPath)] = [
        'path' => $logPath,
        'exists' => file_exists($logPath),
        'readable' => is_readable($logPath),
        'size' => file_exists($logPath) ? filesize($logPath) : 0
    ];
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ AI Security Analyzer - Система анализа безопасности</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            padding: 20px;
            color: #2c3e50;
        }

        .container {
            max-width: 1800px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
            padding: 25px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            backdrop-filter: blur(15px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .header h1 {
            font-size: 3.2rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            background: linear-gradient(45deg, #fff, #f0f8ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header p {
            font-size: 1.3rem;
            opacity: 0.9;
            margin-bottom: 20px;
        }

        .system-status {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 15px;
            flex-wrap: wrap;
        }

        .status-item {
            background: rgba(255, 255, 255, 0.2);
            padding: 10px 18px;
            border-radius: 25px;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            gap: 8px;
            backdrop-filter: blur(10px);
        }

        .status-online {
            background: rgba(40, 167, 69, 0.8);
        }

        .status-warning {
            background: rgba(255, 193, 7, 0.8);
        }

        .status-error {
            background: rgba(220, 53, 69, 0.8);
        }

        /* Статус логов */
        .log-status {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 20px;
            margin-bottom: 25px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }

        .log-status h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .log-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .log-item {
            padding: 15px;
            border-radius: 12px;
            border-left: 5px solid;
            transition: transform 0.3s ease;
        }

        .log-item:hover {
            transform: translateX(5px);
        }

        .log-item.available {
            background: linear-gradient(145deg, #d4edda, #c3e6cb);
            border-color: #28a745;
        }

        .log-item.unavailable {
            background: linear-gradient(145deg, #f8d7da, #f5c6cb);
            border-color: #dc3545;
        }

        .log-name {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }

        .log-details {
            font-size: 0.85rem;
            color: #6c757d;
        }

        /* AI Model Selector */
        .ai-model-selector {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(15px);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .ai-model-selector h3 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.4rem;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 3px solid #1e3c72;
            padding-bottom: 10px;
        }

        .model-controls {
            display: flex;
            gap: 20px;
            align-items: flex-start;
            flex-wrap: wrap;
        }

        .model-select-wrapper {
            flex: 1;
            min-width: 300px;
        }

        .model-select {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e9ecef;
            border-radius: 12px;
            font-size: 1rem;
            background: white;
            color: #2c3e50;
            transition: all 0.3s ease;
        }

        .model-select:focus {
            outline: none;
            border-color: #1e3c72;
            box-shadow: 0 0 0 3px rgba(30, 60, 114, 0.1);
        }

        .model-info {
            margin-top: 15px;
            padding: 15px;
            border-radius: 12px;
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border-left: 5px solid;
        }

        .model-info.free { border-color: #17a2b8; }
        .model-info.budget { border-color: #ffc107; }
        .model-info.premium { border-color: #dc3545; }
        .model-info.newest { border-color: #28a745; }

        .model-stats {
            display: flex;
            gap: 15px;
            margin-top: 10px;
            flex-wrap: wrap;
        }

        .model-stat {
            background: rgba(30, 60, 114, 0.1);
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 0.85rem;
            color: #1e3c72;
            border: 1px solid rgba(30, 60, 114, 0.2);
        }

        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(15px);
            border: 1px solid rgba(255, 255, 255, 0.3);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.25);
        }

        .card h3 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.4rem;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 3px solid #1e3c72;
            padding-bottom: 10px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }

        .stat-item {
            text-align: center;
            padding: 20px 15px;
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border-radius: 15px;
            border-left: 5px solid;
            transition: transform 0.3s ease;
            cursor: pointer;
        }

        .stat-item:hover {
            transform: scale(1.05);
        }

        .stat-item.critical { border-color: #dc3545; }
        .stat-item.high { border-color: #fd7e14; }
        .stat-item.medium { border-color: #ffc107; }
        .stat-item.low { border-color: #28a745; }
        .stat-item.info { border-color: #1e3c72; }

        .stat-number {
            font-size: 2.2rem;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 0.9rem;
            color: #6c757d;
            font-weight: 600;
        }

        .controls {
            text-align: center;
            margin: 30px 0;
            display: flex;
            justify-content: center;
            gap: 15px;
            flex-wrap: wrap;
        }

        .btn {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 25px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            text-decoration: none;
            box-shadow: 0 4px 15px rgba(30, 60, 114, 0.4);
        }

        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(30, 60, 114, 0.6);
        }

        .btn.danger {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            box-shadow: 0 4px 15px rgba(220, 53, 69, 0.4);
        }

        .btn.danger:hover {
            box-shadow: 0 8px 25px rgba(220, 53, 69, 0.6);
        }

        .btn.success {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.4);
        }

        .btn.success:hover {
            box-shadow: 0 8px 25px rgba(40, 167, 69, 0.6);
        }

        .btn:disabled {
            opacity: 0.7;
            cursor: not-allowed;
            transform: none !important;
        }

        .table-container {
            max-height: 500px;
            overflow-y: auto;
            border-radius: 15px;
            background: white;
            box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.1);
        }

        .table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }

        .table th,
        .table td {
            padding: 15px 12px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }

        .table th {
            background: linear-gradient(145deg, #1e3c72, #2a5298);
            color: white;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        .table tbody tr {
            transition: background-color 0.3s ease;
        }

        .table tbody tr:hover {
            background-color: rgba(30, 60, 114, 0.1);
        }

        .badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge.critical { 
            background: linear-gradient(135deg, #ffebee, #ffcdd2); 
            color: #c62828; 
            border: 2px solid #dc3545;
        }
        .badge.high { 
            background: linear-gradient(135deg, #fff3e0, #ffe0b2); 
            color: #ef6c00; 
            border: 2px solid #fd7e14;
        }
        .badge.medium { 
            background: linear-gradient(135deg, #fffbf0, #fff3cd); 
            color: #b8860b; 
            border: 2px solid #ffc107;
        }
        .badge.low { 
            background: linear-gradient(135deg, #e8f5e8, #c8e6c9); 
            color: #2e7d32; 
            border: 2px solid #28a745;
        }

        .decision-badge {
            padding: 8px 16px;
            border-radius: 25px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }

        .decision-block { 
            background: linear-gradient(135deg, #ffebee, #ffcdd2); 
            color: #c62828; 
            border: 2px solid #dc3545;
        }
        .decision-monitor { 
            background: linear-gradient(135deg, #e3f2fd, #bbdefb); 
            color: #1565c0; 
            border: 2px solid #2196f3;
        }
        .decision-alert { 
            background: linear-gradient(135deg, #fff3e0, #ffe0b2); 
            color: #ef6c00; 
            border: 2px solid #ff9800;
        }
        .decision-ignore { 
            background: linear-gradient(135deg, #e8f5e8, #c8e6c9); 
            color: #2e7d32; 
            border: 2px solid #28a745;
        }

        .threat-score {
            display: inline-block;
            min-width: 60px;
            text-align: center;
            padding: 4px 8px;
            border-radius: 12px;
            font-weight: bold;
            font-size: 0.85rem;
        }

        .threat-critical { background: #ffebee; color: #c62828; border: 2px solid #dc3545; }
        .threat-high { background: #fff3e0; color: #ef6c00; border: 2px solid #fd7e14; }
        .threat-medium { background: #fffbf0; color: #b8860b; border: 2px solid #ffc107; }
        .threat-low { background: #e8f5e8; color: #2e7d32; border: 2px solid #28a745; }

        .ip-address {
            font-family: 'Courier New', monospace;
            background: rgba(30, 60, 114, 0.1);
            padding: 4px 8px;
            border-radius: 6px;
            border: 1px solid rgba(30, 60, 114, 0.3);
            font-weight: bold;
        }

        .ai-model-badge {
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 500;
            margin-left: 8px;
        }

        .log-entry {
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border-left: 5px solid #1e3c72;
            padding: 20px;
            margin: 15px 0;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }

        .log-entry:hover {
            transform: translateX(5px);
        }

        .ai-response {
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            border: 3px solid #1e3c72;
            border-radius: 15px;
            padding: 20px;
            margin: 15px 0;
            box-shadow: 0 8px 25px rgba(30, 60, 114, 0.3);
        }

        .ai-response h4 {
            color: #1e3c72;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.1rem;
        }

        .alert {
            padding: 18px 24px;
            margin: 20px 0;
            border-radius: 12px;
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 500;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }

        .alert.success {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            color: #155724;
            border: 2px solid #28a745;
        }

        .alert.error {
            background: linear-gradient(135deg, #f8d7da, #f5c6cb);
            color: #721c24;
            border: 2px solid #dc3545;
        }

        .alert.info {
            background: linear-gradient(135deg, #cce7ff, #b3d9ff);
            color: #004085;
            border: 2px solid #2196f3;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #6c757d;
        }

        .empty-state i {
            font-size: 4rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }

        .empty-state h3 {
            font-size: 1.5rem;
            margin-bottom: 10px;
            color: #495057;
        }

        .loading {
            display: inline-block;
            width: 24px;
            height: 24px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-top: 3px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Модальные окна */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            display: none;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(5px);
        }

        .modal {
            background: white;
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
            width: 90%;
            max-width: 900px;
            max-height: 90vh;
            overflow-y: auto;
        }

        .modal-header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 25px;
            border-radius: 20px 20px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-title {
            font-size: 1.4rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .modal-close {
            background: rgba(255, 255, 255, 0.2);
            border: none;
            color: white;
            font-size: 1.5rem;
            cursor: pointer;
            padding: 8px 12px;
            border-radius: 50%;
            transition: background 0.3s ease;
        }

        .modal-close:hover {
            background: rgba(255, 255, 255, 0.3);
        }

        .modal-body {
            padding: 25px;
        }

        /* Адаптивность */
        @media (max-width: 768px) {
            body {
                padding: 15px;
            }
            
            .header h1 {
                font-size: 2.4rem;
            }
            
            .dashboard {
                grid-template-columns: 1fr;
                gap: 20px;
            }

            .ai-model-selector {
                padding: 20px;
            }

            .model-controls {
                flex-direction: column;
                gap: 15px;
            }

            .model-select-wrapper {
                min-width: 100%;
            }

            .log-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .card {
                padding: 20px;
            }
            
            .controls {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                width: 100%;
                max-width: 300px;
                justify-content: center;
            }
            
            .table {
                font-size: 0.8rem;
            }
            
            .table th,
            .table td {
                padding: 10px 8px;
            }

            .system-status {
                flex-direction: column;
                gap: 10px;
            }
        }

        @media (max-width: 480px) {
            .header {
                padding: 15px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .stat-item {
                padding: 15px;
            }
            
            .stat-number {
                font-size: 1.8rem;
            }
            
            .card {
                padding: 15px;
            }
            
            .card h3 {
                font-size: 1.2rem;
            }
        }

        /* Анимации */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .card, .ai-model-selector, .log-status {
            animation: fadeInUp 0.6s ease-out forwards;
        }

        .card:nth-child(1) { animation-delay: 0.1s; }
        .card:nth-child(2) { animation-delay: 0.2s; }
        .card:nth-child(3) { animation-delay: 0.3s; }
        .card:nth-child(4) { animation-delay: 0.4s; }

        .blink {
            animation: blink 2s infinite;
        }

        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> AI Security Analyzer</h1>
            <p>Система интеллектуального анализа безопасности системных логов</p>
            <div class="system-status">
                <div class="status-item status-online">
                    <i class="fas fa-database"></i>
                    MariaDB подключена
                </div>
                <div class="status-item status-online">
                    <i class="fas fa-brain"></i>
                    Активная модель: <?php echo $models[$currentAiModel]['name'] ?? 'Неизвестная'; ?>
                </div>
                <div class="status-item">
                    <i class="fas fa-clock"></i>
                    Анализ каждые <?php echo $config['analysis_interval']/60; ?> мин
                </div>
                <div class="status-item">
                    <i class="fas fa-file-alt"></i>
                    <?php echo count(array_filter($logStatus, fn($s) => $s['exists'])); ?>/<?php echo count($logStatus); ?> логов доступно
                </div>
            </div>
        </div>

        <!-- Статус логов безопасности -->
        <div class="log-status">
            <h3><i class="fas fa-file-shield"></i> Статус логов безопасности</h3>
            <div class="log-grid">
                <?php foreach ($logStatus as $logName => $status): ?>
                <div class="log-item <?php echo $status['exists'] && $status['readable'] ? 'available' : 'unavailable'; ?>">
                    <div class="log-name">
                        <i class="fas fa-<?php echo $status['exists'] && $status['readable'] ? 'check-circle' : 'exclamation-triangle'; ?>"></i>
                        <?php echo $logName; ?>
                    </div>
                    <div class="log-details">
                        <?php if ($status['exists'] && $status['readable']): ?>
                            Размер: <?php echo number_format($status['size'] / 1024 / 1024, 2); ?> MB<br>
                            Путь: <?php echo $status['path']; ?>
                        <?php elseif ($status['exists']): ?>
                            Недоступен для чтения<br>
                            Путь: <?php echo $status['path']; ?>
                        <?php else: ?>
                            Файл не существует<br>
                            Путь: <?php echo $status['path']; ?>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- AI Model Selector -->
        <div class="ai-model-selector">
            <h3><i class="fas fa-brain"></i> Выбор AI модели для анализа безопасности</h3>
            <div class="model-controls">
                <div class="model-select-wrapper">
                    <select class="model-select" id="aiModelSelect" onchange="changeAIModel()">
                        <?php 
                        $categoryNames = [
                            'free' => '🆓 БЕСПЛАТНЫЕ',
                            'budget' => '💰 БЮДЖЕТНЫЕ',
                            'premium' => '🥇 ПРЕМИУМ',
                            'newest' => '🚀 НОВЕЙШИЕ'
                        ];
                        
                        $categorizedModels = [];
                        foreach ($models as $key => $model) {
                            $categorizedModels[$model['category']][$key] = $model;
                        }
                        
                        foreach ($categoryNames as $category => $categoryName) {
                            if (isset($categorizedModels[$category])) {
                                echo '<optgroup label="' . $categoryName . '">';
                                foreach ($categorizedModels[$category] as $key => $model) {
                                    $selected = $key === $currentAiModel ? 'selected' : '';
                                    echo '<option value="' . $key . '" ' . $selected . '>';
                                    echo $model['name'];
                                    if ($model['recommended']) echo ' ⭐';
                                    echo '</option>';
                                }
                                echo '</optgroup>';
                            }
                        }
                        ?>
                    </select>
                    
                    <div class="model-info <?php echo $models[$currentAiModel]['category'] ?? 'info'; ?>" id="modelInfo">
                        <div>
                            <strong><?php echo $models[$currentAiModel]['name'] ?? 'Неизвестная модель'; ?></strong>
                            <?php if (($models[$currentAiModel]['recommended'] ?? false)): ?>
                                <span style="color: #f39c12; margin-left: 8px;"><i class="fas fa-star"></i> Рекомендуется для безопасности</span>
                            <?php endif; ?>
                        </div>
                        <div style="margin: 8px 0; color: #6c757d;">
                            <?php echo $models[$currentAiModel]['description'] ?? ''; ?>
                        </div>
                        <div class="model-stats">
                            <div class="model-stat">
                                💰 <?php echo $models[$currentAiModel]['price'] ?? 'N/A'; ?>
                            </div>
                            <div class="model-stat">
                                ⚡ <?php echo $models[$currentAiModel]['speed'] ?? '⚡⚡⚡'; ?>
                            </div>
                            <div class="model-stat">
                                ⭐ <?php echo $models[$currentAiModel]['quality'] ?? '⭐⭐⭐'; ?>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php if (!empty($stats['model_usage'])): ?>
                <div style="min-width: 200px;">
                    <h4 style="color: #2c3e50; margin-bottom: 10px;">📊 Статистика моделей (24ч)</h4>
                    <div class="table-container" style="max-height: 200px;">
                        <table class="table" style="font-size: 0.8rem;">
                            <thead>
                                <tr>
                                    <th>Модель</th>
                                    <th>Использований</th>
                                    <th>Ср. время</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach (array_slice($stats['model_usage'], 0, 5) as $usage): ?>
                                <tr>
                                    <td>
                                        <?php 
                                        $modelName = $models[$usage['ai_model']]['name'] ?? 'Неизвестная';
                                        echo substr($modelName, 0, 20) . (strlen($modelName) > 20 ? '...' : '');
                                        ?>
                                    </td>
                                    <td><?php echo $usage['usage_count']; ?></td>
                                    <td><?php echo round($usage['avg_processing_time']); ?>мс</td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="controls">
            <button class="btn" onclick="runSecurityAnalysis()">
                <i class="fas fa-shield-alt"></i> Запустить анализ безопасности
            </button>
            <button class="btn success" onclick="loadSecurityStats()">
                <i class="fas fa-sync"></i> Обновить статистику
            </button>
            <button class="btn" onclick="showSecurityInfo()">
                <i class="fas fa-info-circle"></i> Информация о системе
            </button>
        </div>

        <div id="alerts"></div>

        <div class="dashboard">
            <!-- Статистика анализов безопасности -->
            <div class="card">
                <h3><i class="fas fa-chart-bar"></i> Анализ безопасности за 24ч</h3>
                <div class="stats-grid">
                    <div class="stat-item info">
                        <div class="stat-number"><?php echo $stats['analysis']['total_analysis'] ?? 0; ?></div>
                        <div class="stat-label">Анализов</div>
                    </div>
                    <div class="stat-item critical">
                        <div class="stat-number"><?php echo number_format($stats['analysis']['avg_threat_level'] ?? 0, 1); ?></div>
                        <div class="stat-label">Ср. угроза</div>
                    </div>
                    <div class="stat-item medium">
                        <div class="stat-number"><?php echo $stats['analysis']['total_security_events'] ?? 0; ?></div>
                        <div class="stat-label">События</div>
                    </div>
                    <div class="stat-item high">
                        <div class="stat-number"><?php echo $stats['analysis']['total_blocked_ips'] ?? 0; ?></div>
                        <div class="stat-label">Заблокировано</div>
                    </div>
                </div>
                <?php if (!empty($stats['analysis']['last_analysis'])): ?>
                <div class="alert info">
                    <i class="fas fa-clock"></i>
                    Последний анализ: <?php echo date('d.m.Y H:i:s', strtotime($stats['analysis']['last_analysis'])); ?>
                </div>
                <?php endif; ?>
            </div>

            <!-- Статистика блокировок безопасности -->
            <div class="card">
                <h3><i class="fas fa-ban"></i> Блокировки безопасности</h3>
                <div class="stats-grid">
                    <div class="stat-item critical">
                        <div class="stat-number"><?php echo $stats['blocks']['critical_blocks'] ?? 0; ?></div>
                        <div class="stat-label">Критические</div>
                    </div>
                    <div class="stat-item high">
                        <div class="stat-number"><?php echo $stats['blocks']['high_blocks'] ?? 0; ?></div>
                        <div class="stat-label">Высокие</div>
                    </div>
                    <div class="stat-item medium">
                        <div class="stat-number"><?php echo $stats['blocks']['recent_blocks'] ?? 0; ?></div>
                        <div class="stat-label">За час</div>
                    </div>
                    <div class="stat-item info">
                        <div class="stat-number"><?php echo $stats['blocks']['active_blocks'] ?? 0; ?></div>
                        <div class="stat-label">Всего активных</div>
                    </div>
                </div>
                <div style="margin-top: 15px; font-size: 0.9rem; color: #6c757d;">
                    <div>UFW блокировок: <?php echo $stats['blocks']['ufw_blocks'] ?? 0; ?></div>
                    <div>iptables блокировок: <?php echo $stats['blocks']['iptables_blocks'] ?? 0; ?></div>
                </div>
            </div>

            <!-- Решения ИИ по безопасности -->
            <div class="card">
                <h3><i class="fas fa-robot"></i> Решения ИИ за 24ч</h3>
                <div class="stats-grid">
                    <?php 
                    $decisionCounts = ['block' => 0, 'monitor' => 0, 'alert' => 0, 'ignore' => 0];
                    foreach ($stats['decisions'] as $decision) {
                        if (isset($decisionCounts[$decision['decision_type']])) {
                            $decisionCounts[$decision['decision_type']] += $decision['count'];
                        }
                    }
                    ?>
                    
                    <div class="stat-item critical">
                        <div class="stat-number"><?php echo $decisionCounts['block']; ?></div>
                        <div class="stat-label">Block</div>
                    </div>
                    <div class="stat-item medium">
                        <div class="stat-number"><?php echo $decisionCounts['monitor']; ?></div>
                        <div class="stat-label">Monitor</div>
                    </div>
                    <div class="stat-item high">
                        <div class="stat-number"><?php echo $decisionCounts['alert']; ?></div>
                        <div class="stat-label">Alert</div>
                    </div>
                    <div class="stat-item low">
                        <div class="stat-number"><?php echo $decisionCounts['ignore']; ?></div>
                        <div class="stat-label">Ignore</div>
                    </div>
                </div>
            </div>

            <!-- Топ угроз безопасности -->
            <div class="card">
                <h3><i class="fas fa-exclamation-triangle"></i> Топ угроз безопасности</h3>
                <?php if (empty($stats['top_threats'])): ?>
                    <div class="empty-state">
                        <i class="fas fa-shield-check"></i>
                        <h3>Критических угроз не обнаружено</h3>
                        <p>Система безопасности работает нормально</p>
                    </div>
                <?php else: ?>
                    <div class="table-container">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>IP адрес</th>
                                    <th>Тип угрозы</th>
                                    <th>Оценка</th>
                                    <th>События</th>
                                    <th>Последняя активность</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach (array_slice($stats['top_threats'], 0, 10) as $threat): ?>
                                <tr>
                                    <td><code class="ip-address"><?php echo htmlspecialchars($threat['ip_address']); ?></code></td>
                                    <td>
                                        <span class="badge 
                                            <?php 
                                            switch($threat['threat_type']) {
                                                case 'ssh_bruteforce': echo 'critical'; break;
                                                case 'port_scan': echo 'high'; break;
                                                case 'ddos': echo 'critical'; break;
                                                case 'malware': echo 'critical'; break;
                                                default: echo 'medium';
                                            }
                                            ?>">
                                            <?php echo strtoupper(str_replace('_', ' ', $threat['threat_type'])); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <span class="threat-score 
                                            <?php 
                                            if ($threat['threat_score'] >= 80) echo 'threat-critical';
                                            elseif ($threat['threat_score'] >= 60) echo 'threat-high';
                                            elseif ($threat['threat_score'] >= 40) echo 'threat-medium';
                                            else echo 'threat-low';
                                            ?>">
                                            <?php echo $threat['threat_score']; ?>/100
                                        </span>
                                    </td>
                                    <td><?php echo $threat['event_count']; ?></td>
                                    <td><?php echo date('d.m H:i', strtotime($threat['last_seen'])); ?></td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>

            <!-- События безопасности по типам -->
            <div class="card">
                <h3><i class="fas fa-list"></i> События безопасности по типам</h3>
                <?php if (empty($stats['event_types'])): ?>
                    <div class="empty-state">
                        <i class="fas fa-calendar-check"></i>
                        <h3>События не обнаружены</h3>
                        <p>За последние 24 часа подозрительных событий не зафиксировано</p>
                    </div>
                <?php else: ?>
                    <div class="table-container">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Тип события</th>
                                    <th>Количество</th>
                                    <th>Ср. серьезность</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($stats['event_types'] as $eventType): ?>
                                <tr>
                                    <td>
                                        <?php 
                                        $eventName = str_replace('_', ' ', $eventType['event_type']);
                                        echo ucwords($eventName);
                                        ?>
                                    </td>
                                    <td>
                                        <span class="badge 
                                            <?php 
                                            if ($eventType['count'] > 100) echo 'critical';
                                            elseif ($eventType['count'] > 50) echo 'high';
                                            elseif ($eventType['count'] > 20) echo 'medium';
                                            else echo 'low';
                                            ?>">
                                            <?php echo $eventType['count']; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <span class="threat-score 
                                            <?php 
                                            $avgSev = $eventType['avg_severity'];
                                            if ($avgSev >= 4) echo 'threat-critical';
                                            elseif ($avgSev >= 3) echo 'threat-high';
                                            elseif ($avgSev >= 2) echo 'threat-medium';
                                            else echo 'threat-low';
                                            ?>">
                                            <?php echo number_format($eventType['avg_severity'], 1); ?>/5
                                        </span>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="dashboard">
            <!-- История анализов безопасности -->
            <div class="card">
                <h3><i class="fas fa-history"></i> Последние анализы безопасности (48ч)</h3>
                <?php if (empty($recent_analyses)): ?>
                    <div class="empty-state">
                        <i class="fas fa-search"></i>
                        <h3>Анализы не найдены</h3>
                        <p>Запустите первый анализ безопасности для получения данных</p>
                    </div>
                <?php else: ?>
                <div class="table-container">
                    <?php foreach ($recent_analyses as $analysis): ?>
                    <?php 
                    $data = json_decode($analysis['analysis_data'], true);
                    $decision = json_decode($analysis['ai_decision'], true);
                    ?>
                    <div class="log-entry" onclick="showSecurityDetails(<?php echo $analysis['id']; ?>)" style="cursor: pointer;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <div>
                                <strong style="font-size: 1.1rem;">
                                    <i class="fas fa-shield-alt"></i>
                                    <?php echo date('d.m.Y H:i:s', strtotime($analysis['timestamp'])); ?>
                                </strong>
                                <div style="margin-top: 5px;">
                                    <span class="decision-badge decision-<?php echo $decision['decision'] ?? 'ignore'; ?>">
                                        <?php echo strtoupper($decision['decision'] ?? 'UNKNOWN'); ?>
                                    </span>
                                    <?php if (isset($analysis['processing_time_ms']) && $analysis['processing_time_ms']): ?>
                                        <span class="badge info" style="margin-left: 8px;">
                                            <?php echo $analysis['processing_time_ms']; ?>мс
                                        </span>
                                    <?php endif; ?>
                                    <?php if (!empty($analysis['ai_model'])): ?>
                                        <span class="ai-model-badge">
                                            <?php echo $models[$analysis['ai_model']]['name'] ?? $analysis['ai_model']; ?>
                                        </span>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div style="text-align: right;">
                                <div style="font-size: 1.2rem; font-weight: bold; color: #dc3545;">
                                    <?php echo count($data['threats'] ?? []); ?> угроз
                                </div>
                                <div style="font-size: 0.9rem; color: #6c757d;">
                                    Уровень: <?php echo $analysis['threat_level']; ?>/5
                                </div>
                            </div>
                        </div>
                        
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 10px 0;">
                            <div>
                                <strong>🛡️ События безопасности:</strong> 
                                <?php echo number_format($analysis['security_events_count'] ?? 0, 0, '.', ' '); ?>
                            </div>
                            <div>
                                <strong>🎯 Точность ИИ:</strong> 
                                <?php echo $decision['confidence'] ?? 0; ?>%
                            </div>
                            <div>
                                <strong>🚫 Заблокировано IP:</strong> 
                                <?php echo $analysis['blocked_ips_count'] ?? 0; ?>
                            </div>
                            <div>
                                <strong>📊 Уникальных IP:</strong> 
                                <?php echo $data['unique_ips'] ?? 0; ?>
                            </div>
                        </div>
                        
                        <?php if (!empty($decision['reason'])): ?>
                        <div class="ai-response">
                            <h4><i class="fas fa-robot"></i> Решение ИИ по безопасности</h4>
                            <p><?php echo htmlspecialchars($decision['reason']); ?></p>
                            <?php if (!empty($decision['security_recommendations'])): ?>
                                <div style="margin-top: 8px;">
                                    <strong>Рекомендации по безопасности:</strong>
                                    <ul style="margin: 5px 0 0 20px;">
                                        <?php foreach ($decision['security_recommendations'] as $recommendation): ?>
                                            <li><?php echo htmlspecialchars($recommendation); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>
                        </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($data['threats'])): ?>
                        <details style="margin-top: 15px;">
                            <summary style="cursor: pointer; color: #1e3c72; font-weight: bold;">
                                <i class="fas fa-exclamation-triangle"></i> Детали угроз безопасности (<?php echo count($data['threats']); ?>)
                            </summary>
                            <div style="margin-top: 10px;">
                                <?php foreach (array_slice($data['threats'], 0, 5) as $i => $threat): ?>
                                <div style="background: rgba(220, 53, 69, 0.1); padding: 12px; margin: 8px 0; border-radius: 8px; border-left: 4px solid #dc3545;">
                                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                        <strong><code class="ip-address"><?php echo $threat['ip']; ?></code></strong>
                                        <span class="threat-score 
                                            <?php 
                                            if ($threat['threat_score'] >= 80) echo 'threat-critical';
                                            elseif ($threat['threat_score'] >= 60) echo 'threat-high';
                                            elseif ($threat['threat_score'] >= 40) echo 'threat-medium';
                                            else echo 'threat-low';
                                            ?>">
                                            <?php echo $threat['threat_score']; ?>/100
                                        </span>
                                    </div>
                                    <div style="font-size: 0.9rem; color: #495057;">
                                        <div><strong>Тип угрозы:</strong> <?php echo implode(', ', $threat['threat_types'] ?? []); ?></div>
                                        <div><strong>События:</strong> <?php echo $threat['stats']['events']; ?> | <strong>Блокировок:</strong> <?php echo $threat['stats']['blocked_attempts']; ?></div>
                                        <div><strong>Причины:</strong> <?php echo implode(', ', $threat['reasons']); ?></div>
                                        <?php if (!empty($threat['risk_factors'])): ?>
                                        <div><strong>Факторы риска:</strong> <?php echo implode(', ', $threat['risk_factors']); ?></div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <?php endforeach; ?>
                                <?php if (count($data['threats']) > 5): ?>
                                <div style="text-align: center; margin-top: 10px;">
                                    <em>... и еще <?php echo count($data['threats']) - 5; ?> угроз</em>
                                </div>
                                <?php endif; ?>
                            </div>
                        </details>
                        <?php endif; ?>
                        
                        <div style="text-align: right; margin-top: 10px; font-size: 0.8rem; color: #6c757d;">
                            <i class="fas fa-mouse"></i> Нажмите для подробной информации
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
            </div>

            <!-- Заблокированные IP адреса -->
            <div class="card">
                <h3><i class="fas fa-ban"></i> Заблокированные IP адреса по безопасности</h3>
                <?php if (empty($blocked_ips)): ?>
                    <div class="empty-state">
                        <i class="fas fa-check-circle"></i>
                        <h3>Нет заблокированных IP</h3>
                        <p>Все IP адреса в настоящее время разрешены</p>
                    </div>
                <?php else: ?>
                <div class="table-container">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>IP адрес</th>
                                <th>Тип угрозы</th>
                                <th>Серьезность</th>
                                <th>Причина</th>
                                <th>Заблокирован</th>
                                <th>Истекает</th>
                                <th>Метод</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($blocked_ips as $blocked): ?>
                            <tr class="<?php echo ($blocked['current_status'] === 'expired') ? 'table-secondary' : ''; ?>">
                                <td><code class="ip-address"><?php echo htmlspecialchars($blocked['ip_address']); ?></code></td>
                                <td>
                                    <span class="badge 
                                        <?php 
                                        switch($blocked['threat_type']) {
                                            case 'ssh_bruteforce': echo 'critical'; break;
                                            case 'port_scan': echo 'high'; break;
                                            case 'ddos': echo 'critical'; break;
                                            default: echo 'medium';
                                        }
                                        ?>">
                                        <?php echo strtoupper(str_replace(['_', ','], [' ', ', '], $blocked['threat_type'])); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge <?php echo $blocked['severity']; ?>">
                                        <?php echo strtoupper($blocked['severity']); ?>
                                    </span>
                                </td>
                                <td style="max-width: 300px;">
                                    <span title="<?php echo htmlspecialchars($blocked['reason']); ?>">
                                        <?php echo htmlspecialchars(mb_substr($blocked['reason'], 0, 50)); ?>
                                        <?php if (mb_strlen($blocked['reason']) > 50) echo '...'; ?>
                                    </span>
                                </td>
                                <td><?php echo date('d.m H:i', strtotime($blocked['blocked_at'])); ?></td>
                                <td>
                                    <?php if ($blocked['expires_at']): ?>
                                        <?php 
                                        $expires = strtotime($blocked['expires_at']);
                                        $now = time();
                                        if ($expires > $now) {
                                            $remaining = $expires - $now;
                                            if ($remaining > 3600) {
                                                echo round($remaining / 3600, 1) . 'ч';
                                            } else {
                                                echo round($remaining / 60) . 'мин';
                                            }
                                        } else {
                                            echo '<span class="badge low">Истек</span>';
                                        }
                                        ?>
                                    <?php else: ?>
                                        <span class="badge critical">Навсегда</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge 
                                        <?php 
                                        switch($blocked['block_method']) {
                                            case 'ufw': echo 'critical'; break;
                                            case 'iptables': echo 'high'; break;
                                            default: echo 'low';
                                        }
                                        ?>">
                                        <?php echo strtoupper($blocked['block_method']); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if ($blocked['current_status'] === 'active'): ?>
                                    <button class="btn danger" style="padding: 8px 16px; font-size: 0.8rem;" 
                                            onclick="unblockSecurityIP('<?php echo $blocked['ip_address']; ?>')">
                                        <i class="fas fa-unlock"></i> Разблокировать
                                    </button>
                                    <?php else: ?>
                                        <span class="badge low">Истек</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Модальное окно деталей анализа безопасности -->
    <div class="modal-overlay" id="securityModal">
        <div class="modal">
            <div class="modal-header">
                <div class="modal-title">
                    <i class="fas fa-shield-alt"></i>
                    Детальный анализ безопасности
                </div>
                <button class="modal-close" onclick="hideSecurityModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body" id="securityModalContent">
                <div style="text-align: center; padding: 40px;">
                    <div class="loading"></div>
                    <p>Загрузка данных безопасности...</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Глобальные переменные
        let isAnalyzing = false;
        let autoRefreshInterval = null;
        const models = <?php echo json_encode($models); ?>;

        // Функции уведомлений
        function showAlert(message, type = 'success', duration = 5000) {
            const alerts = document.getElementById('alerts');
            const alert = document.createElement('div');
            alert.className = `alert ${type}`;
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-20px)';
            alert.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : (type === 'error' ? 'exclamation-triangle' : 'info-circle')}"></i>
                ${message}
            `;
            
            alerts.appendChild(alert);
            
            // Анимация появления
            setTimeout(() => {
                alert.style.opacity = '1';
                alert.style.transform = 'translateY(0)';
                alert.style.transition = 'all 0.3s ease';
            }, 10);
            
            // Автоматическое удаление
            setTimeout(() => {
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-20px)';
                setTimeout(() => {
                    if (alerts.contains(alert)) {
                        alerts.removeChild(alert);
                    }
                }, 300);
            }, duration);
        }

        // Изменение AI модели
        async function changeAIModel() {
            const select = document.getElementById('aiModelSelect');
            const selectedModel = select.value;
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=change_model&model=${encodeURIComponent(selectedModel)}`
                });

                const data = await response.json();
                
                if (data.success) {
                    updateModelInfo(selectedModel);
                    showAlert(`🤖 Модель изменена на: ${models[selectedModel].name}`, 'success');
                } else {
                    showAlert(`❌ Ошибка смены модели: ${data.error}`, 'error');
                }
            } catch (error) {
                showAlert(`❌ Ошибка сети: ${error.message}`, 'error');
            }
        }

        // Обновление информации о модели
        function updateModelInfo(modelKey) {
            const model = models[modelKey];
            if (!model) return;
            
            const modelInfo = document.getElementById('modelInfo');
            modelInfo.className = `model-info ${model.category}`;
            
            const recommended = model.recommended ? 
                '<span style="color: #f39c12; margin-left: 8px;"><i class="fas fa-star"></i> Рекомендуется для безопасности</span>' : '';
            
            modelInfo.innerHTML = `
                <div>
                    <strong>${model.name}</strong>
                    ${recommended}
                </div>
                <div style="margin: 8px 0; color: #6c757d;">
                    ${model.description}
                </div>
                <div class="model-stats">
                    <div class="model-stat">💰 ${model.price}</div>
                    <div class="model-stat">⚡ ${model.speed}</div>
                    <div class="model-stat">⭐ ${model.quality}</div>
                </div>
            `;
        }

        // Запуск анализа безопасности
        async function runSecurityAnalysis() {
            if (isAnalyzing) return;
            
            isAnalyzing = true;
            const btn = event.target;
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<div class="loading"></div> Анализирую логи безопасности...';
            btn.disabled = true;

            const selectedModel = document.getElementById('aiModelSelect').value;

            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=run_security_analysis&ai_model=${encodeURIComponent(selectedModel)}`
                });

                const data = await response.json();
                
                if (data.success) {
                    const result = data.data;
                    const decision = result.ai_decision;
                    const modelUsed = result.ai_model_used || selectedModel;
                    const modelName = models[modelUsed]?.name || modelUsed;
                    
                    let alertType = 'success';
                    let icon = '✅';
                    
                    if (decision.decision === 'block') {
                        alertType = 'error';
                        icon = '🚫';
                    } else if (decision.decision === 'monitor') {
                        alertType = 'info';
                        icon = '👁️';
                    } else if (decision.decision === 'alert') {
                        alertType = 'info';
                        icon = '🚨';
                    }
                    
                    showAlert(`${icon} Анализ безопасности завершен с моделью <strong>${modelName}</strong>!<br>
                              ИИ принял решение: <strong>${decision.decision.toUpperCase()}</strong> (точность: ${decision.confidence}%)<br>
                              Найдено угроз: ${result.threat_count}, Заблокировано IP: ${result.blocked_ips_count}`, alertType, 8000);
                    
                    // Обновляем страницу через 2 секунды
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showAlert(`❌ Ошибка анализа: ${data.error}`, 'error', 8000);
                }
            } catch (error) {
                showAlert(`❌ Ошибка сети: ${error.message}`, 'error', 8000);
                console.error('Security analysis error:', error);
            } finally {
                btn.innerHTML = originalHtml;
                btn.disabled = false;
                isAnalyzing = false;
            }
        }

        // Обновление статистики безопасности
        async function loadSecurityStats() {
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'action=get_security_stats'
                });

                const data = await response.json();
                
                if (data.success) {
                    showAlert('📊 Статистика безопасности обновлена');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(`❌ Ошибка обновления: ${data.error}`, 'error');
                }
            } catch (error) {
                showAlert(`❌ Ошибка сети: ${error.message}`, 'error');
            }
        }

        // Разблокировка IP
        async function unblockSecurityIP(ip) {
            if (!confirm(`Разблокировать IP адрес ${ip}?\n\nЭто действие удалит IP из всех методов блокировки (UFW, iptables, база данных).`)) {
                return;
            }

            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=unblock_security_ip&ip=${encodeURIComponent(ip)}`
                });

                const data = await response.json();
                
                if (data.success) {
                    showAlert(`🔓 IP ${ip} успешно разблокирован<br>Выполнено действий: ${data.data.actions.length}`, 'success');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showAlert(`❌ Ошибка разблокировки: ${data.error}`, 'error');
                }
            } catch (error) {
                showAlert(`❌ Ошибка сети: ${error.message}`, 'error');
                console.error('Unblock error:', error);
            }
        }

        // Показать детали анализа безопасности
        async function showSecurityDetails(analysisId) {
            const modal = document.getElementById('securityModal');
            const content = document.getElementById('securityModalContent');
            
            // Показываем модальное окно
            modal.style.display = 'flex';
            content.innerHTML = `
                <div style="text-align: center; padding: 40px;">
                    <div class="loading"></div>
                    <p>Загружаю детальную информацию о безопасности...</p>
                </div>
            `;
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=get_security_details&analysis_id=${analysisId}`
                });

                const data = await response.json();
                
                if (data.success) {
                    const analysis = data.data;
                    const analysisData = analysis.analysis_data;
                    const aiDecision = analysis.ai_decision;
                    const aiModel = models[analysis.ai_model] || { name: analysis.ai_model || 'Неизвестная' };
                    
                    let html = `
                        <div style="margin-bottom: 25px;">
                            <h4><i class="fas fa-shield-alt"></i> Общая информация о безопасности</h4>
                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 10px;">
                                <div class="stat-item info">
                                    <div class="stat-number">${analysisData.total_events || 0}</div>
                                    <div class="stat-label">События безопасности</div>
                                </div>
                                <div class="stat-item critical">
                                    <div class="stat-number">${analysisData.threats.length}</div>
                                    <div class="stat-label">Угроз найдено</div>
                                </div>
                                <div class="stat-item high">
                                    <div class="stat-number">${analysis.threat_level}/5</div>
                                    <div class="stat-label">Уровень угрозы</div>
                                </div>
                                <div class="stat-item medium">
                                    <div class="stat-number">${analysisData.unique_ips || 0}</div>
                                    <div class="stat-label">Уникальных IP</div>
                                </div>
                            </div>
                            <div style="margin-top: 15px; text-align: center;">
                                <span class="ai-model-badge" style="font-size: 0.9rem; padding: 8px 16px;">
                                    <i class="fas fa-brain"></i> Использована модель: ${aiModel.name}
                                </span>
                            </div>
                            <div style="margin-top: 10px; font-size: 0.9rem; color: #6c757d;">
                                <strong>Источники логов:</strong> ${(analysisData.log_sources || []).join(', ')}
                            </div>
                        </div>
                        
                        <div class="ai-response" style="margin: 20px 0;">
                            <h4><i class="fas fa-robot"></i> Решение ИИ по безопасности</h4>
                            <div style="display: flex; gap: 15px; align-items: center; margin-bottom: 10px;">
                                <span class="decision-badge decision-${aiDecision.decision}">
                                    ${aiDecision.decision.toUpperCase()}
                                </span>
                                <span class="badge ${aiDecision.confidence >= 80 ? 'critical' : aiDecision.confidence >= 60 ? 'high' : 'medium'}">
                                    Уверенность: ${aiDecision.confidence}%
                                </span>
                            </div>
                            <p><strong>Обоснование:</strong> ${aiDecision.reason}</p>
                            ${aiDecision.security_recommendations && aiDecision.security_recommendations.length > 0 ? `
                                <div style="margin-top: 10px;">
                                    <strong>Рекомендации по безопасности:</strong>
                                    <ul style="margin-left: 20px;">
                                        ${aiDecision.security_recommendations.map(rec => `<li>${rec}</li>`).join('')}
                                    </ul>
                                </div>
                            ` : ''}
                        </div>
                        
                        ${analysisData.threats.length > 0 ? `
                            <div style="margin: 25px 0;">
                                <h4><i class="fas fa-exclamation-triangle"></i> Обнаруженные угрозы безопасности</h4>
                                <div class="table-container" style="max-height: 400px;">
                                    <table class="table">
                                        <thead>
                                            <tr>
                                                <th>IP адрес</th>
                                                <th>Оценка</th>
                                                <th>Тип угрозы</th>
                                                <th>События</th>
                                                <th>Блокировок</th>
                                                <th>Серьезность</th>
                                                <th>Причины</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${analysisData.threats.map(threat => `
                                                <tr>
                                                    <td><code class="ip-address">${threat.ip}</code></td>
                                                    <td>
                                                        <span class="threat-score ${
                                                            threat.threat_score >= 80 ? 'threat-critical' :
                                                            threat.threat_score >= 60 ? 'threat-high' :
                                                            threat.threat_score >= 40 ? 'threat-medium' : 'threat-low'
                                                        }">
                                                            ${threat.threat_score}/100
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <span class="badge ${
                                                            threat.severity === 'critical' ? 'critical' :
                                                            threat.severity === 'high' ? 'high' :
                                                            threat.severity === 'medium' ? 'medium' : 'low'
                                                        }">
                                                            ${(threat.threat_types || []).join(', ')}
                                                        </span>
                                                    </td>
                                                    <td>${threat.stats.events}</td>
                                                    <td>${threat.stats.blocked_attempts}</td>
                                                    <td>
                                                        <span class="badge ${threat.severity}">
                                                            ${threat.severity.toUpperCase()}
                                                        </span>
                                                    </td>
                                                    <td style="max-width: 300px;">
                                                        <small>${threat.reasons.join('; ')}</small>
                                                    </td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        ` : ''}
                        
                        ${analysis.actions_taken ? `
                            <div style="margin: 25px 0;">
                                <h4><i class="fas fa-cogs"></i> Выполненные действия безопасности</h4>
                                <div class="log-entry">
                                    ${analysis.actions_taken.split(';').map(action => 
                                        action.trim() ? `<div>• ${action.trim()}</div>` : ''
                                    ).join('')}
                                </div>
                            </div>
                        ` : ''}
                    `;
                    
                    content.innerHTML = html;
                } else {
                    content.innerHTML = `
                        <div class="alert error">
                            <i class="fas fa-exclamation-triangle"></i>
                            Ошибка загрузки: ${data.error}
                        </div>
                    `;
                }
            } catch (error) {
                content.innerHTML = `
                    <div class="alert error">
                        <i class="fas fa-exclamation-triangle"></i>
                        Ошибка сети: ${error.message}
                    </div>
                `;
                console.error('Security details error:', error);
            }
        }

        // Скрыть модальное окно
        function hideSecurityModal() {
            document.getElementById('securityModal').style.display = 'none';
        }

        // Показать информацию о системе безопасности
        function showSecurityInfo() {
            const currentModel = document.getElementById('aiModelSelect').value;
            const modelInfo = models[currentModel];
            
            const info = `
                🛡️ AI Security Analyzer v3.0
                
                📊 Конфигурация безопасности:
                • Активная модель: ${modelInfo.name}
                • Категория: ${modelInfo.category.toUpperCase()}
                • Стоимость: ${modelInfo.price}
                • Скорость: ${modelInfo.speed}
                • Качество: ${modelInfo.quality}
                • Интервал анализа: <?php echo $config['analysis_interval']/60; ?> минут
                • Максимум строк лога: <?php echo number_format($config['max_log_lines']); ?>
                
                🔍 Анализируемые логи:
                <?php foreach ($logStatus as $logName => $status): ?>
                • <?php echo $status['path']; ?> (<?php echo $status['exists'] && $status['readable'] ? 'доступен' : 'недоступен'; ?>)
                <?php endforeach; ?>
                
                🚨 Пороги угроз:
                • SSH попытки: <?php echo $config['threat_threshold']['failed_ssh_attempts']; ?>
                • Сканирование портов: <?php echo $config['threat_threshold']['port_scan_threshold']; ?>
                • UFW блокировки/час: <?php echo $config['threat_threshold']['blocked_attempts_hour']; ?>
                • Ошибки ядра: <?php echo $config['threat_threshold']['kernel_errors_threshold']; ?>
                • DDoS подозрения: <?php echo $config['threat_threshold']['ddos_requests_threshold']; ?>
                
                🛡️ Методы блокировки:
                • UFW (Uncomplicated Firewall)
                • iptables (системный уровень)
                • База данных (учет и мониторинг)
                
                🤖 Доступно AI моделей: <?php echo count($models); ?>
                • Бесплатных: <?php echo count(array_filter($models, fn($m) => $m['category'] === 'free')); ?>
                • Бюджетных: <?php echo count(array_filter($models, fn($m) => $m['category'] === 'budget')); ?>
                • Премиум: <?php echo count(array_filter($models, fn($m) => $m['category'] === 'premium')); ?>
                • Новейших: <?php echo count(array_filter($models, fn($m) => $m['category'] === 'newest')); ?>
                
                ⚙️ База данных безопасности:
                • Хост: <?php echo $db_config['host']; ?>
                • БД: <?php echo $db_config['dbname']; ?>
                • Пользователь: <?php echo $db_config['username']; ?>
                
                📈 Статистика за все время:
                • Всего анализов: <?php echo $stats['analysis']['total_analysis'] ?? 0; ?>
                • Активных блокировок: <?php echo $stats['blocks']['active_blocks'] ?? 0; ?>
                • Средний уровень угрозы: <?php echo number_format($stats['analysis']['avg_threat_level'] ?? 0, 2); ?>/5
                • События безопасности: <?php echo $stats['analysis']['total_security_events'] ?? 0; ?>
            `;
            
            alert(info);
        }

        // Обработка клавиатурных сокращений
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 'r': // Ctrl+R - запуск анализа
                        if (!isAnalyzing) {
                            e.preventDefault();
                            runSecurityAnalysis();
                        }
                        break;
                    case 'u': // Ctrl+U - обновление статистики
                        e.preventDefault();
                        loadSecurityStats();
                        break;
                    case 'i': // Ctrl+I - информация о системе
                        e.preventDefault();
                        showSecurityInfo();
                        break;
                    case 'm': // Ctrl+M - смена модели
                        e.preventDefault();
                        document.getElementById('aiModelSelect').focus();
                        break;
                }
            }
            
            // ESC - закрытие модальных окон
            if (e.key === 'Escape') {
                hideSecurityModal();
            }
        });

        // Закрытие модального окна по клику вне его
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('modal-overlay')) {
                hideSecurityModal();
            }
        });

        // Инициализация при загрузке страницы
        document.addEventListener('DOMContentLoaded', function() {
            // Показываем приветствие
            setTimeout(() => {
                const currentModel = models[document.getElementById('aiModelSelect').value];
                showAlert(`🛡️ AI Security Analyzer система готова к работе с моделью <strong>${currentModel.name}</strong>!<br>
                          Используйте Ctrl+R для быстрого анализа безопасности, Ctrl+M для смены модели`, 'info', 6000);
            }, 1000);
            
            // Запускаем автообновление
            setTimeout(() => {
                startAutoRefresh();
            }, 5000);
            
            // Проверяем доступность логов
            checkLogAvailability();

            // Устанавливаем обработчик на селект модели
            document.getElementById('aiModelSelect').addEventListener('change', function() {
                updateModelInfo(this.value);
            });
        });

        // Проверка доступности логов
        function checkLogAvailability() {
            const logStatus = <?php echo json_encode($logStatus); ?>;
            const unavailableLogs = Object.values(logStatus).filter(log => !log.exists || !log.readable);
            
            if (unavailableLogs.length > 0) {
                showAlert(`⚠️ Внимание: ${unavailableLogs.length} логов недоступно. Анализ безопасности может быть неполным.`, 'error', 8000);
            }
        }

        // Автообновление статистики
        function startAutoRefresh() {
            if (autoRefreshInterval) return;
            
            autoRefreshInterval = setInterval(async () => {
                try {
                    const response = await fetch('', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: 'action=get_security_stats'
                    });
                    
                    const data = await response.json();
                    if (data.success) {
                        // Тихое обновление некоторых элементов без перезагрузки
                        updateSecurityStatsDisplay(data.data);
                    }
                } catch (error) {
                    console.warn('Auto-refresh failed:', error);
                }
            }, 90000); // Каждые 1.5 минуты
        }

        // Обновление элементов статистики без перезагрузки
        function updateSecurityStatsDisplay(stats) {
            // Обновляем только числовые значения статистики
            const elements = document.querySelectorAll('.stat-number');
            elements.forEach(el => {
                el.classList.add('blink');
                setTimeout(() => el.classList.remove('blink'), 2000);
            });
        }

        // Копирование IP в буфер обмена
        async function copyToClipboard(text) {
            try {
                await navigator.clipboard.writeText(text);
                showAlert(`📋 IP ${text} скопирован в буфер обмена`, 'success', 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
                showAlert('❌ Не удалось скопировать в буфер', 'error', 2000);
            }
        }

        // Добавляем обработчики для копирования IP
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('ip-address')) {
                copyToClipboard(e.target.textContent);
            }
        });

        // Обработка ошибок
        window.addEventListener('error', function(e) {
            console.error('JavaScript error:', e.error);
            showAlert('❌ Произошла ошибка JavaScript. Обновите страницу.', 'error');
        });

        window.addEventListener('unhandledrejection', function(e) {
            console.error('Unhandled promise rejection:', e.reason);
            showAlert('❌ Ошибка сетевого запроса. Проверьте подключение.', 'error');
        });
    </script>
</body>
</html>