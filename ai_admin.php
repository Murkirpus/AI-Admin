<?php
/**
 * AI Admin - Система анализа логов с искусственным интеллектом
 * Автоматическое выявление угроз и принятие решений
 * Версия: 2.1 с поддержкой множественных AI моделей
 * Поддержка: MariaDB/MySQL
 */

// Отключаем отображение ошибок в production
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('memory_limit', '256M');
ini_set('max_execution_time', 60);

// Запуск сессии для сохранения выбранной модели
session_start();

// Конфигурация базы данных MariaDB
$db_config = [
    'host' => 'localhost',
    'dbname' => 'ai_admin',
    'username' => 'ai_admin',
    'password' => 'ai_admin', // Укажите ваш пароль
    'charset' => 'utf8mb4'
];

// Основная конфигурация
$config = [
    'openrouter_api_key' => 'sk-or-v1-',
    'log_paths' => [
        '/var/log/nginx/access.log',
        //'/var/log/apache2/access.log',
        // Добавьте другие пути к логам
    ],
    'analysis_interval' => 300, // 5 минут
    'threat_threshold' => [
        'requests_per_minute' => 100,
        'failed_requests_ratio' => 0.3,
        'unique_uas_threshold' => 5,
        'suspicious_patterns' => ['bot', 'crawler', 'scan', 'exploit', 'hack', 'attack']
    ],
    'default_ai_model' => 'qwen/qwen-2.5-72b-instruct:free',
    'block_duration' => 3600, // 1 час
    'max_log_lines' => 2000 // Максимум строк лога для анализа
];

// Функция получения доступных AI моделей
function getOpenRouterModels() {
    return [
        // 🆓 БЕСПЛАТНЫЕ МОДЕЛИ
        'qwen/qwen-2.5-72b-instruct:free' => [
            'name' => '🆓 Qwen 2.5 72B Instruct',
            'description' => 'Мощная бесплатная модель от Alibaba',
            'price' => 'БЕСПЛАТНО',
            'cost_1000' => '$0.00',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'free'
        ],
        
        'meta-llama/llama-3.3-70b-instruct:free' => [
            'name' => '🆓 Llama 3.3 70B Instruct',
            'description' => 'Отличная бесплатная модель от Meta',
            'price' => 'БЕСПЛАТНО',
            'cost_1000' => '$0.00',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'free'
        ],
        
        'deepseek/deepseek-r1:free' => [
            'name' => '🆓 DeepSeek R1',
            'description' => 'Новейшая бесплатная модель с рассуждениями',
            'price' => 'БЕСПЛАТНО',
            'cost_1000' => '$0.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'free'
        ],
        
        'mistralai/mistral-nemo:free' => [
            'name' => '🆓 Mistral Nemo',
            'description' => 'Быстрая и качественная бесплатная модель',
            'price' => 'БЕСПЛАТНО',
            'cost_1000' => '$0.00',
            'speed' => '⚡⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => false,
            'category' => 'free'
        ],

        // 💰 БЮДЖЕТНЫЕ МОДЕЛИ
        'deepseek/deepseek-chat' => [
            'name' => '💰 DeepSeek Chat',
            'description' => 'Отличное качество по низкой цене',
            'price' => '$0.14 / $0.28 за 1М токенов',
            'cost_1000' => '$0.42',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'budget'
        ],
        
        'openai/gpt-4.1-nano' => [
            'name' => '💰 GPT-4.1 Nano',
            'description' => 'Новейшая быстрая и дешевая модель OpenAI',
            'price' => '$0.10 / $0.40 за 1М токенов',
            'cost_1000' => '$0.50',
            'speed' => '⚡⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'budget'
        ],
        
        'google/gemini-2.5-flash' => [
            'name' => '💰 Gemini 2.5 Flash',
            'description' => 'СУПЕР ПОПУЛЯРНАЯ! Топ модель по цене/качеству',
            'price' => '$0.075 / $0.30 за 1М токенов',
            'cost_1000' => '$0.375',
            'speed' => '⚡⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'budget'
        ],
        
        'qwen/qwen-2.5-72b-instruct' => [
            'name' => '💰 Qwen 2.5 72B Instruct',
            'description' => 'Мощная модель по доступной цене',
            'price' => '$0.40 / $1.20 за 1М токенов',
            'cost_1000' => '$1.60',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'budget'
        ],
        
        'meta-llama/llama-3.3-70b-instruct' => [
            'name' => '💰 Llama 3.3 70B Instruct',
            'description' => 'Отличная модель от Meta, хорошая цена',
            'price' => '$0.59 / $0.79 за 1М токенов',
            'cost_1000' => '$1.38',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => false,
            'category' => 'budget'
        ],

        // 🥇 ПРЕМИУМ МОДЕЛИ
        'google/gemini-2.5-pro' => [
            'name' => '🥇 Gemini 2.5 Pro',
            'description' => 'Топовая модель Google с отличными возможностями',
            'price' => '$1.25 / $5.00 за 1М токенов',
            'cost_1000' => '$6.25',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'premium'
        ],
        
        'openai/gpt-4o' => [
            'name' => '🥇 GPT-4o',
            'description' => 'Мультимодальная модель от OpenAI',
            'price' => '$2.50 / $10.00 за 1М токенов',
            'cost_1000' => '$12.50',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => false,
            'category' => 'premium'
        ],
        
        'openai/gpt-4o-mini' => [
            'name' => '🥇 GPT-4o Mini',
            'description' => 'Быстрая и качественная мини-версия',
            'price' => '$0.15 / $0.60 за 1М токенов',
            'cost_1000' => '$0.75',
            'speed' => '⚡⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'premium'
        ],
        
        'anthropic/claude-3.5-sonnet' => [
            'name' => '🥇 Claude 3.5 Sonnet',
            'description' => 'Топовая модель от Anthropic для текста и кода',
            'price' => '$3.00 / $15.00 за 1М токенов',
            'cost_1000' => '$18.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => false,
            'category' => 'premium'
        ],
        
        'anthropic/claude-3-haiku' => [
            'name' => '🥇 Claude 3 Haiku',
            'description' => 'Быстрая и экономичная версия Claude',
            'price' => '$0.25 / $1.25 за 1М токенов',
            'cost_1000' => '$1.50',
            'speed' => '⚡⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'premium'
        ],

        // 🚀 НОВЕЙШИЕ И ПОПУЛЯРНЫЕ МОДЕЛИ
        'anthropic/claude-3.7-sonnet' => [
            'name' => '🚀 Claude 3.7 Sonnet',
            'description' => 'Новейшая модель Anthropic с улучшенными возможностями',
            'price' => '$3.00 / $15.00 за 1М токенов',
            'cost_1000' => '$18.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'newest'
        ],
        
        'anthropic/claude-sonnet-4' => [
            'name' => '🚀 Claude Sonnet 4',
            'description' => 'Революционная Claude 4 с мгновенными ответами',
            'price' => '$5.00 / $25.00 за 1М токенов',
            'cost_1000' => '$30.00',
            'speed' => '⚡⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'newest'
        ],
        
        'anthropic/claude-opus-4' => [
            'name' => '🚀 Claude Opus 4',
            'description' => 'Топовая модель Claude 4 с максимальными возможностями',
            'price' => '$15.00 / $75.00 за 1М токенов',
            'cost_1000' => '$90.00',
            'speed' => '⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => false,
            'category' => 'newest'
        ],
        
        'x-ai/grok-3' => [
            'name' => '🚀 Grok 3.0',
            'description' => 'Мощная модель xAI с думающим режимом',
            'price' => '$2.50 / $12.50 за 1М токенов',
            'cost_1000' => '$15.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'newest'
        ],
        
        'x-ai/grok-4' => [
            'name' => '🚀 Grok 4.0',
            'description' => 'Новейшая модель xAI с продвинутыми рассуждениями',
            'price' => '$4.00 / $20.00 за 1М токенов',
            'cost_1000' => '$24.00',
            'speed' => '⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'newest'
        ],
        
        'deepseek/deepseek-r1' => [
            'name' => '🚀 DeepSeek R1',
            'description' => 'Революционная модель с рассуждениями. Конкурент GPT-o1',
            'price' => '$0.55 / $2.19 за 1М токенов',
            'cost_1000' => '$2.74',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'newest'
        ],
        
        'mistralai/mistral-large-2407' => [
            'name' => '🚀 Mistral Large 2407',
            'description' => 'Флагманская модель Mistral с отличным качеством',
            'price' => '$3.00 / $9.00 за 1М токенов',
            'cost_1000' => '$12.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => true,
            'category' => 'newest'
        ],
        
        'x-ai/grok-2-1212' => [
            'name' => '🚀 Grok 2.0',
            'description' => 'Модель от xAI с юмором и актуальными данными',
            'price' => '$2.00 / $10.00 за 1М токенов',
            'cost_1000' => '$12.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => false,
            'category' => 'newest'
        ],
        
        'openai/o1-mini' => [
            'name' => '🚀 GPT-o1 Mini',
            'description' => 'Модель с усиленными рассуждениями от OpenAI',
            'price' => '$3.00 / $12.00 за 1М токенов',
            'cost_1000' => '$15.00',
            'speed' => '⚡⚡',
            'quality' => '⭐⭐⭐⭐⭐',
            'recommended' => false,
            'category' => 'newest'
        ],
        
        'cohere/command-r-plus' => [
            'name' => '🚀 Command R+',
            'description' => 'Мощная модель Cohere для RAG и сложных задач',
            'price' => '$3.00 / $15.00 за 1М токенов',
            'cost_1000' => '$18.00',
            'speed' => '⚡⚡⚡',
            'quality' => '⭐⭐⭐⭐',
            'recommended' => false,
            'category' => 'newest'
        ]
    ];
}

// Получение текущей выбранной модели
function getCurrentAIModel($config) {
    // Проверяем AJAX запрос
    if (isset($_POST['ai_model'])) {
        $_SESSION['selected_ai_model'] = $_POST['ai_model'];
        return $_POST['ai_model'];
    }
    
    // Проверяем сессию
    if (isset($_SESSION['selected_ai_model'])) {
        return $_SESSION['selected_ai_model'];
    }
    
    // Возвращаем модель по умолчанию
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
    
    // Создаем таблицы если их нет
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS log_analysis (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            analysis_data LONGTEXT,
            ai_decision LONGTEXT,
            threat_level TINYINT,
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
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) UNIQUE,
            reason TEXT,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NULL,
            status ENUM('active', 'expired', 'removed') DEFAULT 'active',
            block_method ENUM('iptables', 'htaccess', 'database') DEFAULT 'database',
            INDEX idx_ip_status (ip_address, status),
            INDEX idx_blocked_at (blocked_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS threat_patterns (
            id INT AUTO_INCREMENT PRIMARY KEY,
            pattern_type VARCHAR(100),
            pattern_value VARCHAR(255),
            threat_score TINYINT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            detection_count INT DEFAULT 0,
            INDEX idx_pattern_type (pattern_type),
            INDEX idx_threat_score (threat_score)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS ai_decisions_log (
            id INT AUTO_INCREMENT PRIMARY KEY,
            analysis_id INT,
            decision_type ENUM('block', 'monitor', 'ignore'),
            confidence_score TINYINT,
            ai_reasoning TEXT,
            executed_actions JSON,
            processing_time_ms INT,
            ai_model VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (analysis_id) REFERENCES log_analysis(id) ON DELETE CASCADE,
            INDEX idx_decision_type (decision_type),
            INDEX idx_created_at (created_at),
            INDEX idx_ai_model (ai_model)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS performance_stats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            date_hour DATETIME,
            total_requests INT DEFAULT 0,
            blocked_requests INT DEFAULT 0,
            threats_detected INT DEFAULT 0,
            ai_processing_time_avg DECIMAL(10,2),
            ai_model VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_date_hour_model (date_hour, ai_model),
            INDEX idx_date_hour (date_hour),
            INDEX idx_ai_model (ai_model)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");
    
} catch (PDOException $e) {
    die("Ошибка подключения к MariaDB: " . $e->getMessage());
}

// Класс анализатора логов с ИИ
class AILogAnalyzer {
    private $config;
    private $pdo;
    
    public function __construct($config, $pdo) {
        $this->config = $config;
        $this->pdo = $pdo;
    }
    
    // Основная функция анализа логов
    public function analyzeRecentLogs($selectedModel = null) {
        $startTime = microtime(true);
        $aiModel = $selectedModel ?: getCurrentAIModel($this->config);
        
        try {
            $logData = $this->parseRecentLogs();
            $analysisResult = $this->performThreatAnalysis($logData);
            $aiDecision = $this->consultAI($analysisResult, $aiModel);
            $executionResult = $this->executeDecision($analysisResult, $aiDecision, $aiModel);
            
            $processingTime = round((microtime(true) - $startTime) * 1000);
            
            // Обновляем время обработки
            $this->pdo->prepare("UPDATE log_analysis SET processing_time_ms = ?, ai_model = ? WHERE id = ?")
                      ->execute([$processingTime, $aiModel, $executionResult['analysis_id']]);
            
            $this->updatePerformanceStats($analysisResult, $processingTime, $aiModel);
            
            return array_merge($executionResult, ['ai_model_used' => $aiModel]);
            
        } catch (Exception $e) {
            error_log("AI Admin Error: " . $e->getMessage());
            throw $e;
        }
    }
    
    // Парсинг последних логов
    private function parseRecentLogs() {
        $currentTime = time();
        $startTime = $currentTime - $this->config['analysis_interval'];
        
        $logEntries = [];
        $ipStats = [];
        $suspiciousActivity = [];
        $totalProcessed = 0;
        
        foreach ($this->config['log_paths'] as $logPath) {
            if (!file_exists($logPath) || !is_readable($logPath)) {
                continue;
            }
            
            $lines = $this->tailFile($logPath, $this->config['max_log_lines']);
            
            foreach ($lines as $line) {
                $entry = $this->parseLogLine($line);
                if (!$entry) continue;
                
                $totalProcessed++;
                
                // Фильтруем по времени (приблизительно)
                $entryTime = $this->parseLogTimestamp($entry['timestamp']);
                if ($entryTime && $entryTime < $startTime) {
                    continue;
                }
                
                $logEntries[] = $entry;
                $ip = $entry['ip'];
                
                // Статистика по IP
                if (!isset($ipStats[$ip])) {
                    $ipStats[$ip] = [
                        'requests' => 0,
                        'failed_requests' => 0,
                        'user_agents' => [],
                        'urls' => [],
                        'status_codes' => [],
                        'methods' => [],
                        'sizes' => []
                    ];
                }
                
                $ipStats[$ip]['requests']++;
                $ipStats[$ip]['status_codes'][] = $entry['status'];
                $ipStats[$ip]['urls'][] = substr($entry['url'], 0, 100); // Ограничиваем длину
                $ipStats[$ip]['methods'][] = $entry['method'];
                $ipStats[$ip]['sizes'][] = intval($entry['size']);
                
                if (!in_array($entry['user_agent'], $ipStats[$ip]['user_agents'])) {
                    $ipStats[$ip]['user_agents'][] = $entry['user_agent'];
                }
                
                if (intval($entry['status']) >= 400) {
                    $ipStats[$ip]['failed_requests']++;
                }
                
                // Поиск подозрительных паттернов
                $this->detectSuspiciousPatterns($entry, $suspiciousActivity);
            }
        }
        
        return [
            'total_entries' => count($logEntries),
            'total_processed' => $totalProcessed,
            'ip_stats' => $ipStats,
            'suspicious_activity' => $suspiciousActivity,
            'analysis_period' => $this->config['analysis_interval'],
            'timestamp' => $currentTime
        ];
    }
    
    // Чтение последних строк файла
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
    
    // Парсинг строки лога
    private function parseLogLine($line) {
        $line = trim($line);
        if (empty($line)) return false;
        
        // Стандартный формат NGINX combined
        $pattern = '/^(\S+) - (\S+) \[(.*?)\] "(\S+) (.*?) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)".*$/';
        
        if (preg_match($pattern, $line, $matches)) {
            return [
                'ip' => $matches[1],
                'remote_user' => $matches[2],
                'timestamp' => $matches[3],
                'method' => $matches[4],
                'url' => $matches[5],
                'protocol' => $matches[6],
                'status' => $matches[7],
                'size' => $matches[8],
                'referer' => $matches[9],
                'user_agent' => $matches[10]
            ];
        }
        
        // Альтернативный формат без кавычек
        $pattern2 = '/^(\S+) - (\S+) \[(.*?)\] (\S+) (.*?) (\S+) (\d+) (\d+) (.*?) (.*)$/';
        if (preg_match($pattern2, $line, $matches)) {
            return [
                'ip' => $matches[1],
                'remote_user' => $matches[2],
                'timestamp' => $matches[3],
                'method' => $matches[4],
                'url' => $matches[5],
                'protocol' => $matches[6],
                'status' => $matches[7],
                'size' => $matches[8],
                'referer' => $matches[9] ?? '-',
                'user_agent' => $matches[10] ?? '-'
            ];
        }
        
        return false;
    }
    
    // Парсинг времени из лога
    private function parseLogTimestamp($timestamp) {
        // Формат: 06/Jan/2024:14:30:15 +0200
        if (preg_match('/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/', $timestamp, $matches)) {
            $months = [
                'Jan' => 1, 'Feb' => 2, 'Mar' => 3, 'Apr' => 4, 'May' => 5, 'Jun' => 6,
                'Jul' => 7, 'Aug' => 8, 'Sep' => 9, 'Oct' => 10, 'Nov' => 11, 'Dec' => 12
            ];
            
            $month = $months[$matches[2]] ?? 1;
            return mktime($matches[4], $matches[5], $matches[6], $month, $matches[1], $matches[3]);
        }
        
        return null;
    }
    
    // Обнаружение подозрительных паттернов
    private function detectSuspiciousPatterns($entry, &$suspiciousActivity) {
        foreach ($this->config['threat_threshold']['suspicious_patterns'] as $pattern) {
            if (stripos($entry['user_agent'], $pattern) !== false || 
                stripos($entry['url'], $pattern) !== false) {
                $suspiciousActivity[] = [
                    'ip' => $entry['ip'],
                    'pattern' => $pattern,
                    'url' => $entry['url'],
                    'user_agent' => $entry['user_agent'],
                    'method' => $entry['method'],
                    'status' => $entry['status']
                ];
            }
        }
        
        // Проверка на сканирование
        $scanPatterns = ['/admin', '/wp-', '.env', '.git', 'phpmyadmin', 'phpinfo', 'eval(', 'base64'];
        foreach ($scanPatterns as $scanPattern) {
            if (stripos($entry['url'], $scanPattern) !== false) {
                $suspiciousActivity[] = [
                    'ip' => $entry['ip'],
                    'pattern' => 'scan_' . $scanPattern,
                    'url' => $entry['url'],
                    'user_agent' => $entry['user_agent'],
                    'method' => $entry['method'],
                    'status' => $entry['status']
                ];
            }
        }
    }
    
    // Анализ угроз
    private function performThreatAnalysis($logData) {
        $threats = [];
        $threatLevel = 0;
        
        foreach ($logData['ip_stats'] as $ip => $stats) {
            $threat = [
                'ip' => $ip,
                'threat_score' => 0,
                'reasons' => [],
                'stats' => $stats,
                'risk_factors' => []
            ];
            
            // Анализ частоты запросов
            $requestsPerMinute = $stats['requests'] / ($this->config['analysis_interval'] / 60);
            if ($requestsPerMinute > $this->config['threat_threshold']['requests_per_minute']) {
                $threat['threat_score'] += 50;
                $threat['reasons'][] = "Высокая частота запросов: " . round($requestsPerMinute, 1) . "/мин";
                $threat['risk_factors'][] = 'high_frequency';
            }
            
            // Анализ соотношения ошибок
            if ($stats['requests'] > 0) {
                $failedRatio = $stats['failed_requests'] / $stats['requests'];
                if ($failedRatio > $this->config['threat_threshold']['failed_requests_ratio']) {
                    $threat['threat_score'] += 30;
                    $threat['reasons'][] = "Высокий процент ошибок: " . round($failedRatio * 100, 1) . "%";
                    $threat['risk_factors'][] = 'high_error_rate';
                }
            }
            
            // Анализ разнообразия User-Agent
            if (count($stats['user_agents']) > $this->config['threat_threshold']['unique_uas_threshold']) {
                $threat['threat_score'] += 20;
                $threat['reasons'][] = "Множественные User-Agent: " . count($stats['user_agents']);
                $threat['risk_factors'][] = 'multiple_user_agents';
            }
            
            // Анализ подозрительных URL
            $suspiciousUrls = 0;
            $adminUrls = 0;
            foreach ($stats['urls'] as $url) {
                if (preg_match('/\.(php|asp|jsp|cgi|pl|py)(\?|$)/i', $url)) {
                    $suspiciousUrls++;
                }
                if (stripos($url, 'admin') !== false || stripos($url, 'wp-') !== false) {
                    $adminUrls++;
                }
            }
            
            if ($suspiciousUrls > 5) {
                $threat['threat_score'] += 25;
                $threat['reasons'][] = "Сканирование скриптов: {$suspiciousUrls} файлов";
                $threat['risk_factors'][] = 'script_scanning';
            }
            
            if ($adminUrls > 3) {
                $threat['threat_score'] += 35;
                $threat['reasons'][] = "Попытки доступа к админке: {$adminUrls}";
                $threat['risk_factors'][] = 'admin_probing';
            }
            
            // Анализ методов запросов
            $postRequests = array_count_values($stats['methods'])['POST'] ?? 0;
            if ($postRequests > 10 && $stats['failed_requests'] > $postRequests * 0.5) {
                $threat['threat_score'] += 40;
                $threat['reasons'][] = "Подозрительные POST запросы: {$postRequests}";
                $threat['risk_factors'][] = 'suspicious_posts';
            }
            
            // Проверка известных вредоносных паттернов
            foreach ($stats['user_agents'] as $ua) {
                if (preg_match('/(sqlmap|nikto|nmap|masscan|zmap)/i', $ua)) {
                    $threat['threat_score'] += 60;
                    $threat['reasons'][] = "Инструмент взлома: " . substr($ua, 0, 50);
                    $threat['risk_factors'][] = 'hacking_tool';
                    break;
                }
            }
            
            // Добавляем в список угроз если превышен порог
            if ($threat['threat_score'] > 30) {
                $threats[] = $threat;
                $threatLevel = max($threatLevel, min(5, floor($threat['threat_score'] / 20)));
            }
        }
        
        // Сортируем по убыванию угрозы
        usort($threats, function($a, $b) {
            return $b['threat_score'] - $a['threat_score'];
        });
        
        return [
            'threats' => array_slice($threats, 0, 20), // Ограничиваем до 20 самых опасных
            'threat_level' => $threatLevel,
            'total_entries' => $logData['total_entries'],
            'total_processed' => $logData['total_processed'],
            'analysis_time' => date('Y-m-d H:i:s'),
            'period_minutes' => $this->config['analysis_interval'] / 60,
            'suspicious_patterns_count' => count($logData['suspicious_activity'])
        ];
    }
    
    // Консультация с ИИ
    private function consultAI($analysisResult, $aiModel) {
        if (empty($analysisResult['threats'])) {
            return [
                'decision' => 'ignore',
                'confidence' => 95,
                'reason' => 'В логах не обнаружено угроз. Активность выглядит нормальной.',
                'recommended_actions' => ['Продолжить мониторинг']
            ];
        }
        
        $prompt = $this->buildAIPrompt($analysisResult);
        
        $data = [
            'model' => $aiModel,
            'messages' => [
                [
                    'role' => 'system',
                    'content' => 'Ты опытный системный администратор и специалист по кибербезопасности. Анализируй данные веб-сервера и принимай решения о блокировке подозрительных IP. Отвечай СТРОГО в JSON формате: {"decision": "block/monitor/ignore", "confidence": число_1_100, "reason": "объяснение_на_русском", "recommended_actions": ["действие1", "действие2"]}'
                ],
                [
                    'role' => 'user',
                    'content' => $prompt
                ]
            ],
            'temperature' => 0.2,
            'max_tokens' => 1000
        ];
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://openrouter.ai/api/v1/chat/completions',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($data),
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $this->config['openrouter_api_key'],
                'HTTP-Referer: ' . ($_SERVER['HTTP_HOST'] ?? 'localhost'),
                'X-Title: AI Admin Security System'
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
                            'reason' => $decision['reason'] ?? 'Решение ИИ',
                            'recommended_actions' => $decision['recommended_actions'] ?? []
                        ];
                    }
                }
                
                // Fallback парсинг если JSON поврежден
                $decision = 'ignore';
                $confidence = 50;
                
                if (stripos($aiResponse, 'block') !== false || stripos($aiResponse, 'заблок') !== false) {
                    $decision = 'block';
                    $confidence = 80;
                } elseif (stripos($aiResponse, 'monitor') !== false || stripos($aiResponse, 'наблюд') !== false) {
                    $decision = 'monitor';
                    $confidence = 70;
                }
                
                return [
                    'decision' => $decision,
                    'confidence' => $confidence,
                    'reason' => substr($aiResponse, 0, 300),
                    'recommended_actions' => []
                ];
            }
        }
        
        // ИИ недоступен - принимаем автоматическое решение
        $maxThreatScore = 0;
        foreach ($analysisResult['threats'] as $threat) {
            $maxThreatScore = max($maxThreatScore, $threat['threat_score']);
        }
        
        if ($maxThreatScore >= 80) {
            return [
                'decision' => 'block',
                'confidence' => 85,
                'reason' => 'Автоматическое решение: обнаружена критическая угроза (оценка: ' . $maxThreatScore . ')',
                'recommended_actions' => ['Немедленная блокировка', 'Дополнительный анализ']
            ];
        } elseif ($maxThreatScore >= 60) {
            return [
                'decision' => 'monitor',
                'confidence' => 75,
                'reason' => 'Автоматическое решение: обнаружена умеренная угроза (оценка: ' . $maxThreatScore . ')',
                'recommended_actions' => ['Усиленный мониторинг', 'Анализ паттернов']
            ];
        }
        
        return [
            'decision' => 'ignore',
            'confidence' => 60,
            'reason' => 'Автоматическое решение: низкий уровень угрозы',
            'recommended_actions' => ['Обычный мониторинг']
        ];
    }
    
    // Формирование промпта для ИИ
    private function buildAIPrompt($analysisResult) {
        $prompt = "🔍 ОТЧЕТ ПО БЕЗОПАСНОСТИ ВЕБ-СЕРВЕРА\n\n";
        $prompt .= "📊 ОБЩАЯ ИНФОРМАЦИЯ:\n";
        $prompt .= "• Период анализа: {$analysisResult['period_minutes']} минут\n";
        $prompt .= "• Обработано записей: {$analysisResult['total_processed']}\n";
        $prompt .= "• Записей в анализе: {$analysisResult['total_entries']}\n";
        $prompt .= "• Уровень угрозы системы: {$analysisResult['threat_level']}/5\n";
        $prompt .= "• Подозрительных паттернов: {$analysisResult['suspicious_patterns_count']}\n\n";
        
        if (!empty($analysisResult['threats'])) {
            $prompt .= "⚠️ ОБНАРУЖЕННЫЕ УГРОЗЫ (топ-5):\n\n";
            
            foreach (array_slice($analysisResult['threats'], 0, 5) as $i => $threat) {
                $prompt .= ($i + 1) . ". 🎯 IP-адрес: {$threat['ip']}\n";
                $prompt .= "   • Оценка угрозы: {$threat['threat_score']}/100\n";
                $prompt .= "   • Всего запросов: {$threat['stats']['requests']}\n";
                $prompt .= "   • Неудачных запросов: {$threat['stats']['failed_requests']}\n";
                $prompt .= "   • Уникальных User-Agent: " . count($threat['stats']['user_agents']) . "\n";
                $prompt .= "   • Факторы риска: " . implode(', ', $threat['risk_factors']) . "\n";
                $prompt .= "   • Причины подозрений: " . implode('; ', $threat['reasons']) . "\n";
                
                // Примеры URL (самые подозрительные)
                $suspiciousUrls = [];
                foreach ($threat['stats']['urls'] as $url) {
                    if (preg_match('/\.(php|admin|wp-|\.env)/i', $url) || 
                        stripos($url, 'scan') !== false) {
                        $suspiciousUrls[] = $url;
                        if (count($suspiciousUrls) >= 3) break;
                    }
                }
                
                if (!empty($suspiciousUrls)) {
                    $prompt .= "   • Примеры подозрительных URL: " . implode(', ', $suspiciousUrls) . "\n";
                }
                
                $prompt .= "\n";
            }
        }
        
        $prompt .= "🤔 ПРИНИМАЙ РЕШЕНИЕ:\n\n";
        $prompt .= "Варианты действий:\n";
        $prompt .= "• 🚫 'block' - Немедленно заблокировать IP (если это явная атака/бот)\n";
        $prompt .= "• 👁️ 'monitor' - Усиленное наблюдение (если подозрительно, но не критично)\n";
        $prompt .= "• ✅ 'ignore' - Игнорировать (если активность кажется нормальной)\n\n";
        
        $prompt .= "Учитывай:\n";
        $prompt .= "• Частота запросов и процент ошибок\n";
        $prompt .= "• Разнообразие User-Agent (боты часто меняют их)\n";
        $prompt .= "• Попытки доступа к админ-панелям\n";
        $prompt .= "• Сканирование уязвимостей\n";
        $prompt .= "• Использование хакерских инструментов\n\n";
        
        $prompt .= "Отвечай СТРОГО в JSON формате:\n";
        $prompt .= '{"decision": "block/monitor/ignore", "confidence": число_от_1_до_100, "reason": "подробное_объяснение", "recommended_actions": ["действие1", "действие2"]}';
        
        return $prompt;
    }
    
    // Выполнение решения
    private function executeDecision($analysisResult, $aiDecision, $aiModel) {
        $analysisId = $this->saveAnalysis($analysisResult, $aiDecision, $aiModel);
        $actions = [];
        
        switch ($aiDecision['decision']) {
            case 'block':
                foreach ($analysisResult['threats'] as $threat) {
                    if ($threat['threat_score'] >= 60) { // Блокируем только серьезные угрозы
                        $blockResult = $this->blockIP($threat['ip'], implode('; ', $threat['reasons']));
                        $actions[] = "🚫 Заблокирован IP {$threat['ip']} (угроза: {$threat['threat_score']})";
                        
                        if ($blockResult['method']) {
                            $actions[] = "   Метод блокировки: {$blockResult['method']}";
                        }
                    }
                }
                break;
                
            case 'monitor':
                foreach ($analysisResult['threats'] as $threat) {
                    if ($threat['threat_score'] >= 40) {
                        $this->addToWatchlist($threat['ip'], $threat['threat_score']);
                        $actions[] = "👁️ Добавлен в наблюдение: {$threat['ip']} (угроза: {$threat['threat_score']})";
                    }
                }
                break;
                
            case 'ignore':
                $actions[] = "✅ Активность признана нормальной";
                break;
        }
        
        // Логируем решение ИИ
        $this->logDecision($analysisId, $aiDecision, $actions, $aiModel);
        
        // Обновляем действия в основной записи
        $this->pdo->prepare("UPDATE log_analysis SET actions_taken = ? WHERE id = ?")
                  ->execute([implode('; ', $actions), $analysisId]);
        
        return [
            'analysis_id' => $analysisId,
            'ai_decision' => $aiDecision,
            'actions_taken' => $actions,
            'timestamp' => date('Y-m-d H:i:s'),
            'threat_count' => count($analysisResult['threats'])
        ];
    }
    
    // Сохранение анализа в БД
    private function saveAnalysis($analysisResult, $aiDecision, $aiModel) {
        $stmt = $this->pdo->prepare("
            INSERT INTO log_analysis (analysis_data, ai_decision, threat_level, status, ai_model) 
            VALUES (?, ?, ?, 'processed', ?)
        ");
        
        $stmt->execute([
            json_encode($analysisResult, JSON_UNESCAPED_UNICODE),
            json_encode($aiDecision, JSON_UNESCAPED_UNICODE),
            $analysisResult['threat_level'],
            $aiModel
        ]);
        
        return $this->pdo->lastInsertId();
    }
    
    // Блокировка IP
    private function blockIP($ip, $reason) {
        $expiresAt = date('Y-m-d H:i:s', time() + $this->config['block_duration']);
        
        $stmt = $this->pdo->prepare("
            INSERT INTO blocked_ips (ip_address, reason, expires_at, block_method) 
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE 
            reason = VALUES(reason), 
            expires_at = VALUES(expires_at),
            blocked_at = CURRENT_TIMESTAMP,
            status = 'active',
            block_method = VALUES(block_method)
        ");
        
        $blockMethod = 'database';
        
        // Попытка создать правило iptables
        if (function_exists('exec') && !empty(shell_exec('which iptables'))) {
            $command = "iptables -C INPUT -s {$ip} -j DROP 2>/dev/null || iptables -A INPUT -s {$ip} -j DROP";
            $output = [];
            $returnVar = 0;
            @exec($command, $output, $returnVar);
            
            if ($returnVar === 0) {
                $blockMethod = 'iptables';
            }
        }
        
        // Альтернативно создаем .htaccess правило
        if ($blockMethod === 'database') {
            $htaccessFile = $_SERVER['DOCUMENT_ROOT'] . '/.htaccess';
            if (is_writable(dirname($htaccessFile))) {
                $rule = "\n# AI Admin Block - {$ip} - " . date('Y-m-d H:i:s') . "\nDeny from {$ip}\n";
                if (file_put_contents($htaccessFile, $rule, FILE_APPEND | LOCK_EX)) {
                    $blockMethod = 'htaccess';
                }
            }
        }
        
        $stmt->execute([$ip, $reason, $expiresAt, $blockMethod]);
        
        return [
            'success' => true,
            'method' => $blockMethod,
            'expires_at' => $expiresAt
        ];
    }
    
    // Добавление в список наблюдения
    private function addToWatchlist($ip, $threatScore) {
        $stmt = $this->pdo->prepare("
            INSERT INTO threat_patterns (pattern_type, pattern_value, threat_score) 
            VALUES ('ip_watch', ?, ?)
        ");
        $stmt->execute([$ip, $threatScore]);
    }
    
    // Логирование решения ИИ
    private function logDecision($analysisId, $aiDecision, $actions, $aiModel) {
        $stmt = $this->pdo->prepare("
            INSERT INTO ai_decisions_log (analysis_id, decision_type, confidence_score, ai_reasoning, executed_actions, ai_model) 
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([
            $analysisId,
            $aiDecision['decision'],
            $aiDecision['confidence'],
            $aiDecision['reason'],
            json_encode($actions, JSON_UNESCAPED_UNICODE),
            $aiModel
        ]);
    }
    
    // Обновление статистики производительности
    private function updatePerformanceStats($analysisResult, $processingTime, $aiModel) {
        $currentHour = date('Y-m-d H:00:00');
        
        $stmt = $this->pdo->prepare("
            INSERT INTO performance_stats (date_hour, threats_detected, ai_processing_time_avg, ai_model) 
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE 
            threats_detected = threats_detected + VALUES(threats_detected),
            ai_processing_time_avg = (ai_processing_time_avg + VALUES(ai_processing_time_avg)) / 2
        ");
        
        $stmt->execute([$currentHour, count($analysisResult['threats']), $processingTime, $aiModel]);
    }
    
    // Получение статистики
    public function getStats() {
        $stats = [];
        
        // Общая статистика анализов за 24 часа
        $stmt = $this->pdo->query("
            SELECT COUNT(*) as total_analysis, 
                   AVG(threat_level) as avg_threat_level,
                   MAX(timestamp) as last_analysis,
                   AVG(processing_time_ms) as avg_processing_time
            FROM log_analysis 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $stats['analysis'] = $stmt->fetch();
        
        // Статистика по моделям ИИ за 24 часа
        $stmt = $this->pdo->query("
            SELECT ai_model, COUNT(*) as usage_count, 
                   AVG(processing_time_ms) as avg_processing_time,
                   AVG(threat_level) as avg_threat_level
            FROM log_analysis 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) 
                  AND ai_model IS NOT NULL
            GROUP BY ai_model 
            ORDER BY usage_count DESC
        ");
        $stats['model_usage'] = $stmt->fetchAll();
        
        // Статистика блокировок
        $stmt = $this->pdo->query("
            SELECT COUNT(*) as active_blocks,
                   COUNT(CASE WHEN blocked_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as recent_blocks,
                   COUNT(CASE WHEN block_method = 'iptables' THEN 1 END) as iptables_blocks,
                   COUNT(CASE WHEN block_method = 'htaccess' THEN 1 END) as htaccess_blocks
            FROM blocked_ips 
            WHERE status = 'active' AND (expires_at IS NULL OR expires_at > NOW())
        ");
        $stats['blocks'] = $stmt->fetch();
        
        // Решения ИИ за 24 часа
        $stmt = $this->pdo->query("
            SELECT decision_type, COUNT(*) as count, AVG(confidence_score) as avg_confidence,
                   ai_model
            FROM ai_decisions_log 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY decision_type, ai_model
            ORDER BY count DESC
        ");
        $stats['decisions'] = $stmt->fetchAll();
        
        // Топ угроз
        $stmt = $this->pdo->query("
            SELECT pattern_value as ip, threat_score, COUNT(*) as detections
            FROM threat_patterns 
            WHERE pattern_type = 'ip_watch' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY pattern_value, threat_score
            ORDER BY threat_score DESC, detections DESC
            LIMIT 10
        ");
        $stats['top_threats'] = $stmt->fetchAll();
        
        return $stats;
    }
    
    // Разблокировка IP
    public function unblockIP($ip) {
        // Обновляем статус в БД
        $stmt = $this->pdo->prepare("UPDATE blocked_ips SET status = 'removed' WHERE ip_address = ?");
        $stmt->execute([$ip]);
        
        $actions = [];
        
        // Удаляем из iptables
        if (function_exists('exec') && !empty(shell_exec('which iptables'))) {
            $command = "iptables -D INPUT -s {$ip} -j DROP 2>/dev/null";
            @exec($command);
            $actions[] = 'Удален из iptables';
        }
        
        // Удаляем из .htaccess (простая версия)
        $htaccessFile = $_SERVER['DOCUMENT_ROOT'] . '/.htaccess';
        if (file_exists($htaccessFile) && is_writable($htaccessFile)) {
            $content = file_get_contents($htaccessFile);
            $newContent = preg_replace("/# AI Admin Block - {$ip}.*?\nDeny from {$ip}\n/s", '', $content);
            if ($content !== $newContent) {
                file_put_contents($htaccessFile, $newContent);
                $actions[] = 'Удален из .htaccess';
            }
        }
        
        $actions[] = 'Удален из базы данных';
        
        return [
            'success' => true,
            'actions' => $actions
        ];
    }
}

// Инициализация анализатора
$analyzer = new AILogAnalyzer($config, $pdo);

// Обработка AJAX запросов
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    
    try {
        switch ($_POST['action']) {
            case 'run_analysis':
                $selectedModel = $_POST['ai_model'] ?? getCurrentAIModel($config);
                $result = $analyzer->analyzeRecentLogs($selectedModel);
                echo json_encode(['success' => true, 'data' => $result], JSON_UNESCAPED_UNICODE);
                break;
                
            case 'get_stats':
                $stats = $analyzer->getStats();
                echo json_encode(['success' => true, 'data' => $stats], JSON_UNESCAPED_UNICODE);
                break;
                
            case 'change_model':
                $newModel = $_POST['model'] ?? $config['default_ai_model'];
                $_SESSION['selected_ai_model'] = $newModel;
                echo json_encode(['success' => true, 'message' => "Модель изменена на: {$newModel}"], JSON_UNESCAPED_UNICODE);
                break;
                
            case 'unblock_ip':
                $ip = $_POST['ip'] ?? '';
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $result = $analyzer->unblockIP($ip);
                    echo json_encode(['success' => true, 'message' => "IP {$ip} разблокирован", 'data' => $result], JSON_UNESCAPED_UNICODE);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Некорректный IP адрес'], JSON_UNESCAPED_UNICODE);
                }
                break;
                
            case 'get_threat_details':
                $analysisId = intval($_POST['analysis_id'] ?? 0);
                if ($analysisId > 0) {
                    $stmt = $pdo->prepare("SELECT * FROM log_analysis WHERE id = ?");
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
    SELECT la.*, COUNT(bl.id) as blocked_ips_count 
    FROM log_analysis la
    LEFT JOIN ai_decisions_log adl ON la.id = adl.analysis_id
    LEFT JOIN blocked_ips bl ON adl.decision_type = 'block' AND bl.blocked_at BETWEEN la.timestamp AND DATE_ADD(la.timestamp, INTERVAL 1 MINUTE)
    WHERE la.timestamp >= DATE_SUB(NOW(), INTERVAL 48 HOUR)
    GROUP BY la.id
    ORDER BY la.timestamp DESC 
    LIMIT 15
");
$recent_analyses = $stmt->fetchAll();

$stmt = $pdo->query("
    SELECT bi.*, 
           CASE 
               WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 'expired'
               ELSE 'active'
           END as current_status
    FROM blocked_ips bi
    WHERE bi.status = 'active'
    ORDER BY bi.blocked_at DESC
    LIMIT 50
");
$blocked_ips = $stmt->fetchAll();

$stats = $analyzer->getStats();
$models = getOpenRouterModels();
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🤖 AI Admin - Система анализа логов с множественными моделями</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #2c3e50;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }

        .header h1 {
            font-size: 3rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            background: linear-gradient(45deg, #fff, #f0f8ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header p {
            font-size: 1.2rem;
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
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .status-online {
            background: rgba(40, 167, 69, 0.8);
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
            border-bottom: 3px solid #667eea;
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
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
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
            background: rgba(102, 126, 234, 0.1);
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 0.85rem;
            color: #667eea;
            border: 1px solid rgba(102, 126, 234, 0.2);
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
            border-bottom: 3px solid #667eea;
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

        .stat-item.threat { border-color: #e74c3c; }
        .stat-item.block { border-color: #f39c12; }
        .stat-item.monitor { border-color: #3498db; }
        .stat-item.success { border-color: #27ae60; }
        .stat-item.info { border-color: #667eea; }

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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }

        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6);
        }

        .btn.danger {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            box-shadow: 0 4px 15px rgba(231, 76, 60, 0.4);
        }

        .btn.danger:hover {
            box-shadow: 0 8px 25px rgba(231, 76, 60, 0.6);
        }

        .btn.success {
            background: linear-gradient(135deg, #27ae60 0%, #229954 100%);
            box-shadow: 0 4px 15px rgba(39, 174, 96, 0.4);
        }

        .btn.success:hover {
            box-shadow: 0 8px 25px rgba(39, 174, 96, 0.6);
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
            background: linear-gradient(145deg, #667eea, #764ba2);
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
            background-color: rgba(102, 126, 234, 0.1);
        }

        .badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge.high { 
            background: linear-gradient(135deg, #ffebee, #ffcdd2); 
            color: #c62828; 
            border: 2px solid #ef5350;
        }
        .badge.medium { 
            background: linear-gradient(135deg, #fff3e0, #ffe0b2); 
            color: #ef6c00; 
            border: 2px solid #ff9800;
        }
        .badge.low { 
            background: linear-gradient(135deg, #e8f5e8, #c8e6c9); 
            color: #2e7d32; 
            border: 2px solid #4caf50;
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
            border: 2px solid #e74c3c;
        }
        .decision-monitor { 
            background: linear-gradient(135deg, #fff3e0, #ffe0b2); 
            color: #ef6c00; 
            border: 2px solid #f39c12;
        }
        .decision-ignore { 
            background: linear-gradient(135deg, #e8f5e8, #c8e6c9); 
            color: #2e7d32; 
            border: 2px solid #27ae60;
        }

        .ai-model-badge {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 500;
            margin-left: 8px;
        }

        .log-entry {
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            border-left: 5px solid #667eea;
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
            background: linear-gradient(135deg, #f0f8ff 0%, #e6f3ff 100%);
            border: 3px solid #667eea;
            border-radius: 15px;
            padding: 20px;
            margin: 15px 0;
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
        }

        .ai-response h4 {
            color: #667eea;
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
            border: 2px solid #27ae60;
        }

        .alert.error {
            background: linear-gradient(135deg, #f8d7da, #f5c6cb);
            color: #721c24;
            border: 2px solid #e74c3c;
        }

        .alert.info {
            background: linear-gradient(135deg, #cce7ff, #b3d9ff);
            color: #004085;
            border: 2px solid #3498db;
        }

        .progress-container {
            background: #e9ecef;
            border-radius: 25px;
            overflow: hidden;
            height: 25px;
            margin: 15px 0;
            box-shadow: inset 0 2px 5px rgba(0, 0, 0, 0.1);
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #27ae60, #f39c12, #e74c3c);
            transition: width 0.8s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.9rem;
            font-weight: bold;
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

        .ip-address {
            font-family: 'Courier New', monospace;
            background: rgba(102, 126, 234, 0.1);
            padding: 4px 8px;
            border-radius: 6px;
            border: 1px solid rgba(102, 126, 234, 0.3);
            font-weight: bold;
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

        .threat-critical { background: #ffebee; color: #c62828; border: 2px solid #e74c3c; }
        .threat-high { background: #fff3e0; color: #ef6c00; border: 2px solid #f39c12; }
        .threat-medium { background: #e3f2fd; color: #1976d2; border: 2px solid #2196f3; }
        .threat-low { background: #e8f5e8; color: #2e7d32; border: 2px solid #4caf50; }

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
            max-width: 800px;
            max-height: 90vh;
            overflow-y: auto;
        }

        .modal-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
                font-size: 2.2rem;
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

            .model-stats {
                justify-content: center;
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
                font-size: 1.8rem;
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

            .ai-model-selector {
                padding: 15px;
            }

            .model-select {
                font-size: 0.9rem;
                padding: 10px 12px;
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

        .card, .ai-model-selector {
            animation: fadeInUp 0.6s ease-out forwards;
        }

        .card:nth-child(1) { animation-delay: 0.1s; }
        .card:nth-child(2) { animation-delay: 0.2s; }
        .card:nth-child(3) { animation-delay: 0.3s; }
        .card:nth-child(4) { animation-delay: 0.4s; }

        /* Дополнительные стили для улучшения UX */
        .tooltip {
            position: relative;
            cursor: help;
        }

        .tooltip:hover::after {
            content: attr(data-tooltip);
            position: absolute;
            background: #333;
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            white-space: nowrap;
            z-index: 1000;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            margin-bottom: 5px;
        }

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
            <h1><i class="fas fa-robot"></i> AI Admin</h1>
            <p>Система автоматического анализа логов с множественными AI моделями</p>
            <div class="system-status">
                <div class="status-item status-online">
                    <i class="fas fa-check-circle"></i>
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
                    <i class="fas fa-layer-group"></i>
                    <?php echo count($models); ?> доступных моделей
                </div>
            </div>
        </div>

        <!-- AI Model Selector -->
        <div class="ai-model-selector">
            <h3><i class="fas fa-brain"></i> Выбор AI модели</h3>
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
                                <span style="color: #f39c12; margin-left: 8px;"><i class="fas fa-star"></i> Рекомендуется</span>
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
            <button class="btn" onclick="runAnalysis()">
                <i class="fas fa-search"></i> Запустить анализ
            </button>
            <button class="btn success" onclick="loadStats()">
                <i class="fas fa-sync"></i> Обновить статистику
            </button>
            <button class="btn" onclick="showSystemInfo()">
                <i class="fas fa-info-circle"></i> Информация о системе
            </button>
        </div>

        <div id="alerts"></div>

        <div class="dashboard">
            <!-- Статистика анализов -->
            <div class="card">
                <h3><i class="fas fa-chart-line"></i> Анализ за 24 часа</h3>
                <div class="stats-grid">
                    <div class="stat-item info tooltip" data-tooltip="Общее количество проведенных анализов">
                        <div class="stat-number"><?php echo $stats['analysis']['total_analysis'] ?? 0; ?></div>
                        <div class="stat-label">Анализов</div>
                    </div>
                    <div class="stat-item threat tooltip" data-tooltip="Средний уровень угрозы по шкале 1-5">
                        <div class="stat-number"><?php echo number_format($stats['analysis']['avg_threat_level'] ?? 0, 1); ?></div>
                        <div class="stat-label">Ср. угроза</div>
                    </div>
                    <div class="stat-item success tooltip" data-tooltip="Среднее время обработки в миллисекундах">
                        <div class="stat-number"><?php echo round($stats['analysis']['avg_processing_time'] ?? 0); ?>мс</div>
                        <div class="stat-label">Скорость ИИ</div>
                    </div>
                </div>
                <?php if (!empty($stats['analysis']['last_analysis'])): ?>
                <div class="alert info">
                    <i class="fas fa-clock"></i>
                    Последний анализ: <?php echo date('d.m.Y H:i:s', strtotime($stats['analysis']['last_analysis'])); ?>
                </div>
                <?php endif; ?>
            </div>

            <!-- Статистика блокировок -->
            <div class="card">
                <h3><i class="fas fa-shield-alt"></i> Безопасность</h3>
                <div class="stats-grid">
                    <div class="stat-item block tooltip" data-tooltip="Активно заблокированных IP адресов">
                        <div class="stat-number"><?php echo $stats['blocks']['active_blocks'] ?? 0; ?></div>
                        <div class="stat-label">Заблокировано</div>
                    </div>
                    <div class="stat-item monitor tooltip" data-tooltip="Новых блокировок за последний час">
                        <div class="stat-number"><?php echo $stats['blocks']['recent_blocks'] ?? 0; ?></div>
                        <div class="stat-label">За час</div>
                    </div>
                    <div class="stat-item info tooltip" data-tooltip="Блокировки через iptables">
                        <div class="stat-number"><?php echo $stats['blocks']['iptables_blocks'] ?? 0; ?></div>
                        <div class="stat-label">iptables</div>
                    </div>
                    <div class="stat-item info tooltip" data-tooltip="Блокировки через .htaccess">
                        <div class="stat-number"><?php echo $stats['blocks']['htaccess_blocks'] ?? 0; ?></div>
                        <div class="stat-label">htaccess</div>
                    </div>
                </div>
            </div>

            <!-- Решения ИИ -->
            <div class="card">
                <h3><i class="fas fa-brain"></i> Решения ИИ за 24ч</h3>
                <div class="stats-grid">
                    <?php 
                    $decisionCounts = ['block' => 0, 'monitor' => 0, 'ignore' => 0];
                    $totalConfidence = ['block' => 0, 'monitor' => 0, 'ignore' => 0];
                    
                    foreach ($stats['decisions'] as $decision) {
                        if (!isset($decisionCounts[$decision['decision_type']])) {
                            $decisionCounts[$decision['decision_type']] = 0;
                        }
                        $decisionCounts[$decision['decision_type']] += $decision['count'];
                        $totalConfidence[$decision['decision_type']] = $decision['avg_confidence'];
                    }
                    ?>
                    
                    <div class="stat-item threat tooltip" data-tooltip="Решений о блокировке с средней уверенностью <?php echo round($totalConfidence['block']); ?>%">
                        <div class="stat-number"><?php echo $decisionCounts['block']; ?></div>
                        <div class="stat-label">Block</div>
                    </div>
                    <div class="stat-item block tooltip" data-tooltip="Решений о мониторинге с средней уверенностью <?php echo round($totalConfidence['monitor']); ?>%">
                        <div class="stat-number"><?php echo $decisionCounts['monitor']; ?></div>
                        <div class="stat-label">Monitor</div>
                    </div>
                    <div class="stat-item success tooltip" data-tooltip="Решений игнорировать с средней уверенностью <?php echo round($totalConfidence['ignore']); ?>%">
                        <div class="stat-number"><?php echo $decisionCounts['ignore']; ?></div>
                        <div class="stat-label">Ignore</div>
                    </div>
                </div>
                
                <?php if (!empty($stats['model_usage'])): ?>
                <div style="margin-top: 15px;">
                    <h4 style="color: #2c3e50; font-size: 1rem; margin-bottom: 10px;">Использование моделей:</h4>
                    <?php foreach (array_slice($stats['model_usage'], 0, 3) as $usage): ?>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 5px 0; border-bottom: 1px solid #e9ecef;">
                            <span style="font-size: 0.8rem; color: #6c757d;">
                                <?php 
                                $modelName = $models[$usage['ai_model']]['name'] ?? 'Неизвестная';
                                echo substr($modelName, 0, 25) . (strlen($modelName) > 25 ? '...' : '');
                                ?>
                            </span>
                            <span class="badge info"><?php echo $usage['usage_count']; ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
            </div>

            <!-- Топ угроз -->
            <div class="card">
                <h3><i class="fas fa-exclamation-triangle"></i> Топ угроз</h3>
                <?php if (empty($stats['top_threats'])): ?>
                    <div class="empty-state">
                        <i class="fas fa-check-shield"></i>
                        <h3>Угроз не обнаружено</h3>
                        <p>Система работает в штатном режиме</p>
                    </div>
                <?php else: ?>
                    <div class="table-container">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>IP адрес</th>
                                    <th>Оценка</th>
                                    <th>Обнаружений</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach (array_slice($stats['top_threats'], 0, 10) as $threat): ?>
                                <tr>
                                    <td><code class="ip-address"><?php echo htmlspecialchars($threat['ip']); ?></code></td>
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
                                    <td><?php echo $threat['detections']; ?></td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="dashboard">
            <!-- История анализов -->
            <div class="card">
                <h3><i class="fas fa-history"></i> Последние анализы (48ч)</h3>
                <?php if (empty($recent_analyses)): ?>
                    <div class="empty-state">
                        <i class="fas fa-file-search"></i>
                        <h3>Анализы не найдены</h3>
                        <p>Запустите первый анализ для получения данных</p>
                    </div>
                <?php else: ?>
                <div class="table-container">
                    <?php foreach ($recent_analyses as $analysis): ?>
                    <?php 
                    $data = json_decode($analysis['analysis_data'], true);
                    $decision = json_decode($analysis['ai_decision'], true);
                    ?>
                    <div class="log-entry" onclick="showAnalysisDetails(<?php echo $analysis['id']; ?>)" style="cursor: pointer;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <div>
                                <strong style="font-size: 1.1rem;">
                                    <i class="fas fa-calendar-alt"></i>
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
                                <div style="font-size: 1.2rem; font-weight: bold; color: #e74c3c;">
                                    <?php echo count($data['threats'] ?? []); ?> угроз
                                </div>
                                <div style="font-size: 0.9rem; color: #6c757d;">
                                    Уровень: <?php echo $analysis['threat_level']; ?>/5
                                </div>
                            </div>
                        </div>
                        
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 10px 0;">
                            <div>
                                <strong>📊 Записей обработано:</strong> 
                                <?php echo number_format($data['total_processed'] ?? 0, 0, '.', ' '); ?>
                                <?php if (isset($data['total_entries'])): ?>
                                    (анализ: <?php echo number_format($data['total_entries'], 0, '.', ' '); ?>)
                                <?php endif; ?>
                            </div>
                            <div>
                                <strong>🎯 Точность ИИ:</strong> 
                                <?php echo $decision['confidence'] ?? 0; ?>%
                            </div>
                            <?php if (isset($analysis['blocked_ips_count']) && $analysis['blocked_ips_count'] > 0): ?>
                            <div>
                                <strong>🚫 Заблокировано IP:</strong> 
                                <?php echo $analysis['blocked_ips_count']; ?>
                            </div>
                            <?php endif; ?>
                        </div>
                        
                        <?php if (!empty($decision['reason'])): ?>
                        <div class="ai-response">
                            <h4><i class="fas fa-robot"></i> Решение ИИ</h4>
                            <p><?php echo htmlspecialchars($decision['reason']); ?></p>
                            <?php if (!empty($decision['recommended_actions'])): ?>
                                <div style="margin-top: 8px;">
                                    <strong>Рекомендации:</strong>
                                    <ul style="margin: 5px 0 0 20px;">
                                        <?php foreach ($decision['recommended_actions'] as $action): ?>
                                            <li><?php echo htmlspecialchars($action); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            <?php endif; ?>
                        </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($data['threats'])): ?>
                        <details style="margin-top: 15px;">
                            <summary style="cursor: pointer; color: #667eea; font-weight: bold;">
                                <i class="fas fa-bug"></i> Детали угроз (<?php echo count($data['threats']); ?>)
                            </summary>
                            <div style="margin-top: 10px;">
                                <?php foreach (array_slice($data['threats'], 0, 5) as $i => $threat): ?>
                                <div style="background: rgba(231, 76, 60, 0.1); padding: 12px; margin: 8px 0; border-radius: 8px; border-left: 4px solid #e74c3c;">
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
                                        <div><strong>Запросов:</strong> <?php echo $threat['stats']['requests']; ?> | <strong>Ошибок:</strong> <?php echo $threat['stats']['failed_requests']; ?></div>
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

            <!-- Заблокированные IP -->
            <div class="card">
                <h3><i class="fas fa-ban"></i> Заблокированные IP адреса</h3>
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
                                <td style="max-width: 300px;">
                                    <span class="tooltip" data-tooltip="<?php echo htmlspecialchars($blocked['reason']); ?>">
                                        <?php echo htmlspecialchars(mb_substr($blocked['reason'], 0, 60)); ?>
                                        <?php if (mb_strlen($blocked['reason']) > 60) echo '...'; ?>
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
                                        <span class="badge high">Навсегда</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge 
                                        <?php 
                                        switch($blocked['block_method']) {
                                            case 'iptables': echo 'high'; break;
                                            case 'htaccess': echo 'medium'; break;
                                            default: echo 'low';
                                        }
                                        ?>">
                                        <?php echo strtoupper($blocked['block_method']); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if ($blocked['current_status'] === 'active'): ?>
                                    <button class="btn danger" style="padding: 8px 16px; font-size: 0.8rem;" 
                                            onclick="unblockIP('<?php echo $blocked['ip_address']; ?>')">
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

    <!-- Модальное окно деталей анализа -->
    <div class="modal-overlay" id="analysisModal">
        <div class="modal">
            <div class="modal-header">
                <div class="modal-title">
                    <i class="fas fa-search-plus"></i>
                    Детальный анализ
                </div>
                <button class="modal-close" onclick="hideAnalysisModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body" id="analysisModalContent">
                <div style="text-align: center; padding: 40px;">
                    <div class="loading"></div>
                    <p>Загрузка данных...</p>
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
                '<span style="color: #f39c12; margin-left: 8px;"><i class="fas fa-star"></i> Рекомендуется</span>' : '';
            
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

        // Запуск анализа
        async function runAnalysis() {
            if (isAnalyzing) return;
            
            isAnalyzing = true;
            const btn = event.target;
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<div class="loading"></div> Анализирую логи...';
            btn.disabled = true;

            const selectedModel = document.getElementById('aiModelSelect').value;

            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=run_analysis&ai_model=${encodeURIComponent(selectedModel)}`
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
                    }
                    
                    showAlert(`${icon} Анализ завершен с моделью <strong>${modelName}</strong>!<br>
                              ИИ принял решение: <strong>${decision.decision.toUpperCase()}</strong> (точность: ${decision.confidence}%)<br>
                              Найдено угроз: ${result.threat_count}, Обработано действий: ${result.actions_taken.length}`, alertType, 8000);
                    
                    // Обновляем страницу через 2 секунды
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showAlert(`❌ Ошибка анализа: ${data.error}`, 'error', 8000);
                }
            } catch (error) {
                showAlert(`❌ Ошибка сети: ${error.message}`, 'error', 8000);
                console.error('Analysis error:', error);
            } finally {
                btn.innerHTML = originalHtml;
                btn.disabled = false;
                isAnalyzing = false;
            }
        }

        // Обновление статистики
        async function loadStats() {
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'action=get_stats'
                });

                const data = await response.json();
                
                if (data.success) {
                    showAlert('📊 Статистика обновлена');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(`❌ Ошибка обновления: ${data.error}`, 'error');
                }
            } catch (error) {
                showAlert(`❌ Ошибка сети: ${error.message}`, 'error');
            }
        }

        // Разблокировка IP
        async function unblockIP(ip) {
            if (!confirm(`Разблокировать IP адрес ${ip}?\n\nЭто действие удалит IP из всех методов блокировки (iptables, .htaccess, база данных).`)) {
                return;
            }

            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=unblock_ip&ip=${encodeURIComponent(ip)}`
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

        // Показать детали анализа
        async function showAnalysisDetails(analysisId) {
            const modal = document.getElementById('analysisModal');
            const content = document.getElementById('analysisModalContent');
            
            // Показываем модальное окно
            modal.style.display = 'flex';
            content.innerHTML = `
                <div style="text-align: center; padding: 40px;">
                    <div class="loading"></div>
                    <p>Загружаю детальную информацию...</p>
                </div>
            `;
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=get_threat_details&analysis_id=${analysisId}`
                });

                const data = await response.json();
                
                if (data.success) {
                    const analysis = data.data;
                    const analysisData = analysis.analysis_data;
                    const aiDecision = analysis.ai_decision;
                    const aiModel = models[analysis.ai_model] || { name: analysis.ai_model || 'Неизвестная' };
                    
                    let html = `
                        <div style="margin-bottom: 25px;">
                            <h4><i class="fas fa-info-circle"></i> Общая информация</h4>
                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 10px;">
                                <div class="stat-item info">
                                    <div class="stat-number">${analysisData.total_processed || 0}</div>
                                    <div class="stat-label">Записей обработано</div>
                                </div>
                                <div class="stat-item threat">
                                    <div class="stat-number">${analysisData.threats.length}</div>
                                    <div class="stat-label">Угроз найдено</div>
                                </div>
                                <div class="stat-item block">
                                    <div class="stat-number">${analysis.threat_level}/5</div>
                                    <div class="stat-label">Уровень угрозы</div>
                                </div>
                                <div class="stat-item success">
                                    <div class="stat-number">${analysis.processing_time_ms || 0}мс</div>
                                    <div class="stat-label">Время обработки</div>
                                </div>
                            </div>
                            <div style="margin-top: 15px; text-align: center;">
                                <span class="ai-model-badge" style="font-size: 0.9rem; padding: 8px 16px;">
                                    <i class="fas fa-brain"></i> Использована модель: ${aiModel.name}
                                </span>
                            </div>
                        </div>
                        
                        <div class="ai-response" style="margin: 20px 0;">
                            <h4><i class="fas fa-robot"></i> Решение ИИ</h4>
                            <div style="display: flex; gap: 15px; align-items: center; margin-bottom: 10px;">
                                <span class="decision-badge decision-${aiDecision.decision}">
                                    ${aiDecision.decision.toUpperCase()}
                                </span>
                                <span class="badge ${aiDecision.confidence >= 80 ? 'high' : aiDecision.confidence >= 60 ? 'medium' : 'low'}">
                                    Уверенность: ${aiDecision.confidence}%
                                </span>
                            </div>
                            <p><strong>Обоснование:</strong> ${aiDecision.reason}</p>
                            ${aiDecision.recommended_actions && aiDecision.recommended_actions.length > 0 ? `
                                <div style="margin-top: 10px;">
                                    <strong>Рекомендованные действия:</strong>
                                    <ul style="margin-left: 20px;">
                                        ${aiDecision.recommended_actions.map(action => `<li>${action}</li>`).join('')}
                                    </ul>
                                </div>
                            ` : ''}
                        </div>
                        
                        ${analysisData.threats.length > 0 ? `
                            <div style="margin: 25px 0;">
                                <h4><i class="fas fa-bug"></i> Обнаруженные угрозы</h4>
                                <div class="table-container" style="max-height: 400px;">
                                    <table class="table">
                                        <thead>
                                            <tr>
                                                <th>IP адрес</th>
                                                <th>Оценка</th>
                                                <th>Запросов</th>
                                                <th>Ошибок</th>
                                                <th>User-Agents</th>
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
                                                    <td>${threat.stats.requests}</td>
                                                    <td>${threat.stats.failed_requests}</td>
                                                    <td>${threat.stats.user_agents.length}</td>
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
                                <h4><i class="fas fa-cogs"></i> Выполненные действия</h4>
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
                console.error('Details error:', error);
            }
        }

        // Скрыть модальное окно
        function hideAnalysisModal() {
            document.getElementById('analysisModal').style.display = 'none';
        }

        // Показать информацию о системе
        function showSystemInfo() {
            const currentModel = document.getElementById('aiModelSelect').value;
            const modelInfo = models[currentModel];
            
            const info = `
                🤖 AI Admin Security System v2.1
                
                📊 Конфигурация:
                • Активная модель: ${modelInfo.name}
                • Категория: ${modelInfo.category.toUpperCase()}
                • Стоимость: ${modelInfo.price}
                • Скорость: ${modelInfo.speed}
                • Качество: ${modelInfo.quality}
                • Интервал анализа: <?php echo $config['analysis_interval']/60; ?> минут
                • Максимум строк лога: <?php echo number_format($config['max_log_lines']); ?>
                • Порог запросов/мин: <?php echo $config['threat_threshold']['requests_per_minute']; ?>
                
                🔍 Пути к логам:
                <?php foreach ($config['log_paths'] as $path): ?>
                • <?php echo $path; ?> (<?php echo file_exists($path) ? 'доступен' : 'недоступен'; ?>)
                <?php endforeach; ?>
                
                🛡️ Методы блокировки:
                • iptables (системный уровень)
                • .htaccess (веб-сервер)  
                • База данных (учет)
                
                🤖 Доступно AI моделей: <?php echo count($models); ?>
                • Бесплатных: <?php echo count(array_filter($models, fn($m) => $m['category'] === 'free')); ?>
                • Бюджетных: <?php echo count(array_filter($models, fn($m) => $m['category'] === 'budget')); ?>
                • Премиум: <?php echo count(array_filter($models, fn($m) => $m['category'] === 'premium')); ?>
                • Новейших: <?php echo count(array_filter($models, fn($m) => $m['category'] === 'newest')); ?>
                
                ⚙️ База данных:
                • Хост: <?php echo $db_config['host']; ?>
                • БД: <?php echo $db_config['dbname']; ?>
                • Пользователь: <?php echo $db_config['username']; ?>
                
                📈 Статистика за все время:
                • Всего анализов: <?php echo $stats['analysis']['total_analysis'] ?? 0; ?>
                • Активных блокировок: <?php echo $stats['blocks']['active_blocks'] ?? 0; ?>
                • Средний уровень угрозы: <?php echo number_format($stats['analysis']['avg_threat_level'] ?? 0, 2); ?>/5
            `;
            
            alert(info);
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
                        body: 'action=get_stats'
                    });
                    
                    const data = await response.json();
                    if (data.success) {
                        // Тихое обновление некоторых элементов без перезагрузки
                        updateStatsDisplay(data.data);
                    }
                } catch (error) {
                    console.warn('Auto-refresh failed:', error);
                }
            }, 60000); // Каждую минуту
            
            showAlert('🔄 Автообновление включено (каждую минуту)', 'info', 3000);
        }

        function stopAutoRefresh() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
                showAlert('⏸️ Автообновление отключено', 'info', 3000);
            }
        }

        // Обновление элементов статистики без перезагрузки
        function updateStatsDisplay(stats) {
            // Обновляем только числовые значения
            const elements = {
                'total_analysis': stats.analysis?.total_analysis || 0,
                'avg_threat_level': (stats.analysis?.avg_threat_level || 0).toFixed(1),
                'active_blocks': stats.blocks?.active_blocks || 0,
                'recent_blocks': stats.blocks?.recent_blocks || 0
            };
            
            Object.entries(elements).forEach(([key, value]) => {
                const element = document.querySelector(`[data-stat="${key}"]`);
                if (element) {
                    element.textContent = value;
                    element.classList.add('blink');
                    setTimeout(() => element.classList.remove('blink'), 2000);
                }
            });
        }

        // Обработка клавиатурных сокращений
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 'r': // Ctrl+R - запуск анализа
                        if (!isAnalyzing) {
                            e.preventDefault();
                            runAnalysis();
                        }
                        break;
                    case 'u': // Ctrl+U - обновление статистики
                        e.preventDefault();
                        loadStats();
                        break;
                    case 'i': // Ctrl+I - информация о системе
                        e.preventDefault();
                        showSystemInfo();
                        break;
                    case 'm': // Ctrl+M - смена модели (фокус на селект)
                        e.preventDefault();
                        document.getElementById('aiModelSelect').focus();
                        break;
                }
            }
            
            // ESC - закрытие модальных окон
            if (e.key === 'Escape') {
                hideAnalysisModal();
            }
        });

        // Закрытие модального окна по клику вне его
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('modal-overlay')) {
                hideAnalysisModal();
            }
        });

        // Инициализация при загрузке страницы
        document.addEventListener('DOMContentLoaded', function() {
            // Показываем приветствие
            setTimeout(() => {
                const currentModel = models[document.getElementById('aiModelSelect').value];
                showAlert(`🤖 AI Admin система готова к работе с моделью <strong>${currentModel.name}</strong>!<br>
                          Используйте Ctrl+R для быстрого анализа, Ctrl+M для смены модели`, 'info', 6000);
            }, 1000);
            
            // Запускаем автообновление
            setTimeout(() => {
                startAutoRefresh();
            }, 5000);
            
            // Проверяем доступность ИИ при загрузке
            checkAIAvailability();
            
            // Добавляем data-stat атрибуты для автообновления
            const statElements = document.querySelectorAll('.stat-number');
            statElements.forEach(el => {
                const label = el.nextElementSibling?.textContent?.toLowerCase();
                if (label?.includes('анализов')) el.setAttribute('data-stat', 'total_analysis');
                else if (label?.includes('угроза')) el.setAttribute('data-stat', 'avg_threat_level');
                else if (label?.includes('заблокировано')) el.setAttribute('data-stat', 'active_blocks');
                else if (label?.includes('за час')) el.setAttribute('data-stat', 'recent_blocks');
            });

            // Устанавливаем обработчик на селект модели для обновления информации при изменении
            document.getElementById('aiModelSelect').addEventListener('change', function() {
                updateModelInfo(this.value);
            });
        });

        // Проверка доступности ИИ
        async function checkAIAvailability() {
            const apiKey = '<?php echo substr($config['openrouter_api_key'], 0, 10); ?>...';
            if (!apiKey || apiKey === '...') {
                showAlert('⚠️ API ключ OpenRouter не настроен. ИИ анализ недоступен.', 'error', 8000);
                return;
            }
            
            const currentModel = document.getElementById('aiModelSelect').value;
            console.log('AI system ready with model:', currentModel);
        }

        // Функция для экспорта статистики
        function exportStatistics() {
            const currentModel = document.getElementById('aiModelSelect').value;
            const data = {
                export_date: new Date().toISOString(),
                system_info: {
                    current_ai_model: currentModel,
                    ai_model_name: models[currentModel].name,
                    analysis_interval: <?php echo $config['analysis_interval']; ?>,
                    threat_thresholds: <?php echo json_encode($config['threat_threshold']); ?>,
                    available_models: Object.keys(models).length
                },
                statistics: <?php echo json_encode($stats); ?>
            };
            
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ai-admin-stats-${currentModel.replace(/[^a-zA-Z0-9]/g, '_')}-${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showAlert('📊 Статистика экспортирована в файл JSON', 'success');
        }

        // Обработка ошибок JavaScript
        window.addEventListener('error', function(e) {
            console.error('JavaScript error:', e.error);
            showAlert('❌ Произошла ошибка JavaScript. Обновите страницу.', 'error');
        });

        // Обработка ошибок fetch
        window.addEventListener('unhandledrejection', function(e) {
            console.error('Unhandled promise rejection:', e.reason);
            showAlert('❌ Ошибка сетевого запроса. Проверьте подключение.', 'error');
        });

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

        // Функция быстрой смены моделей горячими клавишами
        document.addEventListener('keydown', function(e) {
            if (e.altKey) {
                switch(e.key) {
                    case '1': // Alt+1 - первая бесплатная модель
                        e.preventDefault();
                        setModelAndAnalyze('qwen/qwen-2.5-72b-instruct:free');
                        break;
                    case '2': // Alt+2 - быстрая бюджетная модель
                        e.preventDefault();
                        setModelAndAnalyze('google/gemini-2.5-flash');
                        break;
                    case '3': // Alt+3 - мощная новейшая модель
                        e.preventDefault();
                        setModelAndAnalyze('deepseek/deepseek-r1');
                        break;
                }
            }
        });

        // Установка модели и запуск анализа
        async function setModelAndAnalyze(modelKey) {
            if (isAnalyzing) return;
            
            document.getElementById('aiModelSelect').value = modelKey;
            await changeAIModel();
            setTimeout(() => runAnalysis(), 500);
        }
    </script>
</body>
</html>
