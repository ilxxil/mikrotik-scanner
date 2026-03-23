#!/bin/bash
# ============================================
# MikroTik Advanced Auto Scanner v2.0
# نظام فحص تلقائي متقدم لأجهزة MikroTik
# ============================================

# إعدادات الأمان والتحكم في الأخطاء
set -euo pipefail
trap 'log_error "حدث خطأ غير متوقع في السطر $LINENO"; exit 1' ERR
trap 'log_info "تم إيقاف الفحص بواسطة المستخدم"; exit 0' INT TERM

# ============================================
# الألوان والتنسيق
# ============================================
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# ============================================
# الإعدادات الأساسية
# ============================================
SCRIPT_VERSION="2.0"
SCRIPT_START=$(date +%s)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/root/mikrotik_scans"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/scan_$TIMESTAMP.log"
REPORT_FILE="$LOG_DIR/report_$TIMESTAMP.txt"
JSON_FILE="$LOG_DIR/results_$TIMESTAMP.json"
ERROR_LOG="$LOG_DIR/errors_$TIMESTAMP.log"

# ============================================
# دوال متقدمة للتسجيل
# ============================================

log() {
    local level="$1"
    local message="$2"
    local color="${3:-$WHITE}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "${color}[$timestamp] [$level] $message${NC}" | tee -a "$LOG_FILE"
    
    # تسجيل الأخطاء بشكل منفصل
    if [[ "$level" == "ERROR" ]]; then
        echo "[$timestamp] $message" >> "$ERROR_LOG"
    fi
}

log_info() { log "INFO" "$1" "$CYAN"; }
log_success() { log "SUCCESS" "$1" "$GREEN"; }
log_warning() { log "WARNING" "$1" "$YELLOW"; }
log_error() { log "ERROR" "$1" "$RED"; }
log_debug() { 
    if [[ "${DEBUG:-0}" == "1" ]]; then
        log "DEBUG" "$1" "$MAGENTA"
    fi
}

# ============================================
# دوال JSON
# ============================================

init_json() {
    cat > "$JSON_FILE" << EOF
{
    "scan_info": {
        "timestamp": "$TIMESTAMP",
        "version": "$SCRIPT_VERSION",
        "target": "",
        "network": ""
    },
    "network": {},
    "ports": [],
    "vulnerabilities": [],
    "services": {},
    "recommendations": []
}
EOF
}

add_to_json() {
    local section="$1"
    local key="$2"
    local value="$3"
    
    # استخدام jq لإضافة البيانات (إذا كان مثبتاً)
    if command -v jq &> /dev/null; then
        local temp_file="$LOG_DIR/temp_$$.json"
        jq --arg key "$key" --arg value "$value" ".$section += {($key): $value}" "$JSON_FILE" > "$temp_file"
        mv "$temp_file" "$JSON_FILE"
    fi
}

# ============================================
# فحص الأدوات المطلوبة
# ============================================

check_dependencies() {
    log_info "فحص الأدوات المطلوبة..."
    
    local required_tools=("nmap" "curl" "timeout" "ip" "grep" "awk" "sed")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_warning "الأدوات التالية غير مثبتة: ${missing_tools[*]}"
        log_info "جاري محاولة تثبيت الأدوات..."
        
        if command -v apt &> /dev/null; then
            apt update -y &>/dev/null || true
            apt install -y "${missing_tools[@]}" &>/dev/null || true
        elif command -v pkg &> /dev/null; then
            pkg install -y "${missing_tools[@]}" &>/dev/null || true
        fi
    fi
    
    # فحص الأدوات الاختيارية
    if command -v jq &> /dev/null; then
        log_success "jq متاح - سيتم استخدام JSON"
    else
        log_warning "jq غير مثبت - سيتم استخدام تنسيق نصي فقط"
    fi
    
    if command -v hydra &> /dev/null; then
        log_success "hydra متاح - يمكن اختبار Brute Force"
    fi
}

# ============================================
# اكتشاف الشبكة الذكي
# ============================================

discover_network() {
    log_info "========== مرحلة اكتشاف الشبكة =========="
    
    # محاولات متعددة للحصول على IP
    local ips=()
    
    # الطريقة 1: ip route
    local ip1=$(ip route get 1 2>/dev/null | grep -oP 'src \K\S+' | head -1)
    [[ -n "$ip1" ]] && ips+=("$ip1")
    
    # الطريقة 2: ifconfig
    local ip2=$(ifconfig 2>/dev/null | grep -oP 'inet (10|172\.16|192\.168)\.\d+\.\d+\.\d+' | awk '{print $2}' | head -1)
    [[ -n "$ip2" ]] && ips+=("$ip2")
    
    # الطريقة 3: hostname -I
    local ip3=$(hostname -I 2>/dev/null | awk '{print $1}')
    [[ -n "$ip3" ]] && ips+=("$ip3")
    
    # اختيار أول IP صالح
    CURRENT_IP=""
    for ip in "${ips[@]}"; do
        if [[ "$ip" =~ ^(10|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\. ]]; then
            CURRENT_IP="$ip"
            break
        fi
    done
    
    if [ -z "$CURRENT_IP" ]; then
        log_error "لم يتم اكتشاف عنوان IP تلقائياً"
        read -p "الرجاء إدخال عنوان IP يدوياً: " CURRENT_IP
    fi
    
    log_success "العنوان الحالي: $CURRENT_IP"
    
    # حساب نطاق الشبكة والبوابة
    NETWORK=$(echo "$CURRENT_IP" | cut -d. -f1-3)
    
    # محاولة اكتشاف البوابة
    GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
    if [ -z "$GATEWAY" ]; then
        GATEWAY="$NETWORK.1"
        log_info "البوابة غير مكتشفة، استخدم الافتراضية: $GATEWAY"
    else
        log_success "البوابة المكتشفة: $GATEWAY"
    fi
    
    TARGET="$GATEWAY"
    
    # تحديث JSON
    if command -v jq &> /dev/null; then
        local temp="$LOG_DIR/temp_$$.json"
        jq --arg ip "$CURRENT_IP" --arg gw "$GATEWAY" --arg net "$NETWORK" \
            '.scan_info.target = $gw | .scan_info.network = $net | .network.local_ip = $ip | .network.gateway = $gw | .network.subnet = ($net + ".0/24")' \
            "$JSON_FILE" > "$temp" && mv "$temp" "$JSON_FILE"
    fi
}

# ============================================
# فحص المنافذ المتقدم
# ============================================

scan_ports_advanced() {
    log_info "========== فحص المنافذ المتقدم =========="
    
    local ports_mikrotik="21,22,23,53,80,443,8291,8728,8729,9201"
    local ports_winbox="64872-64875"
    local ports_vpn="1723,1194,500,4500"
    local ports_all="$ports_mikrotik,$ports_winbox,$ports_vpn"
    
    log_info "فحص المنافذ المهمة..."
    
    # فحص سريع
    local scan_result=$(nmap -p "$ports_all" -sV --open --min-rate 1000 "$TARGET" 2>/dev/null)
    
    local open_ports=()
    while IFS= read -r line; do
        if [[ "$line" =~ ([0-9]+)/tcp[[:space:]]+open[[:space:]]+(.+) ]]; then
            local port="${BASH_REMATCH[1]}"
            local service="${BASH_REMATCH[2]}"
            open_ports+=("$port")
            log_success "المنفذ $port مفتوح: $service"
            
            # إضافة إلى JSON
            if command -v jq &> /dev/null; then
                local temp="$LOG_DIR/temp_$$.json"
                jq --arg port "$port" --arg service "$service" \
                    '.ports += [{"port": $port, "service": $service, "status": "open"}]' \
                    "$JSON_FILE" > "$temp" && mv "$temp" "$JSON_FILE"
            fi
        fi
    done <<< "$scan_result"
    
    # فحص UDP للمنافذ المهمة
    log_info "فحص منافذ UDP..."
    local udp_ports="53,67,68,123,161,500,1900,5353"
    nmap -sU -p "$udp_ports" --min-rate 500 "$TARGET" 2>/dev/null | while read line; do
        if [[ "$line" =~ ([0-9]+)/udp[[:space:]]+open ]]; then
            log_success "UDP $line"
        fi
    done
    
    echo "$open_ports"
}

# ============================================
# فحص الثغرات المتقدم
# ============================================

scan_vulnerabilities() {
    log_info "========== فحص الثغرات الأمنية =========="
    
    # 1. اختبار CSRF
    log_info "اختبار CSRF..."
    local csrf_test1=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET/logout?erase-cookie=on" 2>/dev/null)
    local csrf_test2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://$TARGET/logout" -d "erase-cookie=on" 2>/dev/null)
    
    if [[ "$csrf_test1" == "200" ]] || [[ "$csrf_test2" == "200" ]] || [[ "$csrf_test2" == "302" ]]; then
        log_warning "ثغرة CSRF محتملة في صفحة logout"
        echo "- CSRF Vulnerability: /logout endpoint" >> "$REPORT_FILE"
    fi
    
    # 2. فحص PPTP
    log_info "فحص PPTP..."
    local pptp_result=$(nmap -p 1723 --script pptp-version "$TARGET" 2>/dev/null | grep -i "mikrotik")
    if [ -n "$pptp_result" ]; then
        log_warning "PPTP مفتوح: $pptp_result"
        echo "- PPTP Open: قديم وقابل للاختراق" >> "$REPORT_FILE"
    fi
    
    # 3. فحص API
    log_info "فحص RouterOS API..."
    local api_result=$(echo -e "/system/identity/print\n" | timeout 2 nc "$TARGET" 8728 2>/dev/null | head -1)
    if [ -n "$api_result" ]; then
        log_warning "API مفتوح (8728) - قد يكون عرضة للهجمات"
        echo "- API Open: port 8728 is accessible" >> "$REPORT_FILE"
    fi
    
    # 4. فحص SSL/TLS
    log_info "فحص SSL/TLS..."
    if command -v testssl.sh &> /dev/null; then
        testssl.sh --quiet "$TARGET" 2>/dev/null | grep -E "VULNERABLE|WEAK" >> "$REPORT_FILE" || true
    elif command -v nmap &> /dev/null; then
        nmap --script ssl-enum-ciphers -p 443 "$TARGET" 2>/dev/null | grep -E "VULNERABLE|weak" >> "$REPORT_FILE" || true
    fi
    
    # 5. فحص DNS Zone Transfer
    log_info "فحص DNS Zone Transfer..."
    local zone_result=$(dig @"$TARGET" axfr chcc.net 2>/dev/null | grep -v ";" | head -5)
    if [ -n "$zone_result" ]; then
        log_warning "Zone Transfer ممكن!"
        echo "- DNS Zone Transfer: possible" >> "$REPORT_FILE"
    fi
}

# ============================================
# فحص HTTP المتقدم
# ============================================

scan_http_advanced() {
    log_info "========== فحص خدمات HTTP =========="
    
    local ports_http=("80" "443" "64873" "64875")
    
    for port in "${ports_http[@]}"; do
        log_info "فحص المنفذ $port..."
        
        # فحص headers
        local headers=$(curl -s -I "http://$TARGET:$port" 2>/dev/null | head -5)
        if [ -n "$headers" ]; then
            log_success "HTTP على $port يستجيب"
            echo "$headers" >> "$LOG_FILE"
        fi
        
        # فحص صفحة login
        local login_page=$(curl -s "http://$TARGET:$port/login.html" 2>/dev/null | grep -oP '<title>\K[^<]+' | head -1)
        if [ -n "$login_page" ]; then
            log_info "صفحة login: $login_page"
        fi
        
        # فحص صفحة status
        local status_page=$(curl -s "http://$TARGET:$port/status" 2>/dev/null | grep -oP '<title>\K[^<]+' | head -1)
        if [ -n "$status_page" ]; then
            log_info "صفحة status: $status_page"
        fi
    done
}

# ============================================
# اكتشاف أجهزة MikroTik
# ============================================

discover_mikrotik_devices() {
    log_info "========== اكتشاف أجهزة MikroTik =========="
    
    local subnet="$NETWORK.0/24"
    log_info "البحث في $subnet..."
    
    local devices=$(nmap -sn "$subnet" 2>/dev/null | grep -B 2 "Routerboard" | grep "Nmap scan" | grep -oP '\d+\.\d+\.\d+\.\d+')
    
    if [ -n "$devices" ]; then
        while read -r ip; do
            log_success "جهاز MikroTik: $ip"
            echo "- $ip" >> "$REPORT_FILE"
        done <<< "$devices"
    else
        log_info "لم يتم العثور على أجهزة MikroTik إضافية"
    fi
}

# ============================================
# إنشاء التقرير النهائي
# ============================================

generate_report() {
    log_info "========== إنشاء التقرير النهائي =========="
    
    local end_time=$(date +%s)
    local duration=$((end_time - SCRIPT_START))
    
    cat > "$REPORT_FILE" << EOF
╔════════════════════════════════════════════════════════════════════╗
║     MikroTik Advanced Security Scan Report                        ║
║     Version: $SCRIPT_VERSION                                      ║
║     Date: $(date)                                                 ║
║     Duration: ${duration} seconds                                 ║
╚════════════════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════════════
  NETWORK INFORMATION
════════════════════════════════════════════════════════════════════
Local IP: $CURRENT_IP
Gateway: $GATEWAY
Network: $NETWORK.0/24

════════════════════════════════════════════════════════════════════
  OPEN PORTS & SERVICES
════════════════════════════════════════════════════════════════════
$(grep "open" "$LOG_FILE" 2>/dev/null | grep -v "grep" || echo "No open ports found")

════════════════════════════════════════════════════════════════════
  VULNERABILITIES FOUND
════════════════════════════════════════════════════════════════════
$(grep -E "VULNERABLE|ثغرة|possible|Open|CSRF|PPTP" "$LOG_FILE" 2>/dev/null | grep -v "grep" || echo "No critical vulnerabilities found")

════════════════════════════════════════════════════════════════════
  RECOMMENDATIONS
════════════════════════════════════════════════════════════════════
1. تحديث RouterOS إلى أحدث إصدار
2. تعطيل الخدمات غير المستخدمة (FTP, Telnet, HTTP)
3. استخدام HTTPS بدلاً من HTTP
4. تعطيل PPTP واستخدام VPN آمن (WireGuard/OpenVPN)
5. تعطيل API إذا لم يكن بحاجة له
6. تغيير كلمات المرور الافتراضية
7. تقييد الوصول للإدارة (WinBox, SSH) للشبكة المحلية
8. تفعيل جدار الحماية وتقييد المنافذ المفتوحة

════════════════════════════════════════════════════════════════════
  FILES GENERATED
════════════════════════════════════════════════════════════════════
Log File: $LOG_FILE
JSON Results: $JSON_FILE
Error Log: $ERROR_LOG

EOF

    log_success "تم حفظ التقرير في: $REPORT_FILE"
    log_success "تم حفظ السجل في: $LOG_FILE"
}

# ============================================
# إرسال إشعارات (اختياري)
# ============================================

send_notification() {
    # إشعار عبر البريد الإلكتروني (إذا تم إعداد SMTP)
    # mail -s "MikroTik Scan Complete" admin@example.com < "$REPORT_FILE" 2>/dev/null || true
    
    # إشعار عبر Telegram (اختياري)
    # curl -s -X POST "https://api.telegram.org/bot<TOKEN>/sendMessage" \
    #     -d "chat_id=<CHAT_ID>" \
    #     -d "text=MikroTik Scan Completed: $(date)" &>/dev/null || true
    
    log_info "يمكن تفعيل إشعارات البريد الإلكتروني/Telegram حسب الحاجة"
}

# ============================================
# الوظيفة الرئيسية
# ============================================

main() {
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║     MikroTik Advanced Auto Scanner v$SCRIPT_VERSION                     ║"
    echo "║     Professional Network Security Scanner                         ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    init_json
    check_dependencies
    discover_network
    scan_ports_advanced
    scan_http_advanced
    scan_vulnerabilities
    discover_mikrotik_devices
    generate_report
    send_notification
    
    echo -e "\n${GREEN}${BOLD}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ الفحص اكتمل بنجاح!${NC}"
    echo -e "${YELLOW}📁 تقرير مفصل: $REPORT_FILE${NC}"
    echo -e "${YELLOW}📄 سجل كامل: $LOG_FILE${NC}"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════════════${NC}"
}

# تشغيل السكربت
main "$@"
