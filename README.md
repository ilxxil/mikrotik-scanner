# 🔐 MikroTik Advanced Security Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Bash](https://img.shields.io/badge/shell-bash-4EAA25)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux-lightgrey)

**أداة متقدمة لفحص ثغرات أجهزة MikroTik RouterOS بشكل تلقائي واحترافي**

[التثبيت](#-التثبيت) • [الاستخدام](#-الاستخدام) • [المميزات](#-المميزات) • [النتائج](#-النتائج)

</div>

---

## 📋 نظرة عامة

**MikroTik Advanced Security Scanner** هي أداة شاملة لاختبار اختراق أجهزة MikroTik RouterOS. تقوم الأداة تلقائياً باكتشاف الشبكة، فحص المنافذ، واستكشاف الثغرات الأمنية الشائعة مثل:

- 🔴 **CSRF Attacks** - ثغرات تسجيل الخروج
- 🔴 **PPTP VPN** - بروتوكول VPN قديم وقابل للاختراق
- 🔴 **RouterOS API** - واجهة برمجة بدون تشفير
- 🔴 **WinBox Ports** - منافذ الإدارة المكشوفة
- 🔴 **DNS Zone Transfer** - تسريب معلومات DNS

---

## ✨ المميزات

| الميزة | الوصف |
|--------|-------|
| 🚀 **اكتشاف تلقائي** | يكتشف الشبكة والبوابة تلقائياً |
| 📊 **فحص شامل** | يفحص 20+ منفذ وخدمة مهمة |
| 🛡️ **كشف الثغرات** | يكتشف CSRF, PPTP, API vulnerabilities |
| 📝 **تقارير متعددة** | TXT, JSON, Log files |
| 🔧 **معالجة الأخطاء** | نظام متقدم لإدارة الأخطاء |
| 📱 **متعدد المنصات** | يعمل على Kali, Ubuntu, Termux |

---

## 🛠️ المتطلبات

- **Linux / Termux** (Android)
- **nmap** - فحص المنافذ
- **curl** - طلبات HTTP
- **jq** (اختياري) - معالجة JSON

---

## 📥 التثبيت

### طريقة 1: التثبيت السريع

```bash
git clone https://github.com/ilxxil/mikrot.git
cd mikrot
chmod +x install.sh
./install.sh
