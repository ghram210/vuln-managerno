# المرجع النهائي لأنواع البيانات والعلاقات في مخطط الـ ERD

إليك الدليل الكامل والمفصل لكل جدول في مخططك، مع تحديد "نوع الحقل" (Data Type) لكل سطر، وشرح العلاقات التي تربط هذه الجداول ببعضها.

---

### 1. أنواع الحقول لكل جدول (Data Types Reference)

#### جدول الـ Profiles (بيانات المستخدمين)
*   **id**: `uuid` (المفتاح الأساسي)
*   **user_id**: `uuid` (الربط مع نظام الصلاحيات)
*   **display_name**: `text`
*   **avatar_url**: `text`

#### جدول الـ Scanned_Assets (الأصول المفحوصة)
*   **id**: `uuid`
*   **hostname**: `text`
*   **ip_address**: `text`
*   **os**: `text`
*   **risk**: `text` (أو `string`)

#### جدول الـ Scan_Results (نتائج العمليات)
*   **id**: `uuid`
*   **user_id**: `uuid`
*   **name**: `text`
*   **target**: `text`
*   **tool**: `text`
*   **status**: `text`
*   **started_at**: `timestamp` (أو `datetime`)
*   **raw_output**: `text`
*   **options**: `text`

#### جدول الـ Scan_Findings (الثغرات المكتشفة في فحص معين)
*   **id**: `uuid`
*   **scan_id**: `uuid` (مفتاح أجنبي للربط مع العملية)
*   **title**: `text`
*   **severity**: `text`
*   **status**: `text`
*   **target**: `text`

#### جدول الـ Vulnerabilities (إدارة الثغرات الموحدة)
*   **id**: `uuid`
*   **cve_id**: `text`
*   **cvss_severity**: `text`
*   **exploit_status**: `text`
*   **status**: `text`
*   **exprt_rating**: `text`
*   **vulnerability_count**: `integer` (تأكد من تصحيح الإملاء من intger إلى integer)

#### جدول الـ Nvd_Cves (البيانات العالمية)
*   **id**: `uuid`
*   **cve_id**: `text`
*   **description**: `text`
*   **cvss_score**: `float`
*   **severity**: `text`
*   **published_date**: `timestamp`

#### جدول الـ Exploits (أكواد الاستغلال)
*   **id**: `uuid`
*   **exploit_id**: `text`
*   **cve_id**: `text`
*   **description**: `text`
*   **file_path**: `text`

---

### 2. العلاقات بين الجداول (Entity Relationships)

يجب عليك استخدام أداة (One to Many Relationship) أو (One to One) من القائمة اليسرى في برنامج StarUML لربط الجداول كالتالي:

1.  **من Profiles إلى Scan_Results**:
    *   نوع العلاقة: **One to Many** (رأس السهم عند Scan_Results).
    *   المنطق: المستخدم الواحد يمكنه إجراء عدة عمليات فحص.

2.  **من Scan_Results إلى Scan_Findings**:
    *   نوع العلاقة: **One to Many** (رأس السهم عند Scan_Findings).
    *   المنطق: عملية الفحص الواحدة تحتوي على العديد من النتائج المكتشفة.

3.  **من Scan_Findings إلى Vulnerabilities**:
    *   نوع العلاقة: **Many to One** (رأس السهم عند Vulnerabilities).
    *   المنطق: عدة نتائج مكتشفة قد تشير إلى نفس نوع الثغرة (CVE).

4.  **من Vulnerabilities إلى Nvd_Cves**:
    *   نوع العلاقة: **One to One**.
    *   المنطق: كل سجل إدارة ثغرة يقابله سجل معلومات واحد في قاعدة البيانات العالمية.

5.  **من Vulnerabilities إلى Exploits**:
    *   نوع العلاقة: **One to Many** (رأس السهم عند Exploits).
    *   المنطق: الثغرة الواحدة قد يتوفر لها أكثر من كود استغلال (Exploit) مختلف.

---

### 3. نصيحة أخيرة للتنسيق في StarUML:
عند إضافة العلاقة، تأكد من الضغط على الخط وكتابة اسم العلاقة (مثل: `Contains` أو `Matched with`) لتبدو اللوحة احترافية في بحث التخرج.
