# قاموس بيانات مخطط الـ ERD (ماذا تكتب داخل كل جدول)

هذا الجدول مخصص لتقوم بنقل المحتويات مباشرة إلى برنامج StarUML لضمان دقة أنواع البيانات (Data Types):

### 1. جدول Profiles
| الحقل (Column) | النوع (Data Type) |
| :--- | :--- |
| id | uuid (PK) |
| user_id | uuid (FK) |
| display_name | text |
| avatar_url | text |

### 2. جدول Scanned_Assets
| الحقل (Column) | النوع (Data Type) |
| :--- | :--- |
| id | uuid (PK) |
| hostname | text |
| ip_address | text |
| os | text |
| risk | text |

### 3. جدول Scan_Results
| الحقل (Column) | النوع (Data Type) |
| :--- | :--- |
| id | uuid (PK) |
| user_id | uuid (FK) |
| name | text |
| started_at | timestamp |
| raw_output | text |
| options | text |

### 4. جدول Scan_Findings
| الحقل (Column) | النوع (Data Type) |
| :--- | :--- |
| id | uuid (PK) |
| scan_id | uuid (FK) |
| title | text |
| severity | text |
| status | text |
| target | text |

### 5. جدول Vulnerabilities
| الحقل (Column) | النوع (Data Type) |
| :--- | :--- |
| id | uuid (PK) |
| cve_id | text |
| cvss_severity | text |
| status | text |
| vulnerability_count | integer |

### 6. جدول Nvd_Cves
| الحقل (Column) | النوع (Data Type) |
| :--- | :--- |
| id | uuid (PK) |
| cve_id | text (Unique) |
| cvss_score | float |
| severity | text |
| published_date | timestamp |

### 7. جدول Exploits
| الحقل (Column) | النوع (Data Type) |
| :--- | :--- |
| id | uuid (PK) |
| exploit_id | text |
| cve_id | text (FK) |
| description | text |
| file_path | text |
