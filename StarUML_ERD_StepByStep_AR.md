# دليل الخطوات التفصيلية لإكمال مخطط الـ ERD في برنامج StarUML

بناءً على الصورة التي أرسلتها، إليك شرح "خطوة بخطوة" لما يجب عليك فعله تماماً داخل البرنامج لتصحيح أنواع البيانات ورسم العلاقات.

---

### المرحلة الأولى: تصحيح أنواع البيانات (Data Types)
في الصورة، بعض الحقول فارغة وبعضها يحتوي على أخطاء إملائية. اتبع الخطوات التالية لكل جدول:

1.  **كيف تعدل النوع؟**: اضغط ضغطة مزدوجة (Double Click) على الحقل الذي تريد تعديله (مثلاً `id`).
2.  **ماذا تكتب؟**: اكتب الاسم ثم نقطتين فوق بعض ثم النوع.
    *   *مثال:* بدلاً من `id` فقط، اكتب `id: uuid`.
    *   *تصحيح هام:* في جدول `vulnerabilities` غير كلمة `intger` إلى `integer`.

**إليك القائمة التي يجب أن تنقلها لكل جدول:**
*   **Profiles**:
    *   `id: uuid`
    *   `user_id: uuid`
    *   `display_name: text`
    *   `avatar_url: text`
*   **Scanned_Assets**:
    *   `id: uuid`
    *   `hostname: text`
    *   `ip_address: text`
    *   `os: text`
    *   `risk: text`
*   **Scan_Results**:
    *   `id: uuid`
    *   `user_id: uuid`
    *   `started_at: timestamp`
    *   `raw_output: text`
    *   `options: text`
*   **Scan_Findings**:
    *   `id: uuid`
    *   `scan_id: uuid`
    *   `title: text`
    *   `severity: text`
    *   `status: text`
    *   `target: text`

---

### المرحلة الثانية: رسم العلاقات بين الجداول (Relationships)
هذا هو الجزء الأهم لربط الجداول ببعضها منطقياً. اتبع الخطوات التالية:

1.  **اختر الأداة**: من القائمة اليسرى (Toolbox)، اذهب لأسفل قسم **Entity-Relationship**.
2.  **اختر One to Many Relationship**: (هي الأيقونة التي تظهر خطاً ينتهي بـ 3 خطوط صغيرة تشبه قدم الغراب).
3.  **طريقة الرسم**: اضغط على الجدول "الأب" واسحب الفأرة إلى الجدول "الابن".

**قم برسم الخطوط كالتالي:**
1.  **من profiles إلى scan_results**: اضغط على profiles واسحب إلى scan_results. (المعنى: المستخدم يملك عدة فحوصات).
2.  **من scan_results إلى scan_findings**: اضغط على scan_results واسحب إلى scan_findings. (المعنى: عملية الفحص تحتوي على عدة نتائج).
3.  **من nvd_cves إلى vulnerabilities**: اختر أداة **One to One Relationship**، واضغط على nvd_cves واسحب إلى vulnerabilities. (المعنى: كل ثغرة لها بيانات مرجعية عالمية واحدة).
4.  **من vulnerabilities إلى exploits**: اختر أداة **One to Many Relationship**، اضغط على vulnerabilities واسحب إلى exploits. (المعنى: الثغرة الواحدة قد يكون لها عدة أكواد استغلال).
5.  **من vulnerabilities إلى scan_findings**: اضغط على vulnerabilities واسحب إلى scan_findings. (المعنى: النتيجة المكتشفة تتبع تصنيف ثغرة معين).

---

### المرحلة الثالثة: لمسات احترافية للبحث
*   **تسمية العلاقات**: بعد رسم الخط، اضغط عليه واكتب في جهة اليمين (Properties) في خانة **Name** كلمة تصف العلاقة (مثل: `Contains`, `Owns`, `Linked to`).
*   **تنظيم الخطوط**: لجعل الخطوط مستقيمة، اضغط على الخط بزر الفأرة الأيمن واختر **Format** -> **Line Style** -> **Rectilinear**.

بهذه الخطوات، سيكون مخططك مكتملاً وجاهزاً لوضعه في الفصل الثالث من بحث التخرج كنموذج احترافي لقواعد البيانات.
