from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.shared import Pt

def set_rtl(paragraph):
    p = paragraph._element
    pPr = p.get_or_add_pPr()
    bidi = pPr.find(qn('w:bidi'))
    if bidi is None:
        bidi = pPr.makeelement(qn('w:bidi'))
        pPr.append(bidi)
    bidi.set(qn('w:val'), '1')
    paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT

def add_arabic_paragraph(doc, text, is_heading=False, level=1):
    if is_heading:
        p = doc.add_heading(text, level=level)
    else:
        p = doc.add_paragraph(text)
    set_rtl(p)
    return p

def set_table_rtl(table):
    tbl = table._element
    tblPr = tbl.find(qn('w:tblPr'))
    if tblPr is None:
        tblPr = OxmlElement('w:tblPr')
        tbl.insert(0, tblPr)
    bidiVisual = tblPr.find(qn('w:bidiVisual'))
    if bidiVisual is None:
        bidiVisual = OxmlElement('w:bidiVisual')
        tblPr.append(bidiVisual)

doc = Document()

# Global Style
style = doc.styles['Normal']
font = style.font
font.name = 'Arial'
font.size = Pt(12)

# ==========================================
# CHAPTER 1
# ==========================================
add_arabic_paragraph(doc, 'الفصل الأول: مبادئ ومفاهيم في الأمن السيبراني', is_heading=True, level=0)

add_arabic_paragraph(doc, '1.1 مقدمة', is_heading=True, level=1)
add_arabic_paragraph(doc, "في العالم الرقمي الذي يشهد معارك خفية بين المدافعين والمهاجمين، يبرز دور \"صيادي الثغرات\" كخط الدفاع الأول. اكتشاف الثغرات في مواقع الويب هو عملية استباقية تشبه البحث عن مفاتيح خفية قد تفتح الأبواب أمام الاختراقات [1]. مع تحول حياتنا إلى الفضاء الإلكتروني، لم يعد هذا الترف رفاهية، بل أصبح درعًا واقيًا يحفظ خصوصيتنا ويحمي أصولنا الرقمية من الاستغلال.")

add_arabic_paragraph(doc, '1.2 تعريف الأمن السيبراني', is_heading=True, level=1)
add_arabic_paragraph(doc, "اكتشاف الثغرات الأمنية هو تخصص دقيق ضمن الأمن السيبراني، يُعنى بفحص وتقييم مواقع الويب وتطبيقاتها بحثًا عن نقاط الضعف والهنات البرمجية التي قد تستغل لاختراقها [2]. ومع الاعتماد المتزايد على الخدمات الإلكترونية، أصبح اكتشاف هذه الثغرات ضرورة حتمية لتعزيز حماية المنصات الرقمية، والحد من المخاطر التي تهدد سلامة البيانات وسير العمليات [3].")

add_arabic_paragraph(doc, '1.3 أهمية الأمن السيبراني', is_heading=True, level=1)
add_arabic_paragraph(doc, "تكمن أهمية أمن المعلومات في اكتشاف ثغرات مواقع الويب في كونه حاجزًا وقائيًا يحول دون اختراق الأنظمة الرقمية. حيث يمثل الاكتشاف المبكر للثغرات خط الدفاع الأول لحماية البيانات من التسرب غير المصرح به، والحفاظ على سلامة (Integrity) البيانات من العبث أو التعديل، وضمان استمرارية عمل الخدمات الإلكترونية دون انقطاع [3]. يؤدي إهمال هذا الجانب الحاسم إلى خروقات أمنية شاملة، تتراوح بين سرقة البيانات الحساسة، تشويه المحتوى، أو تعطيل المنصات الرقمية بالكامل، مما يهدد مصداقية المنظمات واستقرار عملياتها الرقمية.")

add_arabic_paragraph(doc, '1.4 التهديدات السيبرانية الشائعة', is_heading=True, level=1)
add_arabic_paragraph(doc, "تشمل التهديدات السيبرانية الشائعة لاكتشاف الثغرات في مواقع الويب ثغرات الحقن (Injection) مثل SQL Injection وCross-Site Scripting (XSS)، وثغرات كسر المصادقة وإدارة الجلسات، بالإضافة إلى مشكلات التحكم في الوصول، وتعرّض البيانات الحساسة، وتهديدات تزييف الطلبات عبر المواقع (CSRF) [4]. كل من هذه الثغرات يمكن أن تستغل من قبل المهاجمين للوصول غير المصرح به إلى قواعد البيانات، وسرقة معلومات المستخدمين، والسيطرة على جلسات التسجيل، أو التحكم الكامل في الموقع الإلكتروني.")

add_arabic_paragraph(doc, '1.5 مفاهيم أساسية في الأمن السيبراني', is_heading=True, level=1)
add_arabic_paragraph(doc, "الأمن السيبراني يعتمد على عدة مفاهيم أساسية تشمل السرية، السلامة، والتوافر (CIA Triad) [1] [2]:")
for bp in ["• السرية: تعني حماية المعلومات من الوصول غير المصرح به.", "• السلامة: تعني الحفاظ على دقة واكتمال المعلومات.", "• التوافر: تعني ضمان أن تكون المعلومات والأنظمة متاحة عند الحاجة إليها."]:
    add_arabic_paragraph(doc, bp)

doc.add_page_break()

# ==========================================
# CHAPTER 2
# ==========================================
add_arabic_paragraph(doc, 'الفصل الثاني: المعلومات الأساسية اللازمة لتوضيح أهمية اكتشاف الثغرات', is_heading=True, level=0)

add_arabic_paragraph(doc, '2.1 المقدمة', is_heading=True, level=1)
add_arabic_paragraph(doc, "في العصر الرقمي الحديث، أصبحت المواقع الإلكترونية والتطبيقات الويب تمثل الواجهة الأساسية لأنشطة المؤسسات. ومع ذلك، تشهد الهجمات الإلكترونية على هذه التطبيقات ارتفاعًا غير مسبوق، سواء كانت من مهاجمين أفراد أو مجموعات منظمة تستهدف البيانات والبنى التحتية [5].")
add_arabic_paragraph(doc, "تشير الإحصاءات إلى أن أكثر من 70% من حوادث الاختراق في السنوات الأخيرة كان سببها ثغرات غير اكتشفت في تطبيقات الويب، مثل ثغرات SQL Injection، وCross-Site Scripting (XSS)، وInsecure Direct Object Reference (IDOR)، وثغرات إعداد الخوادم [4].")
add_arabic_paragraph(doc, "ونظرًا للتنوع الكبير في طبيعة الثغرات واختلاف الأدوات المستخدمة في الكشف عنها، أصبحت المؤسسات بحاجة إلى حلول مؤتمتة وذكية تساعدها في اكتشاف الثغرات بشكل شامل، وتقديم تحليل موحّد ومنسّق للنتائج يسهل قراءته من قبل فرق التطوير والأمن [6].")
add_arabic_paragraph(doc, "من هنا، جاءت فكرة إنشاء منصة إلكترونية موحدة تجمع بين أدوات فحص متعددة، وتحلل نواتجها باستخدام منهجية معيارية، وتولّد تقارير جاهزة تُمكّن فرق الأمن السيبراني من إدارة المخاطر بفاعلية. هذه المنصة تُعتبر خطوة نحو دمج التحليل الأمني الآلي مع التحليل البشري، وتُمكّن المؤسسات من تحويل الأمن السيبراني من مهمة تفاعلية إلى عملية استباقية وقائية.")

add_arabic_paragraph(doc, '2.2 أهمية البروتوكولات في فحص ثغرات الويب', is_heading=True, level=1)
add_arabic_paragraph(doc, "البروتوكولات في فحص ثغرات الويب تلعب دوراً أساسياً وحيوياً لأنها تشكل القنوات والوسائل التي يتم من خلالها التواصل بين أداة الفحص ومواقع الويب المستهدفة [7]. بدون بروتوكولات واضحة وموثوقة، يصبح من الصعب جدياً تنفيذ الفحوصات بشكل دقيق أو سريع، لأن الاختبار يعتمد على نقل البيانات بين الماسح (scanner) والخادم الذي يُفحص.")

add_arabic_paragraph(doc, '2.2.1 بروتوكول HTTP/HTTPS', is_heading=True, level=2)
add_arabic_paragraph(doc, "يوفر طبقة أمان عبر التشفير (في حالة HTTPS)، مما يساعد على الكشف الدقيق عن ثغرات متعلقة بالأمان والبيانات المرسلة [8]. هذا البروتوكول هو الأساس لأي فحص ثغرات في تطبيقات الويب لضمان التقاط كل التفاعلات بين المستخدم والموقع.")

add_arabic_paragraph(doc, '2.2.2 بروتوكول TCP/IP', is_heading=True, level=2)
add_arabic_paragraph(doc, "يمثل مجموعة بروتوكولات أساسية لنقل البيانات عبر الشبكة، حيث يضمن TCP النقل الموثوق للحزم ويوفر آلية التحكم بتدفق البيانات، ما يؤثر إيجاباً على دقة وسرعة إرسال واستقبال بيانات الفحص للمواقع [7]. IP مسؤول عن توجيه الحزم عبر الشبكات. اعتماد هذه الطبقة يؤمن فحص الشبكة بفعالية.")

add_arabic_paragraph(doc, '2.2.3 بروتوكول DNS', is_heading=True, level=2)
add_arabic_paragraph(doc, "يحول أسماء النطاق إلى عناوين IP، وبالتالي تمكين أدوات الفحص من الوصول للمواقع المستهدفة بدقة وسرعة [7]. دقة عمل DNS تؤثر على سرعة بداية عملية الفحص.")

add_arabic_paragraph(doc, '2.2.4 بروتوكول ICMP', is_heading=True, level=2)
add_arabic_paragraph(doc, "يستخدم للكشف عن إتاحة الاتصال عبر إرسال رسائل اختبار مثل (Ping)، ويساعد في قياس زمن الاستجابة ونوعية الاتصال مع السيرفر، ما يوفر مؤشرات أولية عن حالة الهدف قبل الفحص العميق [9].")

# Table 1: Protocols
table1 = doc.add_table(rows=5, cols=4)
table1.style = 'Table Grid'
set_table_rtl(table1)
headers = ['البروتوكول', 'تأثيره على الدقة', 'تأثيره على السرعة', 'ملاحظات']
p_data = [
    ['HTTP/HTTPS', 'عالي جداً لأنه يحتوي على محتوى البيانات والتفاعلات', 'متوسط (التشفير قد يبطئ قليلاً)', 'أساس دقة فحص ثغرات تطبيقات الويب'],
    ['TCP/IP', 'يوفر نقل بيانات موثوق بدقة عالية', 'عالي (ينظم تدفق البيانات)', 'يدعم كل عمليات نقل البيانات بين العميل والخادم'],
    ['DNS', 'دقة عالية في توجيه الفحص للموقع الصحيح', 'سرعة عالية في تحويل الأسماء', 'مشكلة في DNS قد تعيق الفحص'],
    ['ICMP', 'دقة منخفضة في اكتشاف الثغرات', 'سرعة عالية في اختبار وجود السيرفر', 'يستخدم لأغراض التشخيص وانتقاء الأهداف']
]
for i, h in enumerate(headers):
    cell = table1.cell(0, i)
    cell.text = h
    set_rtl(cell.paragraphs[0])
for r, row in enumerate(p_data):
    for c, val in enumerate(row):
        cell = table1.cell(r+1, c)
        cell.text = val
        set_rtl(cell.paragraphs[0])

add_arabic_paragraph(doc, '2.4.1 أنظمة التشغيل ودورها في اكتشاف ثغرات الويب', is_heading=True, level=1)
add_arabic_paragraph(doc, "تلعب أنظمة التشغيل دورًا أساسيًا في مجال أمن المعلومات، لأنها تشكل البيئة التي تُشغَّل عليها أدوات الفحص والتحليل [6]. تختلف قدرات أنظمة التشغيل بحسب دعمها للأدوات الأمنية وإدارة الشبكات. يُفضَّل استخدام أنظمة توفر مرونة عالية مثل Kali Linux التي تأتي مسبقة التثبيت بمئات الأدوات [10].")

# Table 2: OS Comparison
table2 = doc.add_table(rows=5, cols=4)
table2.style = 'Table Grid'
set_table_rtl(table2)
os_headers = ['المعيار', 'توزيعات لينكس (Kali, Parrot)', 'Windows', 'macOS']
os_data = [
    ['الجمهور', 'المحترفون ومختبرو الاختراق', 'المبتدئون ومطورو الويب', 'المطورون ومختبرو الأمن'],
    ['الأدوات', 'ممتاز (مسبقة التثبيت بالأدوات)', 'جيد (يتطلب تثبيت وتكوين يدوي)', 'جيد إلى ممتاز (عبر Homebrew)'],
    ['المرونة', 'ممتاز (وصول كامل للجذر)', 'محدود (الواجهة الرسومية أساس)', 'جيد جداً (بيئة Unix)'],
    ['الأمان والعزل', 'ممتاز (عادة داخل آلة افتراضية)', 'جيد', 'جيد (بنية Unix آمنة)']
]
for i, h in enumerate(os_headers):
    cell = table2.cell(0, i)
    cell.text = h
    set_rtl(cell.paragraphs[0])
for r, row in enumerate(os_data):
    for c, val in enumerate(row):
        cell = table2.cell(r+1, c)
        cell.text = val
        set_rtl(cell.paragraphs[0])

add_arabic_paragraph(doc, '2.4.2 نظام التشغيل المستخدم في المشروع (Kali Linux)', is_heading=True, level=2)
add_arabic_paragraph(doc, "في هذا المشروع، تم الاعتماد بشكل حصري على نظام التشغيل Kali Linux كبيئة تقنية متكاملة. يعود هذا الاختيار إلى الطبيعة المتخصصة للنظام الذي يوفر دعماً أصيلاً (Native Support) لكافة أدوات الفحص المستخدمة في المنصة، مما يقلل من تعقيدات التوافقية ويسمح بالوصول المباشر إلى موارد الشبكة اللازمة لإجراء عمليات المسح والتحليل بدقة عالية [10].")

add_arabic_paragraph(doc, '2.5.1 بيئة العمل الموحدة (Unified Environment)', is_heading=True, level=1)
add_arabic_paragraph(doc, "تم دمج مرحلتي التطوير والتنفيذ ضمن بيئة عمل واحدة تعتمد على Kali Linux. هذا الدمج يضمن التوافق التام بين الخادم (Backend) وأدوات الفحص الأمنية، ويسهل عملية إدارة الموارد وتتبع العمليات الخلفية أثناء عمليات المسح الفعلي.")

add_arabic_paragraph(doc, '2.5.2 واجهة برمجة التطبيقات (API / ABI)', is_heading=True, level=1)
add_arabic_paragraph(doc, "واجهة برمجة التطبيقات (API) هي الوسيط الذي يسمح للتطبيقات بالتواصل فيما بينها (يربط الواجهة بالخادم الخلفي). أما ABI فهي مسؤولة عن طريقة تفاعل البرامج على المستوى التنفيذي لتشغيل الأدوات من النظام.")

# ==========================================
# REFERENCES
# ==========================================
add_arabic_paragraph(doc, 'المراجع', is_heading=True, level=1)
refs = [
    "[1] Stallings, W. (2018). Computer Security: Principles and Practice.",
    "[2] NIST (2014). SP 800-12 Rev. 1: Introduction to Information Security.",
    "[3] ISO/IEC 27001:2022. Information security management systems.",
    "[4] OWASP Top 10:2021. The Ten Most Critical Web Application Security Risks.",
    "[5] Engebretson, P. (2013). The Basics of Hacking and Penetration Testing.",
    "[6] Scarfone, K., & Hoffman, P. (2008). NIST SP 800-115: Technical Guide to Information Security Testing.",
    "[7] Tanenbaum, A. S., & Wetherall, D. J. (2011). Computer Networks.",
    "[8] Fielding, R., et al. (1999). RFC 2616: HTTP/1.1.",
    "[9] Postel, J. (1981). RFC 792: ICMP.",
    "[10] Hertzog, R., et al. (2017). Kali Linux Revealed."
]
for r in refs:
    p = doc.add_paragraph(r)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT

doc.save('Graduation_Thesis_Draft.docx')
