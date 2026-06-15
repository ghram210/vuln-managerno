from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.shared import Pt, Inches

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

# Set default font
style = doc.styles['Normal']
font = style.font
font.name = 'Arial'
font.size = Pt(11)

# Chapter Title
add_arabic_paragraph(doc, 'الفصل الثاني: المعلومات الأساسية اللازمة لتوضيح أهمية اكتشاف الثغرات', is_heading=True, level=0)

# 2.1 Introduction
add_arabic_paragraph(doc, '2.1 المقدمة', is_heading=True, level=1)
text2_1 = (
    "في العصر الرقمي الحديث، أصبحت المواقع الإلكترونية والتطبيقات الويب تمثل الواجهة الأساسية لأنشطة المؤسسات. "
    "ومع ذلك، تشهد الهجمات الإلكترونية على هذه التطبيقات ارتفاعًا غير مسبوق [1]. "
    "تشير الإحصاءات إلى أن نسبة كبيرة من حوادث الاختراق تعود لثغرات غير مكتشفة مثل SQL Injection وXSS [2]. "
    "ونظرًا لتنوع الثغرات، أصبحت المؤسسات بحاجة إلى حلول مؤتمتة وذكية تساعدها في الاكتشاف الشامل والتحليل الموحد للنتائج. "
    "من هنا، جاءت فكرة إنشاء منصة إلكترونية موحدة تجمع بين أدوات فحص متعددة، وتحلل نواتجها باستخدام منهجية معيارية [3]."
)
add_arabic_paragraph(doc, text2_1)

# 2.2 Importance of Protocols
add_arabic_paragraph(doc, '2.2 أهمية البروتوكولات في فحص ثغرات الويب', is_heading=True, level=1)
text2_2 = (
    "البروتوكولات في فحص ثغرات الويب تلعب دوراً أساسياً وحيوياً لأنها تشكل القنوات التي يتم من خلالها التواصل بين أداة الفحص والهدف [4]. "
    "بدون بروتوكولات واضحة، يصعب تنفيذ الفحوصات بدقة، لأن الاختبار يعتمد على نقل البيانات بين الماسح (Scanner) والخادم المستهدف."
)
add_arabic_paragraph(doc, text2_2)

# 2.2.1 HTTP/HTTPS
add_arabic_paragraph(doc, '2.2.1 بروتوكول HTTP/HTTPS', is_heading=True, level=2)
add_arabic_paragraph(doc, "يوفر طبقة أمان عبر التشفير (في حالة HTTPS)، مما يساعد على الكشف الدقيق عن ثغرات البيانات المرسلة. هذا البروتوكول هو الأساس لأي فحص ثغرات في تطبيقات الويب [5].")

# 2.2.2 TCP/IP
add_arabic_paragraph(doc, '2.2.2 بروتوكول TCP/IP', is_heading=True, level=2)
add_arabic_paragraph(doc, "يمثل مجموعة بروتوكولات أساسية لنقل البيانات عبر الشبكة. يضمن TCP النقل الموثوق للحزم ويوفر آلية التحكم بالتدفق [4]. IP مسؤول عن توجيه الحزم، واعتماد هذه الطبقة يؤمن فحص الشبكة بفعالية [6].")

# 2.2.3 DNS
add_arabic_paragraph(doc, '2.2.3 بروتوكول DNS', is_heading=True, level=2)
add_arabic_paragraph(doc, "يحول أسماء النطاق إلى عناوين IP، مما يمكن أدوات الفحص من الوصول للمواقع المستهدف بدقة وسرعة [4].")

# 2.2.4 ICMP
add_arabic_paragraph(doc, '2.2.4 بروتوكول ICMP', is_heading=True, level=2)
add_arabic_paragraph(doc, "يستخدم للكشف عن إتاحة الاتصال عبر إرسال رسائل اختبار مثل (Ping)، ويساعد في قياس زمن الاستجابة ونوعية الاتصال [7].")

# Protocol Table
add_arabic_paragraph(doc, 'جدول: مقارنة البروتوكولات وتأثيرها على الفحص', is_heading=False)
table1 = doc.add_table(rows=5, cols=4)
table1.style = 'Table Grid'
set_table_rtl(table1)

headers = ['البروتوكول', 'تأثيره على الدقة', 'تأثيره على السرعة', 'ملاحظات']
data = [
    ['HTTP/HTTPS', 'عالي جداً', 'متوسط (التشفير قد يبطئ قليلاً)', 'أساس دقة فحص ثغرات تطبيقات الويب'],
    ['TCP/IP', 'عالي (نقل موثوق)', 'عالي (تنظيم التدفق)', 'يدعم كل عمليات نقل البيانات'],
    ['DNS', 'دقة عالية في التوجيه', 'سرعة عالية في التحويل', 'مشاكل DNS قد تعيق الفحص'],
    ['ICMP', 'منخفضة في اكتشاف الثغرات', 'سرعة عالية في اختبار الوجود', 'يستخدم للتشخيص الأولي']
]

for i, header in enumerate(headers):
    cell = table1.cell(0, i)
    cell.text = header
    set_rtl(cell.paragraphs[0])

for r, row_data in enumerate(data):
    for c, val in enumerate(row_data):
        cell = table1.cell(r+1, c)
        cell.text = val
        set_rtl(cell.paragraphs[0])

# 2.4.1 OS Role
add_arabic_paragraph(doc, '2.4.1 أنظمة التشغيل ودورها في اكتشاف ثغرات الويب', is_heading=True, level=1)
add_arabic_paragraph(doc, "تلعب أنظمة التشغيل دورًا أساسيًا كبيئة لتشغيل أدوات الفحص [3]. يفضل استخدام أنظمة توفر مرونة عالية ودعمًا قويًا لسطر الأوامر مثل Kali Linux [8].")

# OS Table
table2 = doc.add_table(rows=5, cols=4)
table2.style = 'Table Grid'
set_table_rtl(table2)

os_headers = ['المعيار', 'توزيعات لينكس (Kali, Parrot)', 'Windows', 'macOS']
os_data = [
    ['الجمهور', 'المحترفون ومختبرو الاختراق', 'المبتدئون والمطورون', 'المطورون ومختبرو الأمن'],
    ['التوفر والأدوات', 'ممتاز (مئات الأدوات مسبقة التثبيت)', 'جيد (يتطلب تثبيت يدوي)', 'جيد إلى ممتاز (عبر Homebrew)'],
    ['المرونة والتحكم', 'ممتاز (وصول كامل للجذر)', 'محدود (الواجهة الرسومية أساس)', 'جيد جداً (بيئة Unix)'],
    ['العزل والأمان', 'ممتاز (غالباً في آلة افتراضية)', 'جيد', 'جيد (بنية Unix آمنة)']
]

for i, header in enumerate(os_headers):
    cell = table2.cell(0, i)
    cell.text = header
    set_rtl(cell.paragraphs[0])

for r, row_data in enumerate(os_data):
    for c, val in enumerate(row_data):
        cell = table2.cell(r+1, c)
        cell.text = val
        set_rtl(cell.paragraphs[0])

# 2.4.2 Project OS
add_arabic_paragraph(doc, '2.4.2 أنظمة التشغيل المستخدمة في المشروع (Windows و Linux)', is_heading=True, level=2)
add_arabic_paragraph(doc, "• Windows: يستخدم كنظام أساسي لتطوير واجهة المستخدم وإدارة المشروع باستخدام VS Code.")
add_arabic_paragraph(doc, "• Linux (Kali Linux): يستخدم لتشغيل أدوات فحص الثغرات مثل Nmap و SQLmap لقوته في التعامل مع الشبكات [8].")

# 2.5.1 Environments
add_arabic_paragraph(doc, '2.5.1 بيئات العمل (Development & Execution Environments)', is_heading=True, level=1)
add_arabic_paragraph(doc, "توجد بيئتان رئيسيتان في المشروع:")
add_arabic_paragraph(doc, "1. بيئة التطوير (Windows): مخصصة للبرمجة والتصميم وإدارة الكود.")
add_arabic_paragraph(doc, "2. بيئة التنفيذ (Kali Linux): مخصصة للتنفيذ الفعلي للأدوات الأمنية وجمع النتائج.")

# 2.5.2 API/ABI
add_arabic_paragraph(doc, '2.5.2 واجهة برمجة التطبيقات (API / ABI)', is_heading=True, level=1)
add_arabic_paragraph(doc, "الـ API هي الوسيط الذي يربط الواجهة الأمامية بالخادم الخلفي وأدوات الفحص. الـ ABI مسؤولة عن التفاعل على المستوى التنفيذي مع النظام لتشغيل الأدوات واستعادة النتائج.")

# References
add_arabic_paragraph(doc, 'المراجع', is_heading=True, level=1)
refs = [
    "[1] Engebretson, P. (2013). The Basics of Hacking and Penetration Testing. Syngress.",
    "[2] OWASP Top 10:2021. The Ten Most Critical Web Application Security Risks.",
    "[3] Scarfone, K., & Hoffman, P. (2008). NIST SP 800-115: Technical Guide to Information Security Testing and Assessment.",
    "[4] Tanenbaum, A. S., & Wetherall, D. J. (2011). Computer Networks. 5th Edition, Pearson.",
    "[5] Fielding, R., et al. (1999). RFC 2616: Hypertext Transfer Protocol -- HTTP/1.1.",
    "[6] Postel, J. (1981). RFC 791: Internet Protocol.",
    "[7] Postel, J. (1981). RFC 792: Internet Control Message Protocol (ICMP).",
    "[8] Hertzog, R., O'Gorman, J., & Aharoni, M. (2017). Kali Linux Revealed: Mastering the Penetration Testing Distribution. Offsec Press."
]
for ref in refs:
    p = doc.add_paragraph(ref)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT

doc.save('Chapter2_Vulnerability_Discovery_Importance.docx')
