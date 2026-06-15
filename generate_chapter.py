from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
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

doc = Document()

# Set default font to something that supports Arabic if possible, though docx defaults are usually okay
style = doc.styles['Normal']
font = style.font
font.name = 'Arial'
font.size = Pt(12)

# Chapter Title
add_arabic_paragraph(doc, 'الفصل الأول: مبادئ ومفاهيم في الأمن السيبراني', is_heading=True, level=0)

# 1.1 Introduction
add_arabic_paragraph(doc, '1.1 مقدمة', is_heading=True, level=1)
text1_1 = (
    "في العالم الرقمي الذي يشهد معارك خفية بين المدافعين والمهاجمين، يبرز دور \"صيادي الثغرات\" كخط الدفاع الأول. "
    "اكتشاف الثغرات في مواقع الويب هو عملية استباقية تشبه البحث عن مفاتيح خفية قد تفتح الأبواب أمام الاختراقات [1]. "
    "مع تحول حياتنا إلى الفضاء الإلكتروني، لم يعد هذا الترف رفاهية، بل أصبح درعًا واقيًا يحفظ خصوصيتنا ويحمي أصولنا الرقمية من الاستغلال."
)
add_arabic_paragraph(doc, text1_1)

# 1.2 Definition
add_arabic_paragraph(doc, '1.2 تعريف الأمن السيبراني', is_heading=True, level=1)
text1_2 = (
    "اكتشاف الثغرات الأمنية هو تخصص دقيق ضمن الأمن السيبراني، يُعنى بفحص وتقييم مواقع الويب وتطبيقاتها بحثًا عن نقاط الضعف والهنات البرمجية التي قد تستغل لاختراقها [2]. "
    "ومع الاعتماد المتزايد على الخدمات الإلكترونية، أصبح اكتشاف هذه الثغرات ضرورة حتمية لتعزيز حماية المنصات الرقمية، والحد من المخاطر التي تهدد سلامة البيانات وسير العمليات [3]."
)
add_arabic_paragraph(doc, text1_2)

# 1.3 Importance
add_arabic_paragraph(doc, '1.3 أهمية الأمن السيبراني', is_heading=True, level=1)
text1_3 = (
    "تكمن أهمية أمن المعلومات في اكتشاف ثغرات مواقع الويب في كونه حاجزًا وقائيًا يحول دون اختراق الأنظمة الرقمية [3]. "
    "حيث يمثل الاكتشاف المبكر للثغرات خط الدفاع الأول لحماية البيانات من التسرب غير المصرح به، والحفاظ على سلامة (Integrity) البيانات من العبث أو التعديل، وضمان استمرارية عمل الخدمات الإلكترونية دون انقطاع. "
    "يؤدي إهمال هذا الجانب الحاسم إلى خروقات أمنية شاملة، تتراوح بين سرقة البيانات الحساسة، تشويه المحتوى، أو تعطيل المنصات الرقمية بالكامل، مما يهدد مصداقية المنظمات واستقرار عملياتها الرقمية."
)
add_arabic_paragraph(doc, text1_3)

# 1.4 Common Threats
add_arabic_paragraph(doc, '1.4 التهديدات السيبرانية الشائعة', is_heading=True, level=1)
text1_4 = (
    "تشمل التهديدات السيبرانية الشائعة لاكتشاف الثغرات في مواقع الويب ثغرات الحقن (Injection) مثل SQL Injection وCross-Site Scripting (XSS)، "
    "وثغرات كسر المصادقة وإدارة الجلسات، بالإضافة إلى مشكلات التحكم في الوصول، وتعرّض البيانات الحساسة، وتهديدات تزييف الطلبات عبر المواقع (CSRF) [4]. "
    "كل من هذه الثغرات يمكن أن تستغل من قبل المهاجمين للوصول غير المصرح به إلى قواعد البيانات، وسرقة معلومات المستخدمين، والسيطرة على جلسات التسجيل، أو التحكم الكامل في الموقع الإلكتروني."
)
add_arabic_paragraph(doc, text1_4)

# 1.5 Basic Concepts
add_arabic_paragraph(doc, '1.5 مفاهيم أساسية في الأمن السيبراني', is_heading=True, level=1)
text1_5_intro = "الأمن السيبراني يعتمد على عدة مفاهيم أساسية تشمل السرية، السلامة، والتوافر [1] [2]:"
add_arabic_paragraph(doc, text1_5_intro)

bullet_points = [
    "• السرية: تعني حماية المعلومات من الوصول غير المصرح به.",
    "• السلامة: تعني الحفاظ على دقة واكتمال المعلومات.",
    "• التوافر: تعني ضمان أن تكون المعلومات والأنظمة متاحة عند الحاجة إليها."
]
for bp in bullet_points:
    add_arabic_paragraph(doc, bp)

# References Section
add_arabic_paragraph(doc, 'المراجع', is_heading=True, level=1)
refs = [
    "[1] Stallings, W. (2018). Computer Security: Principles and Practice. 4th Edition, Pearson.",
    "[2] NIST (2014). Special Publication 800-12 Revision 1: An Introduction to Information Security. National Institute of Standards and Technology.",
    "[3] ISO/IEC 27001:2022. Information security, cybersecurity and privacy protection — Information security management systems — Requirements.",
    "[4] OWASP Top 10:2021. The Ten Most Critical Web Application Security Risks. Open Web Application Security Project."
]
for ref in refs:
    p = doc.add_paragraph(ref)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT # References usually in English/Left-aligned

doc.save('Chapter1_Cybersecurity_Principles.docx')
