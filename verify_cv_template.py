from docx import Document
from docx.shared import Inches

def verify_cv_template():
    doc = Document("CV_Template.docx")
    section = doc.sections[0]

    # Verify Left Margin (should be 3.0 inches)
    print(f"Left Margin: {section.left_margin.inches} inches")
    assert abs(section.left_margin.inches - 3.0) < 0.1, "Left margin is not 3.0 inches"

    # Verify Header contains drawing elements
    header = section.header
    header_xml = header._element.xml
    print("Checking header for VML elements...")
    assert "v:rect" in header_xml, "Sidebar background (v:rect) missing from header"
    assert "v:shape" in header_xml, "Sidebar text box (v:shape) missing from header"
    assert "CONTACT" in header_xml, "Placeholder text 'CONTACT' missing from sidebar"

    print("Verification successful!")

if __name__ == "__main__":
    verify_cv_template()
