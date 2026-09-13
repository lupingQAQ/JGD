"""Update lupingQAQ profile README + github.io site with JGD."""
import subprocess
from pathlib import Path

# ─── 1. Profile README (lupingQAQ/lupingQAQ) ───
profile = Path("/tmp/lupingQAQ/README.md")
s = profile.read_text(encoding="utf-8")

jgd_section = """### [JGD — JavaGadgetDigger](https://github.com/lupingQAQ/JGD)
[![Stars](https://img.shields.io/github/stars/lupingQAQ/JGD?style=flat-square&color=red)](https://github.com/lupingQAQ/JGD/stargazers)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](https://github.com/lupingQAQ/JGD/blob/main/LICENSE)

Autonomous agent that mines Java deserialization gadget chains from any JAR directory — static bytecode analysis + dynamic JVM probes + dual-model adversarial auditing → weaponized PoC. One command, zero intermediate decisions: `JARs in → chains + PoCs out`. Includes interactive TUI (EN/CN) and CLI modes. 8 novel chains discovered (1 T1 entry + 6 T2 carriers).

English + Chinese README.

"""

# Insert after the Impacket section (before "---\n\n## Currently")
anchor = "---\n\n## Currently"
if anchor in s and "JGD" not in s:
    s = s.replace(anchor, "---\n\n" + jgd_section + "---\n\n## Currently")
    profile.write_text(s, encoding="utf-8")
    print("profile README updated")

# Add badge
s2 = profile.read_text(encoding="utf-8")
if "Java" not in s2.split("Projects")[0]:
    s2 = s2.replace(
        "![AI](https://img.shields.io/badge/AI-powered_offense_|_LLM_attacks-green?style=flat-square)",
        "![AI](https://img.shields.io/badge/AI-powered_offense_|_LLM_attacks-green?style=flat-square)\n![Java](https://img.shields.io/badge/Java-deserialization_|_gadget_chains-red?style=flat-square)")
    profile.write_text(s2, encoding="utf-8")
    print("badge added")

# ─── 2. GitHub Pages (lupingQAQ.github.io/index.html) ───
pages = Path("/tmp/lupingQAQ.github.io/index.html")
s = pages.read_text(encoding="utf-8")

# Find the projects section and add JGD card
jgd_card = """
        <div class="card" onclick="location.href='https://github.com/lupingQAQ/JGD'">
          <div class="card-tag">Agent / Tool</div>
          <h3>JGD — JavaGadgetDigger</h3>
          <p>Autonomous Java deserialization gadget chain mining agent. JARs in → chains + PoCs out. Static bytecode analysis + dynamic JVM probes + dual-model adversarial auditing.</p>
          <div class="card-meta">
            <span class="lang">Python · Java</span>
            <span class="star">★ JGD</span>
          </div>
        </div>
"""

# Insert before the closing </div> of the projects grid
# Look for the last card closing tag followed by the grid closing
import re
# Find where to insert — after the last existing card
insert_marker = '</div>\n      </div>\n\n      <footer'
if insert_marker in s and "JGD" not in s:
    s = s.replace(insert_marker,
                  jgd_card + insert_marker)
    pages.write_text(s, encoding="utf-8")
    print("github.io updated")
else:
    # Try alternate marker
    m = re.search(r'(</div>\s*</div>\s*(?:<footer|<div class="footer))', s)
    if m and "JGD" not in s:
        s = s[:m.start()] + jgd_card + s[m.start():]
        pages.write_text(s, encoding="utf-8")
        print("github.io updated (alt)")
    else:
        print("github.io: marker not found, trying manual insert")
        # Find last </div> before footer
        footer_pos = s.find('<footer')
        if footer_pos < 0:
            footer_pos = s.find('</main>')
        if footer_pos > 0 and "JGD" not in s:
            insert_at = s.rfind('</div>', 0, footer_pos)
            if insert_at > 0:
                s = s[:insert_at] + jgd_card + s[insert_at:]
                pages.write_text(s, encoding="utf-8")
                print("github.io updated (manual)")

print("done")
