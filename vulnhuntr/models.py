import re
import json
from enum import Enum
from pydantic_xml import BaseXmlModel, element
from pydantic import BaseModel
from typing import List, Optional
from pydantic import BaseModel, Field

def extract_between_tags(tag: str, string: str, strip: bool = False) -> list[str]:
    """
    https://github.com/anthropics/anthropic-cookbook/blob/main/misc/how_to_enable_json_mode.ipynb
    """
    ext_list = re.findall(f"<{tag}>(.+?)</{tag}>", string, re.DOTALL)
    if strip:
        ext_list = [e.strip() for e in ext_list]
    return ext_list


class ContextCodeXML(BaseXmlModel, tag='context_code'):
    name: str = element(tag='name', default=None)
    reason: str = element(tag='reason', default=None)
    code_line: str = element(tag='code_line', default=None)

class VulnType(str, Enum):
    LFI = "LFI"
    RCE = "RCE"
    SSRF = "SSRF"
    AFO = "AFO"
    SQLI = "SQLI"
    XSS = "XSS"
    IDOR = "IDOR"

class ResponseXML(BaseXmlModel, tag='response'):
    scratchpad: str = element()
    analysis: str = element()
    poc: Optional[str] = element(default='')
    confidence_score: Optional[int] = element(default=0)
    vulnerability_types: List[str] = element(tag='vulnerability_types', default_factory=list)
    context_code: List[ContextCodeXML] = element(tag='context_code', default_factory=list)

    def clean_data(self):
        allowed_types = ["LFI", "RCE", "SSRF", "AFO", "SQLI", "XSS", "IDOR"]
        self.vulnerability_types = list(set([
            vt.strip()
            for v in self.vulnerability_types
            for vt in v.upper().split(",")
            if vt.strip() in allowed_types
        ]))

        self.context_code = [
            ContextCodeXML(
                name=v.name.strip() if v.name else '',
                reason=v.reason.strip() if v.reason else '',
                code_line=v.code_line.strip() if v.code_line else ''
            )
            for v in self.context_code if v.name
        ]


class ContextCode(BaseModel):
    name: str = Field(description="Function or Class name")
    reason: str = Field(description="Brief reason why this function's code is needed for analysis")
    code_line: str = Field(description="The single line of code where where this context object is referenced.")

class Response(BaseModel):
    scratchpad: str = Field(description="Your step-by-step analysis process. Output in plaintext with no line breaks.")
    analysis: str = Field(description="Your final analysis. Output in plaintext with no line breaks.")
    poc: str = Field(description="Proof-of-concept exploit, if applicable.")
    confidence_score: int = Field(description="0-10, where 0 is no confidence and 10 is absolute certainty because you have the entire user input to server output code path.")
    vulnerability_types: List[VulnType] = Field(description="The types of identified vulnerabilities")
    context_code: List[ContextCode] = Field(description="List of context code items requested for analysis, one function or class name per item. No standard library or third-party package code.")

class ReadmeContent(BaseXmlModel, tag="readme_content"):
    content: str

class ReadmeSummary(BaseXmlModel, tag="readme_summary"):
    readme_summary: str

class Instructions(BaseXmlModel, tag="instructions"):
    instructions: str

class ResponseFormat(BaseXmlModel, tag="response_format"):
    response_format: str

class AnalysisApproach(BaseXmlModel, tag="analysis_approach"):
    analysis_approach: str

class Guidelines(BaseXmlModel, tag="guidelines"):
    guidelines: str

class FileCode(BaseXmlModel, tag="file_code"):
    file_path: str = element()
    file_source: str = element()

class PreviousAnalysis(BaseXmlModel, tag="previous_analysis"):
    previous_analysis: str

class ExampleBypasses(BaseXmlModel, tag="example_bypasses"):
    example_bypasses: str

class CodeDefinition(BaseXmlModel, tag="code"):
    name: str = element()
    context_name_requested: str = element()
    file_path: str = element()
    source: str = element()

class CodeDefinitions(BaseXmlModel, tag="context_code"):
    definitions: List[CodeDefinition] = []