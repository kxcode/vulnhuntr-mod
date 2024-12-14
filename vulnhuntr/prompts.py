LFI_TEMPLATE = """
Combine the code in <file_code> and <context_code> then analyze the code for remotely-exploitable Local File Inclusion (LFI) vulnerabilities by following the remote user-input call chain of code.

LFI-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - open(), file(), io.open()
   - os.path.join() for file paths
   - Custom file reading functions

2. Path Traversal Opportunities:
   - User-controlled file paths or names
   - Dynamic inclusion of files or modules

3. File Operation Wrappers:
   - Template engines with file inclusion features
   - Custom file management classes

4. Indirect File Inclusion:
   - Configuration file parsing
   - Plugin or extension loading systems
   - Log file viewers

5. Example LFI-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation
- Potential for null byte injection or encoding tricks
- Interaction with file system access controls
"""

RCE_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Remote Code Execution (RCE) vulnerabilities by following the remote user-input call chain of code.

RCE-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - eval(), exec(), subprocess modules
   - os.system(), os.popen()
   - pickle.loads(), yaml.load(), json.loads() with custom decoders

2. Indirect Code Execution:
   - Dynamic imports (e.g., __import__())
   - Reflection/introspection misuse
   - Server-side template injection

3. Command Injection Vectors:
   - Shell command composition
   - Unsanitized use of user input in system calls

4. Deserialization Vulnerabilities:
   - Unsafe deserialization of user-controlled data

5. Example RCE-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into these high-risk areas
- Potential for filter evasion or sanitization bypasses
- Environment-specific factors (e.g., Python version, OS) affecting exploitability
"""

XSS_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Cross-Site Scripting (XSS) vulnerabilities by following the remote user-input call chain of code.

XSS-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - HTML rendering functions
   - JavaScript generation or manipulation
   - DOM manipulation methods

2. Output Contexts:
   - Unescaped output in HTML content
   - Attribute value insertion
   - JavaScript code or JSON data embedding

3. Input Handling:
   - User input reflection in responses
   - Sanitization and encoding functions
   - Custom input filters or cleaners

4. Indirect XSS Vectors:
   - Stored user input (e.g., in databases, files)
   - URL parameter reflection
   - HTTP header injection points

5. Example XSS-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into HTML, JavaScript, or JSON contexts
- Effectiveness of input validation, sanitization, and output encoding
- Potential for filter evasion using encoding or obfuscation
- Impact of Content Security Policy (CSP) if implemented
"""

AFO_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Arbitrary File Overwrite (AFO) vulnerabilities by following the remote user-input call chain of code.

AFO-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - open() with write modes
   - os.rename(), shutil.move()
   - Custom file writing functions

2. Path Traversal Opportunities:
   - User-controlled file paths
   - Directory creation or manipulation

3. File Operation Wrappers:
   - Custom file management classes
   - Frameworks' file handling methods

4. Indirect File Writes:
   - Log file manipulation
   - Configuration file updates
   - Cache file creation

5. Example AFO-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation
- Potential for race conditions in file operations
"""

SSRF_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Server-Side Request Forgery (SSRF) vulnerabilities by following the remote user-input call chain of code.

SSRF-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - requests.get(), urllib.request.urlopen()
   - Custom HTTP clients
   - API calls to external services

2. URL Parsing and Validation:
   - URL parsing libraries usage
   - Custom URL validation routines

3. Indirect SSRF Vectors:
   - File inclusion functions (e.g., reading from URLs)
   - XML parsers with external entity processing
   - PDF generators, image processors using remote resources

4. Cloud Metadata Access:
   - Requests to cloud provider metadata URLs

5. Example SSRF-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences outgoing network requests
- Effectiveness of URL validation and whitelisting approaches
- Potential for DNS rebinding or time-of-check to time-of-use attacks
"""

SQLI_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable SQL Injection (SQLI) vulnerabilities by following these steps:

1. Identify Entry Points:
   - Locate all points where remote user input is received (e.g., API parameters, form submissions).

2. Trace Input Flow:
   - Follow the user input as it flows through the application.
   - Note any transformations or manipulations applied to the input.

3. Locate SQL Operations:
   - Find all locations where SQL queries are constructed or executed.
   - Pay special attention to:
     - Direct SQL query construction (e.g., cursor.execute())
     - ORM methods that accept raw SQL (e.g., Model.objects.raw())
     - Custom query builders

4. Analyze Input Handling:
   - Examine how user input is incorporated into SQL queries.
   - Look for:
     - String concatenation or formatting in SQL queries
     - Parameterized queries implementation
     - Dynamic table or column name usage

5. Evaluate Security Controls:
   - Identify any input validation, sanitization, or escaping mechanisms.
   - Assess the effectiveness of these controls against SQLI attacks.

6. Consider Bypass Techniques:
   - Analyze potential ways to bypass identified security controls.
   - Reference the SQLI-specific bypass techniques provided.

7. Assess Impact:
   - Evaluate the potential impact if the vulnerability is exploited.
   - Consider the sensitivity of the data accessible through the vulnerable query.

When analyzing, consider:
- The complete path from user input to SQL execution
- Any gaps in the analysis where more context is needed, if you need more context code, free to use <context_code> tag in response
- The effectiveness of any security measures in place
- Potential for filter evasion in different database contexts
"""

IDOR_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Insecure Direct Object Reference (IDOR) vulnerabilities.

IDOR-Specific Focus Areas:
1. Look for code segments involving IDs, keys, filenames, session tokens, or any other unique identifiers that might be used to access resources (e.g., user_id, file_id, order_id).

2. Common Locations:
   - URLs/Routes: Check if IDs are passed directly in the URL parameters (e.g., /user/{user_id}/profile).
   - Form Parameters: Look for IDs submitted through forms.
   - API Endpoints: Examine API requests where IDs are sent in request bodies or headers.

3. Ensure Authorization is Enforced:
   - Verify that the code checks the user's authorization before allowing access to the resource identified by the ID.
   - Look for authorization checks immediately after the object reference is received.

4. Common Functions:
   - Functions like `has_permission()`, `is_authorized()`, or similar should be present near the object access code.
   - Absence of such checks could indicate a potential IDOR vulnerability.

5. Example IDOR-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input is used when processing a request.
- Presence of any logic responsible for determining the authentication/authorization of a user.
"""

VULN_SPECIFIC_BYPASSES_AND_PROMPTS = {
    "LFI": {
        "prompt": LFI_TEMPLATE,
        "bypasses" : [
            "../../../../etc/passwd",
            "/proc/self/environ",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "file:///etc/passwd",
            "C:\\win.ini"
            "/?../../../../../../../etc/passwd"
        ]
    },
    "RCE": {
        "prompt": RCE_TEMPLATE,
        "bypasses" : [
            "__import__('os').system('id')",
            "eval('__import__(\\'os\\').popen(\\'id\\').read()')",
            "exec('import subprocess;print(subprocess.check_output([\\'id\\']))')",
            "globals()['__builtins__'].__import__('os').system('id')",
            "getattr(__import__('os'), 'system')('id')",
            "$(touch${IFS}/tmp/mcinerney)",
            "import pickle; pickle.loads(b'cos\\nsystem\\n(S\"id\"\\ntR.')"
        ]
    },
    "SSRF": {
        "prompt": SSRF_TEMPLATE,
        "bypasses": [
            "http://0.0.0.0:22",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/",
            "ftp://anonymous:anonymous@127.0.0.1:21",
            "gopher://127.0.0.1:9000/_GET /"
        ]
    },
    "AFO": {
        "prompt": AFO_TEMPLATE,
        "bypasses": [
            "../../../etc/passwd%00.jpg",
            "shell.py;.jpg",
            ".htaccess",
            "/proc/self/cmdline",
            "../../config.py/."
        ]
    },
    "SQLI": {
        "prompt": SQLI_TEMPLATE,
        "bypasses": [
            "' UNION SELECT username, password FROM users--",
            "1 OR 1=1--",
            "admin'--",
            "1; DROP TABLE users--",
            "' OR '1'='1"
        ]
    },
    "XSS": {
        "prompt": XSS_TEMPLATE,
        "bypasses": [
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "${7*7}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(\"id\").read()}}{%endif%}{% endfor %}",
            "<script>alert(document.domain)</script>",
            "javascript:alert(1)"
        ]
    },
    "IDOR": {
        "prompt": IDOR_TEMPLATE,
        "bypasses": []
    }
}

# 第一轮初始化分析时, 不需要请求 context_code
INITIAL_ANALYSIS_PROMPT_TEMPLATE = """
Analyze the code in <file_code> tags for potential remotely exploitable vulnerabilities:
1. Identify all remote user input entry points (e.g., API endpoints, form submissions) and if you can't find that, request the necessary classes or functions in the <context_code> tags.
2. Locate potential vulnerability sinks for:
   - Local File Inclusion (LFI)
   - Arbitrary File Overwrite (AFO)
   - Server-Side Request Forgery (SSRF)
   - Remote Code Execution (RCE)
   - Cross-Site Scripting (XSS)
   - SQL Injection (SQLI)
   - Insecure Direct Object Reference (IDOR)
3. Note any security controls or sanitization measures encountered along the way so you can craft bypass techniques for the proof of concept (PoC).
4. Highlight areas where more context is needed to complete the analysis.

Be generous and thorough in identifying potential vulnerabilities as you'll analyze more code in subsequent steps so if there's just a possibility of a vulnerability, include it the <vulnerability_types> tags, and set the confidence_score to be greater than 0.
"""

README_SUMMARY_PROMPT_TEMPLATE = """
Provide a very concise summary of the README.md content in <readme_content></readme_content> tags from a security researcher's perspective, focusing specifically on:
1. The project's main purpose
2. Any networking capabilities, such as web interfaces or remote API calls that constitute remote attack surfaces
3. Key features that involve network communications

Please keep the summary brief and to the point, highlighting only the most relevant networking-related functionality as it relates to attack surface.

Output in <summary></summary> XML tags.
"""

GUIDELINES_TEMPLATE = """Reporting Guidelines:
1. XML Format:
   - Follow the XML Schema in <response_format> to generate code audit result in well-formed XML format.
   - Provide a single, well-formed XML report combining all findings.
   - Use empty string for any aspect of the report that you lack the necessary information for.
   - Place your step-by-step analysis in the <scratchpad> element, before doing a final analysis in the <analysis> element.
   - Start response with <response>

2. Context Requests:
   - Classes: Use ClassName1,ClassName2
   - Functions: Use func_name,ClassName.method_name
   - If you request ClassName, do not also request ClassName.method_name as that code will already be fetched with the ClassName request.
   - Important: Do not request code from standard libraries or third-party packages. Simply use what you know about them in your analysis.
   - Include the code where the context object is referenced, enclosed the single line in <code_line> tags. The code must be present in the <file_source> provided by the user.

3. Vulnerability Reporting:
   - Report only remotely exploitable vulnerabilities (no local access/CLI args).
   - Always include at least one vulnerability_type field when requesting context.
   - Provide a confidence score (0-10) and detailed justification for each vulnerability. The confidence score must be greater than 0 if there is any vulnerability or potential vulnerability.
   - Important: mThe higher the possibility of a vulnerability, the higher the confidence score should be.
   - If your proof of concept (PoC) exploit does not start with remote user input via remote networking calls such as remote HTTP, API, or RPC calls, set the confidence score to 6 or below.
   
4. Proof of Concept:
   - Include a PoC exploit or detailed exploitation steps for each vulnerability.
   - Ensure PoCs are specific to the analyzed code, not generic examples.
   - Review the code path ofthe potential vulnerability and be sure that the PoC bypasses any security controls in the code path.
"""

ANALYSIS_APPROACH_TEMPLATE = """Analysis Instructions:
1. Comprehensive Review:
   - Thoroughly examine the content in <file_code>, <context_code> tags (if provided) with a focus on remotely exploitable vulnerabilities.

2. Vulnerability Scanning:
   - You only care about remotely exploitable network related components and remote user input handlers.
   - Identify potential entry points for vulnerabilities.
   - Consider non-obvious attack vectors and edge cases.

3. Code Path Analysis:
   - Very important: trace the flow of user input from remote request source to function sink.
   - Examine input validation, sanitization, and encoding practices.
   - Analyze how data is processed, stored, and output.

4. Security Control Analysis:
   - Evaluate each security measure's implementation and effectiveness.
   - Formulate potential bypass techniques, considering latest exploit methods.

6. Context-Aware Analysis:
   - If this is a follow-up analysis, build upon previous findings in <previous_analysis> using the new information provided in the <context_code>.
   - Request additional context code as needed to complete the analysis and you will be provided with the necessary code.
   - One <context_code> tag in response for one context code. Use multiple <context_code> tags to request multiple pieces of context code.
   - Confirm that the requested context class or function is not already in the <context_code> tags from the user's message.

7. Final Review:
   - Confirm your proof of concept (PoC) exploits bypass any security controls.
   - Important: Double-check that your XML response is well-formed and complete.
   - Ensure the returned XML content has correct syntax and uses proper closing tags. """


SYS_PROMPT_TEMPLATE = """
You are the world's foremost expert in Python security analysis, renowned for uncovering novel and complex vulnerabilities in web applications. Your task is to perform an exhaustive static code analysis, focusing on remotely exploitable vulnerabilities including but not limited to:

1. Local File Inclusion (LFI)
2. Remote Code Execution (RCE)
3. Server-Side Request Forgery (SSRF)
4. Arbitrary File Overwrite (AFO)
5. SQL Injection (SQLI)
6. Cross-Site Scripting (XSS)
7. Insecure Direct Object References (IDOR)

Your analysis must:
- Meticulously track user input from remote sources to high-risk function sinks.
- Uncover complex, multi-step vulnerabilities that may bypass multiple security controls.
- Consider non-obvious attack vectors and chained vulnerabilities.
- Identify vulnerabilities that could arise from the interaction of multiple code components.

If you don't have the complete code chain from user input to high-risk function, strategically request the necessary context to fill in the gaps in the <context_code> tags of your response.

The project's README summary is provided in <readme_summary> tags. Use this to understand the application's purpose and potential attack surfaces.

Remember, you have many opportunities to respond and request additional context. Use them wisely to build a comprehensive understanding of the application's security posture.

Output your findings in XML format, conforming to the schema in <response_format> tags. 
"""

RESPONSE_FORMAT_TEMPLATE = """
<response_format>
<![CDATA[
This is the XSD(XML Schema Definition) of response XML:
```
<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">

  <!-- root element -->
  <xs:element name="response">
    <xs:complexType>
      <xs:sequence>
        <!-- Your step-by-step analysis process. Output in plaintext with no line breaks. -->
        <xs:element name="scratchpad" minOccurs="1"></xs:element>

        <!-- Your final analysis. Output in plaintext with no line breaks. -->
        <xs:element name="analysis" minOccurs="1"></xs:element>

        <!-- Proof-of-concept exploit, if applicable. -->
        <xs:element name="poc" minOccurs="0"></xs:element>

        <!-- possibility of vulnerabilities, from 0 to 10, where 0 indicates no vulnerability exists and 10 indicates certainty of a vulnerability existing. The higher the score, the greater the likelihood of a vulnerability existing. -->
        <xs:element name="confidence_score" type="xs:int" minOccurs="1">
         <xs:simpleType>
            <xs:restriction base="xs:int">
               <xs:minInclusive value="0"/>
               <xs:maxInclusive value="10"/>
            </xs:restriction>
         </xs:simpleType>
        </xs:element>

        <!-- Use multiple vulnerability_types elements if there are multiple identified vulnerability types. -->
        <xs:element name="vulnerability_types" minOccurs="0" maxOccurs="unbounded">
         <xs:simpleType>
            <xs:restriction base="xs:string">
              <xs:enumeration value="LFI"/>
              <xs:enumeration value="RCE"/>
              <xs:enumeration value="SSRF"/>
              <xs:enumeration value="AFO"/>
              <xs:enumeration value="SQLI"/>
              <xs:enumeration value="XSS"/>
              <xs:enumeration value="IDOR"/>
            </xs:restriction>
          </xs:simpleType>
        </xs:element>

        <!-- A context_code tag can only request the code for one function, class, or method. Use multiple <context_code> tags to request multiple pieces of context code. -->
        <xs:element name="context_code" minOccurs="0" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
              <!-- Function or Class name -->
              <xs:element name="name" type="xs:string" minOccurs="1"></xs:element>
              <!-- Brief reason why this function's code is needed for analysis -->
              <xs:element name="reason" type="xs:string" minOccurs="1"></xs:element>
              <!-- the code where this context object is referenced, just single line -->
              <xs:element name="code_line" type="xs:string" minOccurs="1"></xs:element>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
```
]]>
</response_format>
"""

README_SUMMARY_PROMPT_TEMPLATE_CN = """
从安全研究人员的角度，简要总结 readme_content 标签中的 README.md 内容，特别关注以下几点：

项目的主要目的。
任何可能构成远程攻击面的网络功能，如网络接口、远程 API 调用等。
涉及网络通信的关键特性。
请保持总结简洁明了，仅突出与攻击面相关的最重要的网络功能。

以 XML 格式在 summary 标签中输出总结内容，内容为纯文本格式的一段话。
"""

INITIAL_ANALYSIS_PROMPT_TEMPLATE_CN = """
分析file_code标签中给定的源代码以查找潜在的远程可利用漏洞:
找到所有远程用户输入入口(如: API接口、表单提交), 如果找不到, 请在context_code标签中请求相关的Class、Method、Function
查找以下潜在漏洞：
- 本地文件包含(LFI)
- 任意文件覆盖(AFO)
- 服务器端请求伪造(SSRF)
- 远程代码执行(RCE)
- 跨站脚本攻击(XSS)
- SQL 注入(SQLI)
- 不安全的直接对象引用(IDOR)

1. 注意分析过程中遇到的安全验证、安全过滤措施, 以便构造出可以绕过安全策略的PoC
2. 着重强调那些需要更多上下文信息来进一步分析的内容
3. 你可以在后续步骤中请求分析更多代码，所以要全面识别潜在漏洞
4. 重要：找到所有可能存在的漏洞, 在vulnerability_types标签中输出漏洞类型, 并设置相应的confidence_score分值
"""

SYS_PROMPT_TEMPLATE_CN = """
你是全球首屈一指的 Python 安全分析专家, 以挖掘网络应用中的新型和复杂漏洞而闻名。你的任务是进行详尽的静态代码分析, 重点关注远程可利用的漏洞, 包括但不限于:

1. 本地文件包含(LFI)
2. 远程代码执行(RCE)
3. 服务器端请求伪造(SSRF)
4. 任意文件覆盖(AFO)
5. SQL 注入(SQLI)
6. 跨站脚本(XSS)
7. 不安全的直接对象引用(IDOR)

你的分析必须：
- 仔细跟踪用户输入的数据流转, 使用source-sink代码审计思路, 从"远程输入"跟踪到"高风险函数"
- 挖掘需要绕过多个安全控制的复杂多步骤漏洞
- 考虑不明显的攻击向量以及多个风险点组成的链式漏洞(chained vulnerabilities)
- 识别可能由于多个代码组件交互而产生的漏洞

如果缺少从"用户输入"到"高风险函数"的完整代码, 请在你输出的context_code标签中请求必要的上下文以填补逻辑空白
利用readme_summary标签中的项目README文档摘要,可以了解应用程序的项目信息和潜在攻击面
请记住, 你可以多次请求额外的上下文代码, 明智的利用这个能力, 以全面了解应用程序的安全状况

以 XML 格式输出结果
"""

GUIDELINES_TEMPLATE_CN = """报告指南：
1. XML格式:
   - 提供一个包含所有发现的、格式良好的完整的XML报告
   - 将逐步分析的过程放在scratchpad标签中, 最终分析结论放在analysis标签中
2.上下文请求：
   - 类Classes: 使用ClassName1,ClassName2
   - 函数Function: 使用func_name,ClassName.method_name
   - 如果请求ClassName, 不要同时请求ClassName.method_name, 因为请求ClassName时已经包含了该方法的代码
   - 重要：不要请求标准库或第三方包的代码。在分析中直接使用你对它们的了解
3.漏洞报告：
   - 仅报告可远程利用的漏洞(不包括本地访问/命令行参数)
   - 请求上下文时, 必须至少包含一个vulnerability_type字段, 且置信度分数必须大于0
   - 为每个漏洞提供置信度评分(confidence_score), 漏洞存在的可能性越高, 则置信度分数越高。0表示不存在漏洞, 10分表示确信存在。
   - 如果你的PoC中的输入点不是从远程HTTP、API或RPC调用等远程用户输入开始, 则将置信度分数设为6或以下
4.概念验证(PoC):
   - 为每个漏洞包含一个PoC漏洞利用或详细的利用步骤
   - 确保PoC针对所分析的代码, 而不是通用示例
"""

ANALYSIS_APPROACH_TEMPLATE_CN = """分析方法：
1. 结合`file_code`和`context_code`中的源代码来综合判断，彻底分析
2. 漏洞扫描：
   - 只关注可远程可利用的漏洞，关注远程用户输入
   - 识别出任何潜在的漏洞入口点，并按需要请求更多的上下文代码
3. 数据流分析：
   - 根据source-sink方法论，追踪用户的输入流，分析数据的处理、存储和输出逻辑
4. 安全措施分析：
   - 非常重要：仔细分析漏洞路径上的每一个处理措施，分析这些处理措施是否有效，是否可以防御漏洞
   - 如果存在安全措施，则细心制定针对性的绕过方法
5. 结合上下文分析：
   - 如果当前不是首轮分析, 则根据`previous_analysis`以及`context_code`中提供的补充信息进行再次判断
   - 如果分析需要更多代码，可以在回答中使用context_code标签提出请求
   - 确认请求的上下文类或函数不在已提供的`context_code`中
6. 最终审查：
   - 确保PoC概念验证代码绕过了所有的安全控制措施
   - 重要：仔细检查XML响应内容的格式是否正确且完整
"""


# Define language-specific prompt templates
PROMPT_TEMPLATES = {
    "en": {
        "README_SUMMARY": README_SUMMARY_PROMPT_TEMPLATE,
        "INITIAL_ANALYSIS": INITIAL_ANALYSIS_PROMPT_TEMPLATE,
        "SYS_PROMPT": SYS_PROMPT_TEMPLATE,
        "ANALYSIS_APPROACH": ANALYSIS_APPROACH_TEMPLATE,
        "GUIDELINES": GUIDELINES_TEMPLATE,
        "START_COMMAND": "Start code security audit according to the previous instructions guidelines approaches and code"
    },
    "cn": {
        "README_SUMMARY": README_SUMMARY_PROMPT_TEMPLATE_CN,
        "INITIAL_ANALYSIS": INITIAL_ANALYSIS_PROMPT_TEMPLATE_CN,
        "SYS_PROMPT": SYS_PROMPT_TEMPLATE_CN,
        "ANALYSIS_APPROACH": ANALYSIS_APPROACH_TEMPLATE_CN,
        "GUIDELINES": GUIDELINES_TEMPLATE_CN,
        "START_COMMAND": "根据前面的任务信息和指令开始代码安全审计"
    }
}

def get_prompt_template(template_name: str, language: str = "en") -> str:
    """
    Get prompt template by name and language.
    
    Args:
        template_name: Name of the template to retrieve
        language: Language code ("en" or "cn"), defaults to "en"
    
    Returns:
        The requested prompt template string
    """
    # Default to English if language not found
    if language not in PROMPT_TEMPLATES:
        language = "en"
    
    return PROMPT_TEMPLATES[language].get(template_name, PROMPT_TEMPLATES["en"][template_name])