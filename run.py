import json
import re
import argparse
import structlog
import dotenv
import os
import html
import logging
from vulnhuntr.symbol_finder import SymbolExtractor
from vulnhuntr.LLMs import Claude, ChatGPT, Ollama, QWen, Hunyuan
from vulnhuntr import prompts
from rich import print
from typing import List, Generator
from enum import Enum
from pathlib import Path
from pydantic_xml import BaseXmlModel, element
from xml.etree.ElementTree import Element, tostring
from pydantic import BaseModel, Field, constr, conint
from typing import List, Optional
from vulnhuntr import reporter
from vulnhuntr.models import *

dotenv.load_dotenv()

# 配置 logging
logger = logging.getLogger('vulnhuntr')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(Path('vulnhuntr').with_suffix('.log'), mode='w')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# 配置 structlog 使用标准的 logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True
)

import faulthandler
faulthandler.enable()

log = structlog.get_logger("vulnhuntr")

class RepoOps:
    def __init__(self, repo_path: Path | str ) -> None:
        self.repo_path = Path(repo_path)
        self.to_exclude = {'/setup.py', '/test', '/example', '/docs', '/site-packages', '.venv', 'virtualenv', '/dist'}
        self.file_names_to_exclude = ['test_', 'conftest', '_test.py']

        patterns = [
            #Async
            r'async\sdef\s\w+\(.*?request',

            # Gradio
            r'gr.Interface\(.*?\)',
            r'gr.Interface\.launch\(.*?\)',

            # Flask
            r'@app\.route\(.*?\)',
            r'@blueprint\.route\(.*?\)',
            r'class\s+\w+\(MethodView\):',
            r'@(?:app|blueprint)\.add_url_rule\(.*?\)',

            # FastAPI
            r'@app\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)',
            r'@router\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)',

            # Django
            r'url\(.*?\)', #Too broad?
            r're_path\(.*?\)',
            r'@channel_layer\.group_add',
            r'@database_sync_to_async',

            # Pyramid
            r'@view_config\(.*?\)',

            # Bottle
            r'@(?:route|get|post|put|delete|patch)\(.*?\)',

            # Tornado
            r'class\s+\w+\((?:RequestHandler|WebSocketHandler)\):',
            r'@tornado\.gen\.coroutine',
            r'@tornado\.web\.asynchronous',

            #WebSockets
            r'websockets\.serve\(.*?\)',
            r'@websocket\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)',

            # aiohttp
            r'app\.router\.add_(?:get|post|put|delete|patch|head|options)\(.*?\)',
            r'@routes\.(?:get|post|put|delete|patch|head|options)\(.*?\)',

            # Sanic
            r'@app\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)',
            r'@blueprint\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)',

            # Falcon
            r'app\.add_route\(.*?\)',

            # CherryPy
            r'@cherrypy\.expose',

            # web2py
            r'def\s+\w+\(\):\s*return\s+dict\(',

            # Quart (ASGI version of Flask)
            r'@app\.route\(.*?\)',
            r'@blueprint\.route\(.*?\)',

            # Starlette (which FastAPI is based on)
            r'@app\.route\(.*?\)',
            r'Route\(.*?\)',

            # Responder
            r'@api\.route\(.*?\)',

            # Hug
            r'@hug\.(?:get|post|put|delete|patch|options|head)\(.*?\)',

            # Dash (for analytical web applications)
            r'@app\.callback\(.*?\)',

            # GraphQL entry points
            r'class\s+\w+\(graphene\.ObjectType\):',
            r'@strawberry\.type',

            # Generic decorators that might indicate custom routing
            r'@route\(.*?\)',
            r'@endpoint\(.*?\)',
            r'@api\.\w+\(.*?\)',

            # AWS Lambda handlers (which could be used with API Gateway)
            r'def\s+lambda_handler\(event,\s*context\):',
            r'def\s+handler\(event,\s*context\):',

            # Azure Functions
            r'def\s+\w+\(req:\s*func\.HttpRequest\)\s*->',

            # Google Cloud Functions
            r'def\s+\w+\(request\):'

            # Server startup code
            r'app\.run\(.*?\)',
            r'serve\(app,.*?\)',
            r'uvicorn\.run\(.*?\)',
            r'application\.listen\(.*?\)',
            r'run_server\(.*?\)',
            r'server\.start\(.*?\)',
            r'app\.listen\(.*?\)',
            r'httpd\.serve_forever\(.*?\)',
            r'tornado\.ioloop\.IOLoop\.current\(\)\.start\(\)',
            r'asyncio\.run\(.*?\.serve\(.*?\)\)',
            r'web\.run_app\(.*?\)',
            r'WSGIServer\(.*?\)\.serve_forever\(\)',
            r'make_server\(.*?\)\.serve_forever\(\)',
            r'cherrypy\.quickstart\(.*?\)',
            r'execute_from_command_line\(.*?\)',  # Django's manage.py
            r'gunicorn\.app\.wsgiapp\.run\(\)',
            r'waitress\.serve\(.*?\)',
            r'hypercorn\.run\(.*?\)',
            r'daphne\.run\(.*?\)',
            r'werkzeug\.serving\.run_simple\(.*?\)',
            r'gevent\.pywsgi\.WSGIServer\(.*?\)\.serve_forever\(\)',
            r'grpc\.server\(.*?\)\.start\(\)',
            r'app\.start_server\(.*?\)',  # Sanic
            r'Server\(.*?\)\.run\(\)',    # Bottle
        ]

        # Compile the patterns for efficiency
        self.compiled_patterns = [re.compile(pattern) for pattern in patterns]

    def get_readme_content(self) -> str:
        # Use glob to find README.md or README.rst in a case-insensitive manner in the root directory
        prioritized_patterns = ["[Rr][Ee][Aa][Dd][Mm][Ee].[Mm][Dd]", "[Rr][Ee][Aa][Dd][Mm][Ee].[Rr][Ss][Tt]"]
        
        # First, look for README.md or README.rst in the root directory with case insensitivity
        for pattern in prioritized_patterns:
            for readme in self.repo_path.glob(pattern):
                with readme.open(encoding='utf-8') as f:
                    return f.read()
                
        # If no README.md or README.rst is found, look for any README file with supported extensions
        for readme in self.repo_path.glob("[Rr][Ee][Aa][Dd][Mm][Ee]*.[Mm][DdRrSsTt]"):
            with readme.open(encoding='utf-8') as f:
                return f.read()
        
        return

    def get_relevant_py_files(self) -> Generator[Path, None, None]:
        """Gets all Python files in a repo minus the ones in the exclude list (test, example, doc, docs)"""
        files = []
        for f in self.repo_path.rglob("*.py"):
            # Convert the path to a string with forward slashes
            f_str = str(f).replace('\\', '/')
            
            # Lowercase the string for case-insensitive matching
            f_str = f_str.lower()

            # Check if any exclusion pattern matches a substring of the full path
            if any(exclude in f_str for exclude in self.to_exclude):
                continue

            # Check if the file name should be excluded
            if any(fn in f.name for fn in self.file_names_to_exclude):
                continue
            
            files.append(f)

        return files

    def get_network_related_files(self, files: List) -> Generator[Path, None, None]:
        for py_f in files:
            with py_f.open(encoding='utf-8') as f:
                content = f.read()
            if any(re.search(pattern, content) for pattern in self.compiled_patterns):
                yield py_f

    def get_files_to_analyze(self, analyze_path: Path | None = None) -> List[Path]:
        path_to_analyze = analyze_path or self.repo_path
        if path_to_analyze.is_file():
            return [ path_to_analyze ]
        elif path_to_analyze.is_dir():
            return path_to_analyze.rglob('*.py')
        else:
            raise FileNotFoundError(f"Specified analyze path does not exist: {path_to_analyze}")

def initialize_llm(llm_arg: str, system_prompt: str = "", api_key: str = "", model_name: str = "") -> Claude | ChatGPT | Ollama | QWen | Hunyuan:
    llm_arg = llm_arg.lower()
    if llm_arg == 'claude':
        anth_model = model_name or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        # anth_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        anth_base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        llm = Claude(anth_model, anth_base_url, system_prompt)
    elif llm_arg == 'gpt':
        openai_model = model_name or os.getenv("OPENAI_MODEL", "chatgpt-4o-latest")
        # openai_model = os.getenv("OPENAI_MODEL", "chatgpt-4o-latest")
        openai_base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        llm = ChatGPT(openai_model, openai_base_url, system_prompt, skey=api_key)
    elif llm_arg == 'qwen':
        qwen_model = model_name or "qwen-long"
        llm = QWen(qwen_model, system_prompt=system_prompt, skey=api_key)
    elif llm_arg == 'hunyuan':
        hy_model = "hunyuan-turbo"
        llm = Hunyuan(hy_model, system_prompt=system_prompt, skey=api_key)
    elif llm_arg == 'ollama':
        ollama_model = model_name
        if not ollama_model: ollama_model = os.getenv("OLLAMA_MODEL", "llama3")
        ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/api/generate")
        llm = Ollama(ollama_model, ollama_base_url, system_prompt)
    else:
        raise ValueError(f"Invalid LLM argument: {llm_arg}\nValid options are: claude, gpt, ollama")
    return llm

def print_readable(report: Response) -> None:
    for attr, value in vars(report).items():
        print(f"{attr}:")
        if isinstance(value, str):
            # For multiline strings, add indentation
            lines = value.split('\n')
            for line in lines:
                print(f"  {line}")
        elif isinstance(value, list):
            # For lists, print each item on a new line
            for item in value:
                print(f"  - {item}")
        else:
            # For other types, just print the value
            print(f"  {value}")
        print('-' * 40)
        # print()  # Add an empty line between attributes


def run():
    parser = argparse.ArgumentParser(description='Analyze a GitHub project for vulnerabilities.')
    parser.add_argument('-r', '--root', type=str, required=True, help='Path to the root directory of the project')
    parser.add_argument('-a', '--analyze', type=str, help='Specific path or file within the project to analyze')
    parser.add_argument('-l', '--llm', type=str, choices=['claude', 'gpt', 'ollama', 'qwen', 'hunyuan'], default='claude', help='LLM client to use (default: claude)')
    parser.add_argument('-k', '--key', type=str, required=False, help='Specify the api key, or retrieving from env')
    parser.add_argument('-m', '--model', type=str, required=False, help='Specify the model name')
    parser.add_argument('-p', '--prompt_set', type=str, choices=['en', 'cn'], default='en', required=False, help='Prompt Set')
    parser.add_argument('-v', '--verbosity', action='count', default=0, help='Increase output verbosity (-v for INFO, -vv for DEBUG)')
    args = parser.parse_args()

    repo = RepoOps(args.root)
    code_extractor = SymbolExtractor(args.root)
    # Get repo files that don't include stuff like tests and documentation
    files = repo.get_relevant_py_files()

    # User specified --analyze flag
    if args.analyze:
        # Determine the path to analyze
        analyze_path = Path(args.analyze)

        # If the path is absolute, use it as is, otherwise join it with the root path so user can specify relative paths
        if analyze_path.is_absolute():
            files_to_analyze = repo.get_files_to_analyze(analyze_path)
        else:
            files_to_analyze = repo.get_files_to_analyze(Path(args.root) / analyze_path)

    # Analyze the entire project for network-related files
    else:
        files_to_analyze = repo.get_network_related_files(files)
    
    reporter.initialize_report()

    llm = initialize_llm(args.llm, "You are an expert works on code security", args.key, args.model)

    # Get prompt templates based on language preference
    README_SUMMARY_PROMPT_TEMPLATE = prompts.get_prompt_template("README_SUMMARY", args.prompt_set)
    SYS_PROMPT_TEMPLATE = prompts.get_prompt_template("SYS_PROMPT", args.prompt_set)
    INITIAL_ANALYSIS_PROMPT_TEMPLATE = prompts.get_prompt_template("INITIAL_ANALYSIS", args.prompt_set)
    ANALYSIS_APPROACH_TEMPLATE = prompts.get_prompt_template("ANALYSIS_APPROACH", args.prompt_set)
    GUIDELINES_TEMPLATE = prompts.get_prompt_template("GUIDELINES", args.prompt_set)
    START_COMMAND_TEMPLATE = prompts.get_prompt_template("START_COMMAND", args.prompt_set)

    # These don't need language variants
    RESPONSE_FORMAT_TEMPLATE = prompts.RESPONSE_FORMAT_TEMPLATE
    VULN_SPECIFIC_BYPASSES_AND_PROMPTS = prompts.VULN_SPECIFIC_BYPASSES_AND_PROMPTS

    readme_content = repo.get_readme_content()
    if readme_content:
        log.info("Summarizing project README")
        print("\n[*] Summarizing project README...")
        summary = llm.chat(
            (ReadmeContent(content=readme_content).to_xml(encoding='unicode') + '\n' +
            Instructions(instructions=README_SUMMARY_PROMPT_TEMPLATE).to_xml(encoding='unicode')
            )
        )
        summary = extract_between_tags("summary", summary)[0]
        log.info("README summary complete", summary=summary)
        reporter.add_summary_to_report(summary)
    else:
        log.warning("No README summary found")
        print("\n[*] No README summary found")
        summary = ''

    # Initialize the system prompt with the README summary
    system_prompt = (Instructions(instructions=SYS_PROMPT_TEMPLATE).to_xml(encoding='unicode') + '\n' +
                ReadmeSummary(readme_summary=summary).to_xml(encoding='unicode')
    )
    
    llm = initialize_llm(args.llm, system_prompt, args.key, args.model)

    # files_to_analyze is either a list of all network-related files or a list containing a single file/dir to analyze
    for py_f in files_to_analyze:
        log.info(f"Performing initial analysis", file=str(py_f))

        # This is the Initial analysis
        with py_f.open(encoding='utf-8') as f:
            content = f.read()
            if not len(content):
                continue

            print(f"[*] Initial Analyzing {py_f}")

            user_prompt =(
                    FileCode(file_path=str(py_f), file_source=content).to_xml(encoding='unicode') + '\n' +
                    Instructions(instructions=INITIAL_ANALYSIS_PROMPT_TEMPLATE).to_xml(encoding='unicode') + '\n' +
                    AnalysisApproach(analysis_approach=ANALYSIS_APPROACH_TEMPLATE).to_xml(encoding='unicode') + '\n' +
                    PreviousAnalysis(previous_analysis='').to_xml(encoding='unicode') + '\n' +
                    Guidelines(guidelines=GUIDELINES_TEMPLATE).to_xml(encoding='unicode') + '\n' +
                    RESPONSE_FORMAT_TEMPLATE + "\n" +
                    START_COMMAND_TEMPLATE
            )

            initial_analysis_report: Response = llm.chat(user_prompt, response_model=Response)
            log.info("Initial analysis complete", report=initial_analysis_report.model_dump())

            print("[*] Initial Analysis Result:")
            print('-' * 40 +'\n')
            print_readable(initial_analysis_report)

            # Secondary analysis
            if initial_analysis_report.confidence_score > 0 and len(initial_analysis_report.vulnerability_types):

                for vuln_type in initial_analysis_report.vulnerability_types:

                    # Do not fetch the context code on the first pass of the secondary analysis because the context will be from the general analysis
                    stored_code_definitions = {}
                    definitions = CodeDefinitions(definitions=[])
                    same_context = False

                    # Don't include the initial analysis or the first iteration of the secondary analysis in the user_prompt
                    previous_analysis = ''
                    previous_context_amount = 0

                    for i in range(7):
                        log.info(f"Performing vuln-specific analysis", iteration=i, vuln_type=vuln_type, file=py_f)
                        print(f"[*] Performing vuln-specific analysis, iteration:{i}, vuln_type:{vuln_type}, file:{py_f}")

                        # Only lookup context code and previous analysis on second pass and onwards
                        if i > 0:
                            previous_context_amount = len(stored_code_definitions)
                            previous_analysis = secondary_analysis_report.analysis

                            for context_item in secondary_analysis_report.context_code:
                                # Make sure bot isn't requesting the same code multiple times
                                if context_item.name not in stored_code_definitions:
                                    name = context_item.name
                                    code_line = context_item.code_line
                                    match = code_extractor.extract(name, code_line, files)
                                    if match:
                                        stored_code_definitions[name] = match

                            code_definitions = list(stored_code_definitions.values())
                            definitions = CodeDefinitions(definitions=code_definitions)
                            
                            if args.verbosity > 1:
                                for definition in definitions.definitions:
                                    if '\n' in definition.source:
                                        lines = definition.source.split('\n')
                                        snippet = lines[0] + '\n' + lines[1]
                                    else:
                                        snippet = definition.source[:75]
                                    
                                    print(f"Name: {definition.name}")
                                    print(f"Context search: {definition.context_name_requested}")
                                    print(f"File Path: {definition.file_path}")
                                    print(f"First two lines from source: \n```\n{snippet}\n```\n")

                        vuln_specific_user_prompt = (
                            FileCode(file_path=str(py_f), file_source=content).to_xml(encoding='unicode') + '\n' +
                            definitions.to_xml(encoding='unicode') + '\n' +  # These are all the requested context functions and classes
                            ExampleBypasses(
                                example_bypasses='\n'.join(VULN_SPECIFIC_BYPASSES_AND_PROMPTS[vuln_type]['bypasses'])
                            ).to_xml(encoding='unicode') + '\n' +
                            Instructions(instructions=VULN_SPECIFIC_BYPASSES_AND_PROMPTS[vuln_type]['prompt']).to_xml(encoding='unicode') + '\n' +
                            AnalysisApproach(analysis_approach=ANALYSIS_APPROACH_TEMPLATE).to_xml(encoding='unicode') + '\n' +
                            PreviousAnalysis(previous_analysis=previous_analysis).to_xml(encoding='unicode') + '\n' +
                            Guidelines(guidelines=GUIDELINES_TEMPLATE).to_xml(encoding='unicode') + '\n' +
                            RESPONSE_FORMAT_TEMPLATE + "\n" +
                            START_COMMAND_TEMPLATE
                        )

                        secondary_analysis_report: Response = llm.chat(vuln_specific_user_prompt, response_model=Response)
                        log.info("Secondary analysis complete", secondary_analysis_report=secondary_analysis_report.model_dump())

                        if args.verbosity > 0:
                            print("[*] Follow-Up Analysis Result:")
                            print('-' * 40 +'\n')
                            print_readable(secondary_analysis_report)

                        if not len(secondary_analysis_report.context_code):
                            log.debug("No new context functions or classes found")
                            print("[*] No new context functions or classes found")
                            if args.verbosity == 0:
                                print("\n[*] Follow-Up Analysis Result:")
                                print('-' * 40 +'\n')
                                print_readable(secondary_analysis_report)
                            break
                        
                        # Check if any new context code is requested
                        if previous_context_amount >= len(stored_code_definitions) and i > 0:
                            # Let it request the same context once, then on the second time it requests the same context, break
                            if same_context:
                                log.debug("No new context functions or classes requested")
                                if args.verbosity == 0:
                                    print("\n[*] Follow-Up Analysis Result:")
                                    print('-' * 40 +'\n')
                                    print_readable(secondary_analysis_report)
                                break
                            same_context = True
                            log.debug("No new context functions or classes requested")
                    
                    if secondary_analysis_report.confidence_score > 0:
                        if not secondary_analysis_report.vulnerability_types:
                            print(f"[*] Follow-up result confidence_score {secondary_analysis_report.confidence_score}, but vuln_types is empty, set to '{vuln_type}' manually")
                            secondary_analysis_report.vulnerability_types = [vuln_type]
                        reporter.add_vuln_to_report(secondary_analysis_report, str(py_f))
    reporter.finalize_report()

if __name__ == '__main__':
    run()