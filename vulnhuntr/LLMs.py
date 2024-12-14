import logging
from typing import List, Union, Dict, Any
from pydantic import BaseModel, ValidationError
from xml.sax.saxutils import escape
import anthropic
import os
import openai
import dotenv
import requests
import json
import re
import httpx
import xml.etree.ElementTree as ET
from vulnhuntr.models import extract_between_tags
from vulnhuntr.models import ResponseXML, ContextCodeXML, Response


dotenv.load_dotenv()

log = logging.getLogger(__name__)

class LLMError(Exception):
    """Base class for all LLM-related exceptions."""
    pass

class RateLimitError(LLMError):
    pass

class APIConnectionError(LLMError):
    pass

class APIStatusError(LLMError):
    def __init__(self, status_code: int, response: Dict[str, Any]):
        self.status_code = status_code
        self.response = response
        super().__init__(f"Received non-200 status code: {status_code}")

# Base LLM class to handle common functionality
class LLM:
    def __init__(self, system_prompt: str = "") -> None:
        self.system_prompt = system_prompt
        self.history: List[Dict[str, str]] = []
        self.prev_prompt: Union[str, None] = None
        self.prev_response: Union[str, None] = None
        self.prefill = None

    def _validate_response(self, response_text: str, response_model: BaseModel) -> BaseModel:
        try:
            if self.prefill:
                response_text = self.prefill + response_text
            return response_model.model_validate_json(response_text)
        except ValidationError as e:
            log.warning("[-] Response validation failed\n", exc_info=e)
            raise LLMError("Validation failed") from e

    def _add_to_history(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": content})

    def _handle_error(self, e: Exception, attempt: int) -> None:
        log.error(f"An error occurred on attempt {attempt}: {str(e)}", exc_info=e)
        raise e

    def _log_response(self, response: Dict[str, Any]) -> None:
        usage_info = response.usage.__dict__
        log.debug("Received chat response", extra={"usage": usage_info})

    def _unified_xml_element_order(self, xml_string):
        root = ET.fromstring(xml_string)
        new_root = ET.Element("response")
        order = ["scratchpad", "analysis", "poc", "confidence_score", "vulnerability_types", "context_code"]
        for tag in order:
            for elem in root.findall(tag):
                new_root.append(elem)
        new_xml_string = ET.tostring(new_root, encoding='unicode')
        return new_xml_string

    def _auto_fix_xml_response(self, text):
        # fix XML tag
        tags = [
            "response", "code_line", "context_code", "confidence_score", "vulnerability_types",
            "name", "reason", "analysis", "poc", "scratchpad"
        ]
        
        for tag in tags:
            text = re.sub(rf"<[^/!][^<>]*?{tag}[^/<>]*?>", f"<{tag}>", text)
            text = re.sub(rf"</[^<>]*?{tag}[^/<>]*?>", f"</{tag}>", text)
        
        # fix XML element content：escape，validate and correct value
        for tag in ["poc", "analysis", "scratchpad", "confidence_score"]:
            pattern = re.compile(rf'(<{tag}>)(.*?)(</{tag}>)', re.DOTALL)
            def escape_match(match):
                start_tag, content, end_tag = match.groups()
                if "confidence_score" in start_tag:
                    new_content = content.strip()
                    if not new_content.isdigit():
                        new_content = "0"
                else:
                    new_content = escape(content)
                return f'{start_tag}{new_content}{end_tag}'
            text = pattern.sub(escape_match, text)

        text = self._unified_xml_element_order(text)

        return text

    def chat(self, user_prompt: str, response_model: BaseModel = None, max_tokens: int = 6000) -> Union[BaseModel, str]:
        # log.debug(user_prompt)
        retry_cnt = 0
        while retry_cnt < 3:
            try:
                if retry_cnt > 0:
                    user_prompt += "\nImportant: ensure the response meets the format requirements!\n非常重要: 请确保回答的内容符合格式要求!"
                    if response_model is Response:
                        user_prompt += "\nImportant: response content must starts from '<response>' string\n非常重要: 回答内容必须以 '<response>' 字符串开头"
                messages = self.create_messages(user_prompt)
                response = self.send_message(messages, max_tokens, response_model)
                self._log_response(response)

                response_text = self.get_response(response)
                log.debug(response_text)

                if response_model is Response:
                    # convert XML to JSON
                    if '<response>' in response_text and '</response>' in response_text:
                        value = extract_between_tags('response', response_text)[0]
                        response_text = f"<response>{value}</response>"

                        log.debug("fix Response XML text")
                        response_text = self._auto_fix_xml_response(response_text)

                        response = ResponseXML.from_xml(response_text)
                        response.clean_data()
                        response_text_json = response.json()
                    else:
                        # not well-formed response, retry
                        print(f"[-] No <response> element, Retry...")
                        retry_cnt += 1
                        continue
                
                self._add_to_history("assistant", response_text)
                
                if response_model:
                    response_text_json_valid = self._validate_response(response_text_json, response_model)
                    self._add_to_history("user", user_prompt)
                    return response_text_json_valid
                else:
                    self._add_to_history("user", user_prompt)
                    return response_text
            except Exception as e:
                log.error(e)
                print(f"[-] Response Parse Error: {e}, Retry...")
                retry_cnt += 1
        raise(Exception("Response Parse Error, Max Retry Count Exceed"))

class Claude(LLM):
    def __init__(self, model: str, base_url: str, system_prompt: str = "") -> None:
        super().__init__(system_prompt)
        # API key is retrieved from an environment variable by default
        self.client = anthropic.Anthropic(max_retries=3, base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        if "Provide a very concise summary of the README.md content" in user_prompt:
            messages = [{"role": "user", "content": user_prompt}]
        else:
            self.prefill = "{    \"scratchpad\": \"1."
            messages = [{"role": "user", "content": user_prompt}, 
                        {"role": "assistant", "content": self.prefill}]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model: BaseModel) -> Dict[str, Any]:
        try:
            # response_model is not used here, only in ChatGPT
            return self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=self.system_prompt,
                messages=messages
            )
        except anthropic.APIConnectionError as e:
            raise APIConnectionError("Server could not be reached") from e
        except anthropic.RateLimitError as e:
            raise RateLimitError("Request was rate-limited") from e
        except anthropic.APIStatusError as e:
            raise APIStatusError(e.status_code, e.response) from e

    def get_response(self, response: Dict[str, Any]) -> str:
        return response.content[0].text.replace('\n', '')


class ChatGPT(LLM):
    def __init__(self, model: str, base_url: str, system_prompt: str = "", skey: str = "") -> None:
        super().__init__(system_prompt)
        if not skey: skey = os.getenv("LLM_API_KEY")
        http_client = httpx.Client(
            transport=httpx.HTTPTransport(local_address="0.0.0.0"),
            verify=False
        )
        # uncomment this to use proxy
        # http_client = httpx.Client(
        #     proxies="http://127.0.0.1:8084",
        #     transport=httpx.HTTPTransport(local_address="0.0.0.0"),
        #     verify=False
        # )
        self.client = openai.OpenAI(api_key=skey, base_url=base_url, http_client=http_client)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        messages = [{"role": "system", "content": self.system_prompt}, 
                    {"role": "user", "content": user_prompt}]
        # print(self.system_prompt)
        # print(user_prompt)
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model=None) -> Dict[str, Any]:
        try:
            params = {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
            }

            return self.client.chat.completions.create(**params)
        except openai.APIConnectionError as e:
            raise APIConnectionError("The server could not be reached") from e
        except openai.RateLimitError as e:
            raise RateLimitError("Request was rate-limited; consider backing off") from e
        except openai.APIStatusError as e:
            raise APIStatusError(e.status_code, e.response) from e
        except Exception as e:
            raise LLMError(f"An unexpected error occurred: {str(e)}") from e

    def get_response(self, response: Dict[str, Any]) -> str:
        response = response.choices[0].message.content
        return response


class QWen(LLM):
    def __init__(self, model: str, base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1", system_prompt: str = "", skey: str = "") -> None:
        super().__init__(system_prompt)
        if not skey: skey = os.getenv("LLM_API_KEY")
        self.client = openai.OpenAI(api_key=skey, base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        messages = [{"role": "system", "content": self.system_prompt}, 
                    {"role": "user", "content": user_prompt}]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model=None) -> Dict[str, Any]:
        try:
            params = {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
            }

            return self.client.chat.completions.create(**params)
        except openai.APIConnectionError as e:
            raise APIConnectionError("The server could not be reached") from e
        except openai.RateLimitError as e:
            raise RateLimitError("Request was rate-limited; consider backing off") from e
        except openai.APIStatusError as e:
            raise APIStatusError(e.status_code, e.response) from e
        except Exception as e:
            raise LLMError(f"An unexpected error occurred: {str(e)}") from e

    def get_response(self, response: Dict[str, Any]) -> str:
        response = response.choices[0].message.content
        return response


class Hunyuan(LLM):
    def __init__(self, model: str, base_url: str = "https://api.hunyuan.cloud.tencent.com/v1", system_prompt: str = "", skey: str = "") -> None:
        super().__init__(system_prompt)
        if not skey: skey = os.getenv("LLM_API_KEY")
        self.client = openai.OpenAI(api_key=skey, base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        messages = [{"role": "system", "content": self.system_prompt}, 
                    {"role": "user", "content": user_prompt}]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model=None) -> Dict[str, Any]:
        try:
            params = {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
            }

            return self.client.chat.completions.create(**params)
        except openai.APIConnectionError as e:
            raise APIConnectionError("The server could not be reached") from e
        except openai.RateLimitError as e:
            raise RateLimitError("Request was rate-limited; consider backing off") from e
        except openai.APIStatusError as e:
            raise APIStatusError(e.status_code, e.response) from e
        except Exception as e:
            raise LLMError(f"An unexpected error occurred: {str(e)}") from e

    def get_response(self, response: Dict[str, Any]) -> str:
        response = response.choices[0].message.content
        return response

class Ollama(LLM):
    def __init__(self, model: str, base_url: str, system_prompt: str = "") -> None:
        super().__init__(system_prompt)
        self.api_url = base_url
        self.model = model

    def create_messages(self, user_prompt: str) -> str:
        return user_prompt

    def send_message(self, user_prompt: str, max_tokens: int, response_model: BaseModel) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "prompt": user_prompt,
            "options": {
            "temperature": 1,
            "system": self.system_prompt,
            }
            ,"stream":False,
        }

        try:
            response = requests.post(self.api_url, json=payload)
            return response
        except requests.exceptions.RequestException as e:
            if e.response.status_code == 429:
                raise RateLimitError("Request was rate-limited") from e
            elif e.response.status_code >= 500:
                raise APIConnectionError("Server could not be reached") from e
            else:
                raise APIStatusError(e.response.status_code, e.response.json()) from e

    def get_response(self, response: Dict[str, Any]) -> str:
        response = response.json()['response']
        return response

    def _log_response(self, response: Dict[str, Any]) -> None:
        log.debug("Received chat response", extra={"usage": "Ollama"})

