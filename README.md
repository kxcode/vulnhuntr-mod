# Vulnhuntr-Mod

This is a modified version of [vulnhuntr](https://github.com/protectai/vulnhuntr), a tool designed for static code security analysis to discover security vulnerabilities. This tool is driven by LLM (Large Language Model) technology.

## Changes

- Optimized the interaction format for large models, enhancing the compatibility of large model outputs
- Supported more large models, such as Qwen and Hunyuan
- Added multi-language Prompt options, including Chinese Prompts
- Added simple reporting functionality and more command-line options
- Optimized console log information

### Command Line Interface

```
usage: run.py [-h] -r ROOT [-a ANALYZE] [-l {claude,gpt,ollama,qwen,hunyuan}] [-k KEY] [-m MODEL] [-p {en,cn}] [-v]

Analyze a GitHub project for vulnerabilities.

options:
  -h, --help            show this help message and exit
  -r ROOT, --root ROOT  Path to the root directory of the project
  -a ANALYZE, --analyze ANALYZE
                        Specific path or file within the project to analyze
  -l {claude,gpt,ollama,qwen,hunyuan}, --llm {claude,gpt,ollama,qwen,hunyuan}
                        LLM client to use (default: claude)
  -k KEY, --key KEY     Specify the api key, or retrieving from env
  -m MODEL, --model MODEL
                        Specify the model name
  -p {en,cn}, --prompt_set {en,cn}
                        Prompt Set
  -v, --verbosity       Increase output verbosity (-v for INFO, -vv for DEBUG)
```

You can also set the API Key for GPT, Qwen, and Hunyuan in environment variables, for example:
```
export LLM_API_KEY=sk-xxx
```

## Authors

- Dan McInerney: dan@protectai.com, [@DanHMcinerney](https://x.com/DanHMcInerney)
- Marcello Salvati: marcello@protectai.com, [@byt3bl33d3r](https://x.com/byt3bl33d3r)
- Modified by KINGX: [kingx.me](https://kingx.me)