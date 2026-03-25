# Dependency Confusion

> A dependency confusion attack or supply chain substitution attack occurs when a software installer script is tricked into pulling a malicious code file from a public repository instead of the intended file of the same name from an internal repository.

## Tools

* [visma-prodsec/confused](https://github.com/visma-prodsec/confused) - Tool to check for dependency confusion vulnerabilities in multiple package management systems
* [synacktiv/DepFuzzer](https://github.com/synacktiv/DepFuzzer) - Tool used to find dependency confusion or project where owner's email can be takeover.

## Methodology

Look for `npm`, `pip`, `gem` packages, the methodology is the same : you register a public package with the same name of private one used by the company and then you wait for it to be used.

* **DockerHub**: Dockerfile image
* **JavaScript** (npm): package.json
* **MVN** (maven): pom.xml
* **PHP** (composer): composer.json
* **Python** (pypi): requirements.txt

### NPM Example

* List all the packages (ie: package.json, composer.json, ...)
* Find the package missing from [www.npmjs.com](https://www.npmjs.com/)
* Register and create a **public** package with the same name
    * Package example : [0xsapra/dependency-confusion-expoit](https://github.com/0xsapra/dependency-confusion-expoit)
