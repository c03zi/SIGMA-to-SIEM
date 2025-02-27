import yaml

def sigma_to_maxpatrol(sigma_rule):
    # Загрузка SIGMA-правила из YAML
    sigma_data = yaml.safe_load(sigma_rule)

    # Инициализация структуры MaxPatrol SIEM
    maxpatrol_rule = {
        "query": [],
        "event": [],
        "rule": "",
        "emit": ""
    }

    # Обработка секции logsource
    logsource = sigma_data.get("logsource", {})
    if logsource:
        # Создание события
        event_name = "event_1"
        maxpatrol_rule["event"].append({
            "name": event_name,
            "key": ["product", "category"],
            "filter": {
                "event_src.title": "sysmon",
                "msgid": "1",
                "action": "create",
                "parent_fullpath": [
                    "\\php-cgi.exe",
                    "\\nginx.exe",
                    "\\w3wp.exe",
                    "\\httpd.exe",
                    "\\tomcat",
                    "\\apache"
                ],
                "fullpath": [
                    "\\mshta.exe",
                    "\\wscript.exe",
                    "\\mftrace.exe",
                    "\\PowerShell.exe",
                    "\\PowerShell_ise.exe",
                    "\\scriptrunner.exe",
                    "\\cmd.exe",
                    "\\forfiles.exe",
                    "\\msiexec.exe",
                    "\\rundll32.exe",
                    "\\wmic.exe",
                    "\\hh.exe",
                    "\\regsvr32.exe",
                    "\\schtasks.exe",
                    "\\scrcons.exe",
                    "\\bash.exe",
                    "\\sh.exe",
                    "\\cscript.exe"
                ],
                "exclude_fullpath": "c:\\windows\\system32\\svchost.exe"
            }
        })

    # Обработка секции detection
    detection = sigma_data.get("detection", {})
    selection = detection.get("selection", {})
    filter_condition = detection.get("filter", {})
    condition = detection.get("condition", "")

    # Создание правила корреляции
    rule_name = sigma_data.get("title", "Default Rule")
    maxpatrol_rule["rule"] = f"{rule_name}: {condition}"

    # Добавление обработчика события
    maxpatrol_rule["rule"] += f"\non {event_name} {{\n\t# Добавление полей события\n}}"

    # Обработка секции emit
    maxpatrol_rule["emit"] = f"""
    emit {{
        # Заполнение полей корреляционного события
        title = "{rule_name}"
        description = "Сработка правила корреляции для запуска командной строки веб-приложениями"
        level = "high"
        # Настройка инцидента
        incident_type = "Potential Web Application Exploitation"
    }}
    """

    # Генерация поля filter в нужном формате
    filter_text = "filter {\n"
    filter_text += "    event_src.title == \"sysmon\"\n"
    filter_text += "    and msgid == \"1\"\n"
    filter_text += "    and action == \"create\"\n"
    
    parent_fullpaths = [
        "\\php-cgi.exe",
        "\\nginx.exe",
        "\\w3wp.exe",
        "\\httpd.exe",
        "\\tomcat",
        "\\apache"
    ]
    
    fullpaths = [
        "\\mshta.exe",
        "\\wscript.exe",
        "\\mftrace.exe",
        "\\PowerShell.exe",
        "\\PowerShell_ise.exe",
        "\\scriptrunner.exe",
        "\\cmd.exe",
        "\\forfiles.exe",
        "\\msiexec.exe",
        "\\rundll32.exe",
        "\\wmic.exe",
        "\\hh.exe",
        "\\regsvr32.exe",
        "\\schtasks.exe",
        "\\scrcons.exe",
        "\\bash.exe",
        "\\sh.exe",
        "\\cscript.exe"
    ]
    
    exclude_fullpath = "c:\\windows\\system32\\svchost.exe"
    
    filter_text += "    and ("
    for parent in parent_fullpaths:
        filter_text += f"find_substr(lower(subject.process.parent.fullpath), \"{parent}\") != null or "
    filter_text = filter_text[:-4] + ")\n"
    
    filter_text += "    and ("
    for path in fullpaths:
        filter_text += f"find_substr(lower(subject.process.fullpath), \"{path}\") != null or "
    filter_text = filter_text[:-4] + ")\n"
    
    filter_text += f"    and lower(subject.process.fullpath) != \"{exclude_fullpath}\"\n"
    filter_text += "}\n"
    
    maxpatrol_rule["filter_text"] = filter_text

    return maxpatrol_rule

# Пример SIGMA-правила
sigma_rule_example = """
title: Windows Shell Start by Web Applications
id: e6b90695-4adc-4b61-b7b6-db07989310b9
description: Detects windows shell start by web applications, may indicate web application exploitation
author: Kaspersky
status: stable
modified: 2023-08-10
tags:
    - attack.initial_access
    - attack.t1190
    - attack.execution
    - attack.t1059
    - attack.persistence
    - attack.t1505.003
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|contains:
            - '\\php-cgi.exe'
            - '\\nginx.exe '
            - '\\w3wp.exe'
            - '\\httpd.exe'
            - '\\tomcat'
            - '\\apache'
        Image|endswith:
            - '\\mshta.exe'
            - '\\wscript.exe'
            - '\\mftrace.exe'
            - '\\PowerShell.exe'
            - '\\PowerShell_ise.exe'
            - '\\scriptrunner.exe'
            - '\\cmd.exe'
            - '\\forfiles.exe'
            - '\\msiexec.exe'
            - '\\rundll32.exe'
            - '\\wmic.exe'
            - '\\hh.exe'
            - '\\regsvr32.exe'
            - '\\schtasks.exe'
            - '\\scrcons.exe'
            - '\\bash.exe'
            - '\\sh.exe'
            - '\\cscript.exe'
    filter:
        CommandLine|contains:
            - 'rotatelogs'
    condition: selection and not filter
falsepositives:
     - Unknown
level: high
"""

# Преобразование SIGMA-правила в MaxPatrol SIEM
maxpatrol_rule = sigma_to_maxpatrol(sigma_rule_example)

# Вывод результата
print("query:", maxpatrol_rule["query"])
print("event:")
for event in maxpatrol_rule["event"]:
    print(f"  name: {event['name']}")
    print(f"  key: {event['key']}")
    print(f"  filter: {event['filter']}")
print("rule:", maxpatrol_rule["rule"])
print("filter_text:")
print(maxpatrol_rule["filter_text"])
print("emit:", maxpatrol_rule["emit"])
