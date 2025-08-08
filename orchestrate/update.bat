@echo off

orchestrate tools import -k python -f "Zap_Agent/zap_tools.py" -p "Zap_Agent"
orchestrate tools import -k python -f "SQL_Injection_Agent/sql_injection_tools.py" -p "SQL_Injection_Agent"
orchestrate tools import -k python -f "Initial_Screening_Agent/initial_screening_tools.py" -p "Initial_Screening_Agent"
orchestrate agents import -f Initial_Screening_Agent/uv-config.yaml
orchestrate agents import -f SQL_Injection_Agent/uv-config.yaml
orchestrate agents import -f Zap_Agent/uv-config.yaml

orchestrate agents import -f Cybersecurity_Manager/uv-config.yaml