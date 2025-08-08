@echo off

orchestrate tools remove -n initial_screening
orchestrate tools remove -n zap_passive_scan
orchestrate tools remote -n zap_active_scan
orchestrate agents remove -n Cybersecurity_Manager --kind native
orchestrate agents remove -n Initial_Screening_Agent --kind native

orchestrate tools import -k python -f "Zap_Agent/zap_tools.py" -p "Zap_Agent"
orchestrate tools import -k python -f "Initial_Screening_Agent/initial_screening_tools.py" -p "Initial_Screening_Agent"
orchestrate agents import -f Initial_Screening_Agent/uv-config.yaml
orchestrate agents import -f Zap_Agent/uv-config.yaml

orchestrate agents import -f Cybersecurity_Manager/uv-config.yaml