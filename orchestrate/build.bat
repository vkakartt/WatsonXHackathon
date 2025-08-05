@echo off

orchestrate tools remove -n initial_screening
orchestrate agents remove -n Cybersecurity_Manager --kind native
orchestrate agents remove -n Initial_Screening_Agent --kind native

orchestrate tools import -k python -f "Initial_Screening_Agent/initial_screening_tools.py" -p "Initial_Screening_Agent"
orchestrate agents import -f Initial_Screening_Agent/uv-config.yaml

orchestrate agents import -f Cybersecurity_Manager/uv-config.yaml