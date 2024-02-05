Follow the step:
1. Install OWASP ZAP
2. Clone this project
3. In /DYVAM-code
	RUN: python -m vene env
	RUN: .\env\Scripts\activate
	RUN: pip install -r requirements.txt
4. To operate DYVAM
	RUN: python DYVAM.py
5. To deploy wep application
	RUN: cd web-app
	RUN: python app.py

Code Components:
1. DyVAM-code/data/num_record/
Contain vulnerability assessment JSON report from OWASP ZAP

2. DyVAM-code/data/
	alertRef_CVSS.csv
	alertRef_OwaspTop10.csv
	OwaspTop10_OrgCVSS.csv
alertRef_CVSS.csv: alertRef with CVSS of each vulnerability
alertRef_OwaspTop10.csv: alertRef with OWASP Top 10 group of each vulnerability
OwaspTop10_OrgCVSS.csv: Organizational CVSS Score of each OWASP Top 10 group

3. DyVAM-code/evaluation/DyVAM_performance/
	Algorithm_1-2_performance
	Dag_generation_performance
Performance of algorithm 1+2 and DAG generation with multithread processing

4. DyVAM-code/evaluation/WithoutMulti/
	Algorithm_1-2_performance
	Dag_generation_performance
Performance of algorithm 1+2 and DAG generation without multithread processing

5. DyVAM-code/evaluation/Evaluation.xlsx
Performance comparision table and graph

6. DyVAM-code/example_result
Example result of single website report before save to mongoDB of both multithread and single-thread

7. DyVAM-code/web-app
Deploy web application interface

8. DyVAM-code/DyVAM.py
DyVAM code

9. DyVAM-code/DyVAM_withoutMultiThread.py
DyVAM withput multithread processing code

10. DyVAM-code/README.txt
README
11. DyVAM-code/requirements.txt
Python library requirement
