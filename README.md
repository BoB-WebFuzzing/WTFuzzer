# Description
Code coverage 측정용 branch.

# Usage
docker compose 를 통해서 Container 빌드.

PHP를 실행하면 Code coverage 측정값이 Endpoints로 구분되어 자동으로 `/tmp/coverages` 폴더에 json 파일로 저장됨.

`/tmp/coverage/calculate_coverage.py` 를 실행하면 Code coverage 결과값을 확인할 수 있음.
ex) `python3 /tmp/coverage/calculate_coverage.py`
