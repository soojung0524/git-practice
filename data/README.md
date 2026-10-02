# data/

이 디렉터리는 실행 시점에 사용할 로그 데이터셋(russellmitchell)을 놓는 위치입니다.
데이터셋 자체는 용량이 크고 개인 환경마다 위치가 다를 수 있어 저장소에 커밋하지 않습니다
(`.gitignore` 참고).

사용 방법 중 하나를 선택하세요.

1. 이 디렉터리 바로 아래에 데이터셋 내용을 복사하거나 심볼릭 링크로 연결합니다.
   (`data/dataset.yaml`, `data/gather/`, `data/labels/` 형태가 되어야 합니다.)
2. 또는 `--dataset-root` 인자나 `LOG_AGENT_DATASET_ROOT` 환경변수로 실제 데이터셋 경로를
   직접 지정합니다.

```
python main.py --dataset-root "../Data/russellmitchell"
```
