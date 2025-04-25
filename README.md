# Tiny Second-hand Shopping Platform
> **Flask + SocketIO 기반 중고고래 플랫폼**  

---

## 과제 요구 기능
* 사람들이 플랫폼에 가입할 수 있어야 함.
* 상품들을 올리고 볼 수 있어야 함.
* 플랫폼 사용자들끼리 소통이 가능해야함.
* 악성 유저나 상품을 차단 해야 함.
* 유저들 간의 송금이 가능해야함
* 상품의 검색할 수 있어야 함.
* 관리자가 플랫폼의 모든 요소를 관리할 수 있어야 함. 
* 최대한 보안 약점이 없도록 할 것.

---

## 환경 설정

### 1) Conda 환경 생성
```bash
# 저장소 클론
git clone https://github.com/marimo00/WHS-Secure-Coding.git
cd WHS-Secure-Coding

# Conda 환경 생성 & 활성화
conda env create -f environments.yaml     #필요한 패키지 설치
conda activate
```

# 실행 방법
```bash
python3 app.py
```
