# LI License Encryptor

Tibero 라이센스 XML 파일을 AES-GCM 방식으로 암호화하는 CLI 도구입니다.

## Requirements

- Go 1.24.2 이상
- OwlDb 프로젝트 내 YAML 설정 파일 (application-prod.yml)
- 암호화할 XML 라이센스 파일들

## Usage

CLI로 실행 파일을 실행 (예: ./license-encyptor aws ~/licenseFilesDir ~/owlDbProjectDir)

### Parameters

- `cspType`: 클라우드 서비스 제공자 타입 (예: azure, aws)
- `licenseFilesDir`: XML 라이센스 파일들이 있는 디렉토리 경로
- `owlDbProjectDir`: OWL DB 프로젝트 디렉토리 (application-prod.yml 포함)
