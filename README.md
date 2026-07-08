# 개인 포트폴리오 사이트

김태현의 개인 포트폴리오 웹사이트입니다. 별도의 프레임워크나 라이브러리 없이 순수 HTML, CSS, JavaScript만으로 제작했습니다.

## 페이지 구성

| 섹션 | 내용 |
|---|---|
| Hero | 이름과 직무(WEB HACKING) 소개, 아래로 스크롤 유도 |
| About | 기술 슬라이드, 프로필(캐릭터 아이콘 호버 시 정보 표시), 자기소개 |
| Skills | 보유 기술 태그 및 상세 설명 카드 |
| Career & Activity | 경력·대외활동을 하나의 타임라인으로 정리 |
| Projects | 진행한 프로젝트 카드, 기술스택별 필터, 더보기 토글 |

## 주요 기능 (JavaScript)

- 스크롤 시 요소가 서서히 나타나는 애니메이션 (IntersectionObserver 사용, 외부 라이브러리 없이 직접 구현)
- 캐릭터 아이콘에 마우스를 올리면 프로필 정보가 나타나는 호버 효과
- 우측 하단 "맨 위로" 버튼으로 스크롤 최상단 이동
- Projects 섹션 기술스택 필터 버튼
- Projects 카드별 "더보기" 내용 펼치기/접기

## 기술 스택

- **HTML**: 화면 구조
- **CSS**: 디자인 및 애니메이션 (`css/style.css`)
- **JavaScript**: 위 기능들을 담당 (`js/script.js`)

## 실행 방법

별도의 서버나 설치 과정이 필요 없는 정적 사이트입니다. `index.html`을 더블클릭하거나 브라우저로 열면 바로 확인할 수 있습니다.

```bash
git clone <이 저장소 URL>
cd portfolio
open index.html   # Windows는 그냥 더블클릭
```

## 폴더 구조

```
portfolio/
├── index.html
├── css/
│   └── style.css
├── js/
│   └── script.js
└── images/
    ├── memoji.svg
    ├── main.png
    └── images.jpeg
```

## 참고 사항

- `index.html`은 `css/style.css`, `js/script.js`, `images/` 폴더를 상대경로로 참조합니다. 파일을 옮기거나 배포할 때는 이 폴더 구조를 그대로 유지해야 합니다.
- 구글 폰트(Montserrat)를 외부 CDN에서 불러오므로, 폰트가 정상적으로 표시되려면 인터넷 연결이 필요합니다.
